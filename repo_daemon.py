#!/usr/bin/env python
# -*- coding: utf-8 -*-


from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous
from tornado import gen, httputil, httpserver
from concurrent.futures import ThreadPoolExecutor
import logging
import motor
from binascii import hexlify
import email.utils
import time

import common
import repo_manage

access_log = common.setup_logger('tornado.access')
app_log = common.setup_logger('tornado.application')
gen_log = common.setup_logger('tornado.general')


class CachedRequestHandler(RequestHandler):

    def prepare(self):
        pass

    @gen.coroutine
    def _cache_expired(self, repo, env, arch='__all__'):
        db = self.settings['db']
        latest_dt = None
        selector = {'environment': env}
        if (arch != '__all__'):
            selector['architecture'] = arch
        repos = db.cacus[repo].find(selector, {'lastupdated': 1})
        while (yield repos.fetch_next):
            dt = repos.next_object()['lastupdated']
            if not latest_dt or dt > latest_dt:
                latest_dt = dt

        if_modified = self.request.headers.get('If-Modified-Since')
        if not if_modified:
            raise gen.Return((True, latest_dt))

        cached_dt = email.utils.parsedate(if_modified)
        cached_ts = time.mktime(cached_dt)
        latest_ts = time.mktime(latest_dt.timetuple())
        if latest_ts <= cached_ts:
            raise gen.Return((False, latest_dt))
        else:
            raise gen.Return((True, latest_dt))


class PackagesHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, repo=None, env=None, arch=None):

        db = self.settings['db']
        (expired, dt) = yield self._cache_expired(repo, env, arch)
        if not expired:
            self.set_status(304)
            return
        self.add_header("Last-Modified", httputil.format_timestamp(dt))

        doc = yield db.cacus[repo].find_one({'environment': env, 'architecture': arch})
        if doc:
            url = "{0}{1}".format('/storage/', doc['packages_file'])
            logging.info("Redirecting %s/%s/%s/Packages to %s", repo, env, arch, url)
            self.add_header("X-Accel-Redirect", url)
            self.set_status(200)
        else:
            self.set_status(404)


class SourcesHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, repo=None, env=None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired(repo, env, '__all__')
        if not expired:
            self.set_status(304)
            return
        self.add_header("Last-Modified", httputil.format_timestamp(dt))

        cursor = db.repos[repo].find({'environment': env, 'dsc': {'$exists': True}}, {'dsc': 1, 'sources': 1})
        while (yield cursor.fetch_next):
            pkg = cursor.next_object()
            for k, v in pkg['dsc'].iteritems():
                if k == 'Source':
                    self.write(u"Package: {0}\n".format(v))
                else:
                    self.write(u"{0}: {1}\n".format(k.capitalize(), v))
            self.write(u"Directory: {0}/source\n".format(env))
            files = filter(lambda x: x['name'].endswith('.tar.gz') or x['name'].endswith('.dsc'), pkg['sources'])

            def gen_para(algo, files):
                for f in files:
                    self.write(u" {0} {1} {2}\n".format(hexlify(f[algo]), f['size'], f['name']))

            self.write(u"Files: \n")
            gen_para('md5', files)
            self.write(u"Checksums-Sha1: \n")
            gen_para('sha1', files)
            self.write(u"Checksums-Sha256: \n")
            gen_para('sha256', files)

            self.write(u"\n")


class SourcesFilesHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, repo=None, env=None, file=None):
        db = self.settings['db']
        doc = yield db.repos[repo].find_one({'environment': env, 'sources.name': file},
                                            {'sources.storage_key': 1, 'sources.name': 1})
        for f in doc['sources']:
            if f['name'] == file:
                url = "{0}{1}".format('/storage/', f['storage_key'])
                logging.info("Redirecting %s to %s", file, url)
                self.add_header("X-Accel-Redirect", url)
                break
        self.set_status(200)


class ReleaseHandler(CachedRequestHandler):

    @asynchronous
    @gen.coroutine
    def get(self, repo=None, env=None, arch=None, gpg=None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired(repo, env, arch)
        if not expired:
            self.set_status(304)
            return
        self.add_header("Last-Modified", httputil.format_timestamp(dt))

        doc = yield db.cacus[repo].find_one({'environment': env, 'architecture': arch})
        if gpg:
            self.write(doc['release_gpg'])
        else:
            self.write(doc['release_file'])


class ApiDmoveHandler(RequestHandler):

    @asynchronous
    @gen.coroutine
    def post(self, repo=None):
        pkg = self.get_argument('pkg')
        ver = self.get_argument('ver')
        src = self.get_argument('from')
        dst = self.get_argument('to')
        r = yield self.settings['workers'].submit(repo_manage.dmove_package,
                                                  repo=repo, pkg=pkg, ver=ver, src=src, dst=dst)
        if r['result'] == common.status.OK:
            self.write({'success': True, 'msg': r['msg']})
        elif r['result'] == common.status.NO_CHANGES:
            self.write({'success': True, 'msg': r['msg']})
        elif r['result'] == common.status.NOT_FOUND:
            self.set_status(404)
            self.write({'success': False, 'msg': r['msg']})
        elif r['result'] == common.status.TIMEOUT:
            # timeout on dmove can only if we cannot lock the repo,
            # i.e. there is some other operation processing current repo
            self.set_status(409)
            self.write({'success': False, 'msg': r['msg']})


class ApiDistPushHandler(RequestHandler):

    @asynchronous
    @gen.coroutine
    def post(self, repo=None):
        changes_file = self.get_argument('file')

        if repo in common.config['duploader_daemon']['repos']:
            self.write({'success': True, 'msg': 'Submitted package import job'})
        else:
            self.set_status(404)
            self.write({'success': False, 'msg': "Repo {} is not configured".format(repo)})

        r = yield self.settings['workers'].submit(repo_manage.dist_push, repo=repo, changes=changes_file)
        if r['result'] == common.status.OK:
            self.write({'success': True, 'msg': r['msg']})
        elif r['result'] == common.status.NOT_FOUND:
            self.set_status(404)
            self.write({'success': False, 'msg': r['msg']})
        else:
            self.set_status(500)
            self.write({'success': False, 'msg': r['msg']})


class ApiSearchHandler(RequestHandler):

    @asynchronous
    @gen.coroutine
    def get(self, repo=None):
        db = self.settings['db']
        pkg = self.get_argument('pkg', '')
        ver = self.get_argument('ver', '')
        env = self.get_argument('env', '')
        descr = self.get_argument('descr', '')
        lang = self.get_argument('lang', '')

        selector = {}
        if pkg:
            selector['Source'] = {'$regex': pkg}
        if ver:
            selector['Version'] = {'$regex': ver}
        if env:
            selector['environment'] = env
        if descr:
            if lang:
                selector['$text'] = {'$search': descr, '$language': lang}
            else:
                selector['$text'] = {'$search': descr}
        projection = {
            '_id': 0,
            'Source': 1,
            'environment': 1,
            'Version': 1,
            'debs.maintainer': 1,
            'debs.Architecture': 1,
            'debs.Package': 1,
            'debs.Description': 1
        }

        result = {}
        pkgs = []
        app_log.debug("Searching for packages in %s with selector %s", repo, selector)
        cursor = db.repos[repo].find(selector, projection)
        while (yield cursor.fetch_next):
            pkg = cursor.next_object()
            if pkg:
                p = dict((k.lower(), v) for k, v in pkg.iteritems())
                p['debs'] = [dict((k.lower(), v) for k, v in deb.iteritems()) for deb in pkg['debs']]
                pkgs.append(p)
        if not pkgs:
            self.set_status(404)
            result = {'success': False, 'result': []}
        else:
            result = {'success': True, 'result': pkgs}
        self.write(result)


def make_app():
    base = common.config['repo_daemon']['repo_base']

    packages_re = base + r"/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Packages$"
    release_re = base + r"/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Release(?P<gpg>\.gpg)?$"
    sources_re = base + r"/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/Sources$"
    sources_files_re = base + r"/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/source/(?P<file>.*)$"

    api_dmove_re = base + r"/api/v1/dmove/(?P<repo>[-_.A-Za-z0-9]+)$"
    api_search_re = base + r"/api/v1/search/(?P<repo>[-_.A-Za-z0-9]+)$"
    api_dist_push_re = base + r"/api/v1/dist-push/(?P<repo>[-_.A-Za-z0-9]+)$"

    return Application([
        url(packages_re, PackagesHandler),
        url(release_re, ReleaseHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler),
        url(api_dmove_re, ApiDmoveHandler),
        url(api_search_re, ApiSearchHandler),
        url(api_dist_push_re, ApiDistPushHandler)
        ])


def start_daemon():
    app = make_app()
    server = httpserver.HTTPServer(app)
    server.bind(common.config['repo_daemon']['port'])
    server.start(0)
    db = motor.MotorClient(host=common.config['metadb']['host'], port=common.config['metadb']['port'])
    thread_pool = ThreadPoolExecutor(100)
    app.settings['db'] = db
    app.settings['workers'] = thread_pool
    IOLoop.instance().start()
