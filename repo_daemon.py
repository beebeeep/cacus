#!/usr/bin/env python
# -*- coding: utf-8 -*-


from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous, MissingArgumentError, Finish
from tornado import gen, httputil, httpserver, escape
from concurrent.futures import ThreadPoolExecutor
import logging
import motor
from binascii import hexlify
import email.utils
import time
import json
import re
import os

import common
import repo_manage
import plugin_loader

access_log = logging.getLogger('tornado.access')
app_log = logging.getLogger('tornado.application')
gen_log = logging.getLogger('tornado.general')


class CachedRequestHandler(RequestHandler):

    def prepare(self):
        pass

    @gen.coroutine
    def _cache_expired(self, item, selector):
        db = self.settings['db']
        latest_dt = None
        result = db.cacus[item].find(selector, {'lastupdated': 1})
        while (yield result.fetch_next):
            dt = result.next_object()['lastupdated']
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

class JsonRequestHandler(RequestHandler):
    
    def _get_json_request(self):
        if 'application/json' not in self.request.headers.get('Content-type', '').lower():
            self.set_status(400)
            self.write({'success': False, 'msg': 'application/json Content-type expected'})
            raise Finish()
        try:
            app_log.debug("body '%s'",  self.request.body)
            req = json.loads(escape.to_unicode(self.request.body))
        except Exception as e:
            self.set_status(400)
            self.write({'success': False, 'msg': 'invalid JSON: {}'.format(e)})
            raise Finish()

        class JsonRequestData(dict):
            def __getitem__(self, key):
                try: 
                    return dict.__getitem__(self, key)
                except KeyError:
                    app_log.error("Missing required argument %s", key)
                    raise MissingArgumentError(key)

        return JsonRequestData(req)


class StorageHandler(RequestHandler):

    def on_connection_close(self):
        self.dead = True

    @gen.coroutine
    def stream_from_storage(self, key=None, headers=[]):
        self.dead = False
        stream = common.ProxyStream(self, headers=headers)
        self.set_header('Content-Type', 'application/octet-stream')
        # TODO last-modified, content-length and other metadata _should_ be provided! 
        try: 
            yield self.settings['workers'].submit(plugin_loader.get_plugin('storage').get, key, stream)
        except common.NotFound:
            self.set_status(404)
            app_log.error("Key %s was not found at storage", key)
        except common.FatalError as e:
            #self.set_status(500)
            app_log.error("Got error from storage plugin: %s", e)
        self.finish()

    @gen.coroutine
    def get(self, key):
        yield self.stream_from_storage(key)


class PackagesHandler(CachedRequestHandler, StorageHandler):

    @gen.coroutine
    def get(self, distro=None, comp=None, arch=None):

        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('repos', {'distro': distro, 'component': comp, 'architecture': arch})
        if not expired:
            self.set_status(304)
            return
        if not dt:
            self.set_status(404)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.repos.find_one({'distro': distro, 'component': comp, 'architecture': arch})
        if doc:
            s = common.config['repo_daemon']
            if s['proxy_storage']:
                headers = [ ('Content-Length', doc['size']), ('Last-Modified', httputil.format_timestamp(dt)) ]
                yield self.stream_from_storage(doc['packages_file'], headers=headers)
            else:
                # we use x-accel-redirect instead of direct proxying via storage plugin to allow 
                # user to offload cacus' StorageHandler if current storage allows it
                url = os.path.join(s['repo_base'], s['storage_subdir'], doc['packages_file'])
                app_log.info("Redirecting %s/%s/%s/Packages to %s", distro, comp, arch, url)
                self.add_header("X-Accel-Redirect", url)
                self.set_status(200)
        else:
            self.set_status(404)


class SourcesHandler(CachedRequestHandler, StorageHandler):
    """ Returns Sources repo indice
    Generating on the fly as it's rarely used so no point to slow down 
    metadata update by pre-generating and storing this file
    """

    @gen.coroutine
    def get(self, distro=None, comp=None):

        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('components', {'distro': distro, 'component': comp})
        if not expired:
            self.set_status(304)
            return
        if not dt:
            self.set_status(404)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.components.find_one({'distro': distro, 'component': comp})
        if doc:
            s = common.config['repo_daemon']
            if s['proxy_storage']:
                headers = [ ('Content-Length', doc['size']), ('Last-Modified', httputil.format_timestamp(dt)) ]
                yield self.stream_from_storage(doc['sources_file'], headers=headers)
            else:
                # we use x-accel-redirect instead of direct proxying via storage plugin to allow 
                # user to offload cacus' StorageHandler if current storage allows it
                url = os.path.join(s['repo_base'], s['storage_subdir'], doc['sources_file'])
                app_log.info("Redirecting %s/%s/source/Sources to %s", distro, comp, arch, url)
                self.add_header("X-Accel-Redirect", url)
                self.set_status(200)
        else:
            self.set_status(404)


class SourcesFilesHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, distro=None, comp=None, file=None):
        db = self.settings['db']
        doc = yield db.repos[distro].find_one({'component': comp, 'sources.name': file},
                                            {'sources.storage_key': 1, 'sources.name': 1})
        for f in doc['sources']:
            if f['name'] == file:
                s = common.config['repo_daemon']
                url = os.path.join(s['repo_base'], f['storage_key'])
                app_log.info("Redirecting %s to %s", file, url)
                self.add_header("X-Accel-Redirect", url)
                break
        self.set_status(200)


class ReleaseHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, distro=None, gpg=None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('distros', {'distro': distro})
        if not expired:
            self.set_status(304)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.distros.find_one({'distro': distro})
        if gpg:
            self.write(doc['release_gpg'])
        else:
            self.write(doc['release_file'])


class ApiReindexDistroHandler(JsonRequestHandler):

    @gen.coroutine
    def post(self, distro):
        try:
            yield self.settings['workers'].submit(repo_manage.update_distro_metadata, distro=distro, force=True)
        except common.NotFound as e:
            self.set_status(404)
            self.write({'success': False, 'msg': e.message})
            return
        self.write({'success': True, 'msg': 'Reindex complete'})


class ApiCreateDistroHandler(JsonRequestHandler):

    @gen.coroutine
    def post(self, distro):
        req = self._get_json_request()
        gpg_check = req['gpg_check']
        strict = req['strict']
        description = req['description']
        incoming_wait_timeout = req['incoming_timeout']
        r = yield self.settings['db'].cacus.distros.find_one_and_update(
                {'distro': distro},
                {'$set': {'gpg_check': gpg_check, 'strict': strict, 'description': description, 'incoming_wait_timeout': incoming_wait_timeout}},
                upsert=True)
        if not r:
            self.set_status(201)
            self.write({'success': True, 'msg': 'repo created'})
        else:
            self.set_status(200)
            self.write({'success': True, 'msg': 'repo settings updated'})


class ApiDmoveHandler(JsonRequestHandler):

    @gen.coroutine
    def post(self, distro=None):
        req = self._get_json_request()
        pkg = req['pkg']
        ver = req['ver']
        src = req['from']
        dst = req['to']

        try:
            r = yield self.settings['workers'].submit(repo_manage.dmove_package,
                                                      distro=distro, pkg=pkg, ver=ver, src=src, dst=dst)
            self.write({'success': True, 'msg': r})
        except common.NotFound:
            self.set_status(404)
            self.write({'success': False, 'msg': r.msg})
        except common.TemporaryError:
            # TODO retries
            # timeout on dmove can only if we cannot lock the distro,
            # i.e. there is some other operation processing current distro
            self.set_status(409)
            self.write({'success': False, 'msg': r.msg})


class ApiDistPushHandler(RequestHandler):

    @gen.coroutine
    def post(self, distro=None):
        changes_file = self.get_argument('file')

        if distro in common.config['duploader_daemon']['distributions']:
            self.write({'success': True, 'msg': 'Submitted package import job'})
        else:
            self.set_status(404)
            self.write({'success': False, 'msg': "Repo {} is not configured".format(distro)})

        r = yield self.settings['workers'].submit(repo_manage.dist_push, distro=distro, changes=changes_file)
        if r.ok:
            self.write({'success': True, 'msg': r.msg})
        elif r.status == 'NOT_FOUND':
            self.set_status(404)
            self.write({'success': False, 'msg': r.msg})
        else:
            self.set_status(500)
            self.write({'success': False, 'msg': r.msg})


class ApiSearchHandler(RequestHandler):

    @gen.coroutine
    def get(self, distro=None):
        db = self.settings['db']
        pkg = self.get_argument('pkg', '')
        ver = self.get_argument('ver', '')
        comp = self.get_argument('comp', '')
        descr = self.get_argument('descr', '')
        lang = self.get_argument('lang', '')

        selector = {}
        if pkg:
            selector['Source'] = {'$regex': pkg}
        if ver:
            selector['Version'] = {'$regex': ver}
        if comp:
            selector['component'] = comp
        if descr:
            if lang:
                selector['$text'] = {'$search': descr, '$language': lang}
            else:
                selector['$text'] = {'$search': descr}
        projection = {
            '_id': 0,
            'Source': 1,
            'component': 1,
            'Version': 1,
            'debs.maintainer': 1,
            'debs.Architecture': 1,
            'debs.Package': 1,
            'debs.Description': 1
        }

        result = {}
        pkgs = []
        cursor = db.repos[distro].find(selector, projection)
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
    s = common.config['repo_daemon']

    # using full debian repository layout (see https://wiki.debian.org/RepositoryFormat)
    release_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9]+)/Release(?P<gpg>\.gpg)?$"
    packages_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9]+)/(?P<comp>\w+)/binary-(?P<arch>\w+)/Packages$"
    sources_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9]+)/(?P<comp>\w+)/source/Sources$"
    sources_files_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9]+)/(?P<comp>\w+)/source/(?P<file>.*)$"

    api_dmove_re = s['repo_base'] + r"/api/v1/dmove/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_search_re = s['repo_base'] + r"/api/v1/search/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_dist_push_re = s['repo_base'] + r"/api/v1/dist-push/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_create_distro_re = s['repo_base'] + r"/api/v1/create-distro/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_reindex_distro_re = s['repo_base'] + r"/api/v1/reindex-distro/(?P<distro>[-_.A-Za-z0-9]+)$"

    storage_re = os.path.join(s['repo_base'], s['storage_subdir'])  + r"/(?P<key>.*)$"


    return Application([
        url(packages_re, PackagesHandler),
        url(release_re, ReleaseHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler),
        url(api_dmove_re, ApiDmoveHandler),
        url(api_search_re, ApiSearchHandler),
        url(api_dist_push_re, ApiDistPushHandler),
        url(api_create_distro_re, ApiCreateDistroHandler),
        url(api_reindex_distro_re, ApiReindexDistroHandler),
        url(storage_re, StorageHandler),
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
