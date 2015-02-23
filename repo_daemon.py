#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous
from tornado import gen, httputil, httpserver
import tornado.options
import logging
import motor
from binascii import hexlify
import email.utils
import time
import pprint

import common

log = logging.getLogger('tornado')
log.setLevel(logging.DEBUG)

class MyRequestHandler(RequestHandler):
    def prepare(self):
        pass
    @gen.coroutine
    def _cache_expired(self, repo, env, arch = '__all__'):
        db = self.settings['db']
        revalidate = True
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

class PackagesHandler(MyRequestHandler):
    @gen.coroutine
    def get(self, repo = None, env = None, arch = None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired(repo, env, arch)
        if not expired:
            self.set_status(304)
            return
        self.add_header("Last-Modified", httputil.format_timestamp(dt))

        cursor = db.repos[repo].find({'environment': env, 'debs.Architecture': arch}, {'environment': 0, '_id': 0})
        while (yield cursor.fetch_next):
            pkg = cursor.next_object()
            for deb in pkg['debs']:
                for k,v in deb.iteritems():
                    if k == 'md5':
                        self.write(u"MD5sum: {0}\n".format(hexlify(v)))
                    elif k == 'sha1':
                        self.write(u"SHA1: {0}\n".format(hexlify(v)))
                    elif k == 'sha256':
                        self.write(u"SHA256: {0}\n".format(hexlify(v)))
                    elif k == 'sha512':
                        self.write(u"SHA512: {0}\n".format(hexlify(v)))
                    elif k == 'storage_key':
                        self.write(u"Filename: {0}\n".format(v))
                    else:
                        self.write(u"{0}: {1}\n".format(k.capitalize(), v))
                self.write(u"\n")

class SourcesHandler(MyRequestHandler):
    @gen.coroutine
    def get(self, repo = None, env = None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired(repo, env, '__all__')
        if not expired:
            self.set_status(304)
            return
        self.add_header("Last-Modified", httputil.format_timestamp(dt))

        cursor = db.repos[repo].find({'environment': env, 'dsc': {'$exists': True} }, {'dsc': 1, 'sources': 1})
        while (yield cursor.fetch_next):
            pkg = cursor.next_object()
            for k,v in pkg['dsc'].iteritems():
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


class SourcesFilesHandler(MyRequestHandler):
    @gen.coroutine
    def get(self, repo = None, env = None, file = None):
        db = self.settings['db']
        doc = yield  db.repos[repo].find_one({'environment': env, 'sources.name': file},
                {'sources.storage_key': 1, 'sources.name': 1})
        for f in doc['sources']:
            if f['name'] == file:
                url = "{0}{1}".format('/proxy-mds', f['storage_key'])
                logging.info("Redirecting %s to %s", file, url)
                self.add_header("X-Accel-Redirect", url)
                break
        self.set_status(200)

class ReleaseHandler(MyRequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None, arch = None, gpg = None):
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

def make_app():
    base = common.config['repo_daemon']['repo_base']
    packages_re = base + r"/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Packages$"
    release_re = base + r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Release(?P<gpg>\.gpg)?$"
    sources_re = base + r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/Sources$"
    sources_files_re = base + r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/source/(?P<file>.*)$"

    return Application([
        url(packages_re, PackagesHandler),
        url(release_re, ReleaseHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler)
        ])

def start_daemon():
    app = make_app()
    server = httpserver.HTTPServer(app)
    server.bind(common.config['repo_daemon']['port'])
    server.start(0)
    db = motor.MotorClient(host = common.config['metadb']['host'], port = common.config['metadb']['port'])
    app.settings['db'] = db
    IOLoop.instance().start()
