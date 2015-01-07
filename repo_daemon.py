#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous
from tornado import gen
import tornado.options
import logging
import motor
from binascii import hexlify

import common

db = motor.MotorClient(host = common.config['metadb']['host'], port = common.config['metadb']['port'])
log = logging.getLogger('tornado')
log.setLevel(logging.DEBUG)

class PackagesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None, arch = None):
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

class SourcesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None):
        cursor = db.repos[repo].find({'environment': env}, {'dsc': 1, 'sources': 1})
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

class SourcesFilesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None, file = None):
        doc = yield  db.repos[repo].find_one({'environment': env, 'sources.name': file},
                {'sources.storage_key': 1, 'sources.name': 1})
        for f in doc['sources']:
            if f['name'] == file:
                url = "{0}{1}".format('/proxy-mds', f['storage_key'])
                logging.info("Redirecting %s to %s", file, url)
                self.add_header("X-Accel-Redirect", url)
                break
        self.set_status(200)

class ReleaseHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None, arch = None, gpg = None):
        doc = yield db.cacus[repo].find_one({'environment': env, 'architecture': arch})
        if gpg:
            self.write(doc['release_gpg'])
        else:
            self.write(doc['release_file'])

def make_app():
    packages_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Packages$".format(
            common.config['repo_daemon']['repo_base'])
    release_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Release(?P<gpg>\.gpg)?$".format(
            common.config['repo_daemon']['repo_base'])
    sources_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/Sources$".format(
            common.config['repo_daemon']['repo_base'])
    sources_files_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/source/(?P<file>.*)$".format(
            common.config['repo_daemon']['repo_base'])

    return Application([
        url(packages_re, PackagesHandler),
        url(release_re, ReleaseHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler)
        ])

def start_daemon():

    #sys.argv = sys.argv[0:1]
    #tornado.options.parse_command_line()
    app = make_app()
    app.listen(common.config['repo_daemon']['port'])
    IOLoop.current().start()

