#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous
from tornado import gen
import logging
import motor
from binascii import hexlify

import common

db = motor.MotorClient(host = common.config['metadb']['host'], port = common.config['metadb']['port'])
access_log = logging.getLogger('tornado.access')

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
                        self.write("MD5sum: {0}\n".format(hexlify(v)))
                    elif k == 'sha1':
                        self.write("SHA1: {0}\n".format(hexlify(v)))
                    elif k == 'sha256':
                        self.write("SHA256: {0}\n".format(hexlify(v)))
                    elif k == 'sha512':
                        self.write("SHA512: {0}\n".format(hexlify(v)))
                    elif k == 'storage_key':
                        self.write("Filename: {0}\n".format(v))
                    else:
                        self.write("{0}: {1}\n".format(k.capitalize(), v))
                self.write("\n")

class SourcesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None):
        cursor = db.repos[repo].find({'environment': env}, {'dsc': 1, 'sources': 1})
        while (yield cursor.fetch_next):
            pkg = cursor.next_object()
            for k,v in pkg['dsc'].iteritems():
                if k == 'Source':
                    self.write("Package: {0}\n".format(v))
                else:
                    self.write("{0}: {1}\n".format(k.capitalize(), v))
            self.write("Directory: {0}/source\n".format(env))
            files = filter(lambda x: x['name'].endswith('.tar.gz') or x['name'].endswith('.dsc'), pkg['sources'])

            def gen_para(algo, files):
                for f in files:
                    self.write(" {0} {1} {2}\n".format(hexlify(f[algo]), f['size'], f['name']))

            self.write("Files: \n")
            gen_para('md5', files)
            self.write("Checksums-Sha1: \n")
            gen_para('sha1', files)
            self.write("Checksums-Sha256: \n")
            gen_para('sha256', files)

            self.write("\n")



### TODO: check if apt-get can handle redirects and send 301 
### or just use X-Accel-Redirect to tell nginx URL to stream file from storage
class SourcesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None, file = None):
        self.send_error(501, "Not implemented yet")

def make_app():
    packages_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/(?P<arch>\w+)/Packages$".format(
            common.config['repo_daemon']['repo_base'])
    sources_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/Sources$".format(
            common.config['repo_daemon']['repo_base'])
    sources_files_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/source/(?P<file>.*)$".format(
            common.config['repo_daemon']['repo_base'])

    return Application([
        url(packages_re, PackagesHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler)
        ])

def start_daemon():
    app = make_app()
    app.listen(common.config['repo_daemon']['port'])
    IOLoop.current().start()

