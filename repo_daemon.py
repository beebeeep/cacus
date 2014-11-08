#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, asynchronous
from tornado import gen
import motor
from binascii import hexlify

import common

db = motor.MotorClient(host = common.config['metadb']['host'], port = common.config['metadb']['port'])

class PackagesHandler(RequestHandler):
    @asynchronous
    @gen.coroutine
    def get(self, repo = None, env = None):
        cursor = db.repos[repo].find({'environment': env}, {'environment': 0, '_id': 0})
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

def make_app():
    packages_re = r"{0}/(?P<repo>[-_.A-Za-z0-9]+)/(?P<env>\w+)/Packages$".format(
            common.config['repo_daemon']['repo_base'])
    return Application([
        url(packages_re, PackagesHandler),
        ])

def start_daemon():
    app = make_app()
    app.listen(common.config['repo_daemon']['port'])
    IOLoop.current().start()

