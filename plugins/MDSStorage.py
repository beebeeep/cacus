#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import urllib2
import mmap
import logging
import xml.etree.ElementTree as ET
import time

from yapsy.IPlugin import IPlugin
import plugins

log = logging.getLogger('cacus.mds_storage')

class MDSStorage(plugins.IStoragePlugin):
    def configure(self, config):
        self.base_url = config['base_url']
        self.auth_header = config['auth_header']

    def put(self, key, filename):
        with open(filename, 'rb') as f:
            file =  mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
            url = "{0}{1}".format(self.base_url, key)

            request = urllib2.Request(url, file)
            request.add_header(self.auth_header[0], self.auth_header[1])

            for n_try in xrange(3):
                try:
                    response_fp = urllib2.urlopen(request)
                    response = ET.fromstring(response_fp.read())
                    file.close()
                    break
                except urllib2.URLError as e:
                    log.error("Error requesting %s: %s", url, e)
                except urllib2.HTTPError as e:
                    log.error("Error requesting %s: %s", url, e)
                time.sleep(1)
            else:
                log.critical("Cannot upload %s", filename)
                return None

            try:
                storage_key = response.attrib['key']
            except KeyError:
                log.error("Wrong return from server")
                return None
            log.debug("Got storage key '%s'", storage_key)

        return storage_key

    def get(self, key):
        return os.path.join(self.root, key)
