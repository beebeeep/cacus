#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import requests
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
        self.timeout = config['connect_timeout']

    def put(self, key, filename):
        with open(filename, 'rb') as f:
            url = "{0}{1}".format(self.base_url, key)

            for n_try in xrange(3):
                f.seek(0)
                try:
                    response = requests.post(url, data=f, headers=self.auth_header, timeout=self.timeout)
                    log.info("PUT %s %s %s", url, response.status_code, response.elapsed.total_seconds())
                    if response.ok:
                        response = ET.fromstring(response.content)
                        break
                except requests.exceptions.ConnectionError as e:
                    log.error("Error requesting %s: %s", url, e)
                except requests.exceptions.HTTPError as e:
                    log.error("Error requesting %s: %s", url, e)
                except requests.exceptions.Timeout as e:
                    log.error("Timeout requesting %s: %s", url, e)
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
