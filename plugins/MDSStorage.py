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
        self.read_url = config['read_url']
        self.write_url = config['write_url']
        self.auth_header = config['auth_header']
        self.c_timeout = config['connect_timeout']
        self.r_timeout = config['read_timeout']
        self.mdst_groups = [1338, 1959, 1061, 1212, 1633, 2796, 1054, 1079]

    def _find_key(self, key):
        """Restore an actual storage key from MDS

        If MDS returns 403 code for upload-ns handle, that means that we're trying to update an existing key,
        that is prohibited in common MDS namespaces.

        Fastest way to recover an actual key is to just look over all known groups with HEAD requests.
        DO NOT USE at production lol
        """
        for group in self.mdst_groups:
            storage_key = "{}/{}".format(group, key)
            url = "{}/get-repo/{}".format(self.read_url, storage_key)
            response = requests.head(url, headers=self.auth_header, timeout=(self.c_timeout, self.r_timeout))
            if response.ok:
                return storage_key
        return None

    def delete(self, key):
        url = "{}/delete-repo/{}".format(self.write_url, key)
        try:
            response = requests.post(url, headers=self.auth_header, timeout=(self.c_timeout, self.r_timeout))
            log.info("POST %s %s %s", url, response.status_code, response.elapsed.total_seconds())
        except requests.exceptions.ConnectionError as e:
            log.error("Error requesting %s: %s", url, e)
        except requests.exceptions.HTTPError as e:
            log.error("Error requesting %s: %s", url, e)
        except requests.exceptions.Timeout as e:
            log.error("Timeout requesting %s: %s", url, e)

    def put(self, key, filename=None, file=None):
        if filename:
            file = open(filename, 'rb')

        with file as f:
            url = "{0}/upload-repo/{1}".format(self.write_url, key)

            for n_try in xrange(3):
                f.seek(0)
                try:
                    response = requests.post(url, data=f, headers=self.auth_header, timeout=(self.c_timeout, self.r_timeout))
                    log.info("POST %s %s %s", url, response.status_code, response.elapsed.total_seconds())
                    if response.ok:
                        response = ET.fromstring(response.content)
                        break
                    if response.status_code == 403:
                        k = self._find_key(key)
                        log.warning("GOLDEN CRUTCH DETECTED: restored storage key '%s'", k)
                        return k
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
