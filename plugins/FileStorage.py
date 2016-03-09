#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from shutil import copy
from yapsy.IPlugin import IPlugin
import plugins

log = logging.getLogger('cacus.file_storage')


class FileStorage(plugins.IStoragePlugin):

    def configure(self, config):
        self.root = config['path']
        if not os.path.isdir(self.root):
            os.makedirs(self.root)

    def delete(self, key):
        os.unlink(os.path.join(self.root, key))

    def put(self, key, filename=None, file=None):
        #TODO: hashdir mb?
        storage_key = key
        storage_path = os.path.join(self.root, storage_key)
        storage_dir = os.path.dirname(storage_path)
        if not os.path.isdir(storage_dir):
            try:
                os.makedirs(storage_dir)
            except Exception as e:
                log.critical("Cannot create path for given key '%s': %s", key, e)
                return None

        if filename:
            log.debug("Uploading from %s to %s", filename, storage_path)
            try:
                copy(filename, storage_path)
            except Exception as e:
                log.critical("Cannot upload file: %s", e)
                return None
        elif file:
            log.debug("Uploading from <stream> to %s", storage_path)
            try:
                old_pos = file.tell()
                file.seek(0)
                with open(storage_path, 'wb') as f:
                    for chunk in iter(lambda: file.read(4096), b''):
                        f.write(chunk)
                file.seek(old_pos)
            except Exception as e:
                log.critical("Cannot upload file: %s", e)
                return None

        return storage_key


    def get(self, key):
        return os.path.join(self.root, key)
