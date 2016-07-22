#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from shutil import copy
from yapsy.IPlugin import IPlugin
import plugins

try:
    from cacus import common
except ImportError:
    import sys
    sys.path.append('../..')
    from cacus import common
log = logging.getLogger('cacus.file_storage')


class FileStorage(plugins.IStoragePlugin):

    def configure(self, config):
        self.root = config['path']
        if not os.path.isdir(self.root):
            os.makedirs(self.root)

    def delete(self, key):
        try:
            fname = os.path.join(self.root, key)
            if not os.path.isfile(fname):
                return common.Result('NOT_FOUND', 'File not found')
            else:
                os.unlink(os.path.join(self.root, key))
        except Exception as e:
            log.error("Cannot delete file %s: %s", key, e)
            return common.Result('ERROR', e)
        return common.Result('OK')

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
                return common.Result('ERROR', e)

        if filename:
            log.debug("Uploading from %s to %s", filename, storage_path)
            try:
                copy(filename, storage_path)
            except Exception as e:
                log.critical("Cannot upload file: %s", e)
                return common.Result('ERROR', e)
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
                return common.Result('ERROR', e)

        return common.Result('OK', 'OK', storage_key)


    def get(self, key, stream):
        try:
            fname = os.path.join(self.root, key)
            if not os.path.isfile(fname):
                return common.Result('NOT_FOUND', 'File not found')
            else:
                f = open(fname, 'r')
        except Exception as e:
            log.error("Cannot open file %s: %s", key, e)
            return common.Result('ERROR', e)
        for chunk in iter(lambda: f.read(4*1024*1024), b''):
            try:
                stream.write(chunk)
            except IOError:
                # remote side closed connection
                break
        return common.Result('OK')
