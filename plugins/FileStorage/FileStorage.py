#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
from shutil import copy

from cacus import common
from cacus.plugin import IStoragePlugin

log = logging.getLogger('cacus.file_storage')


class FileStorage(IStoragePlugin):

    def configure(self, config):
        self.root = config['path']
        if not os.path.isdir(self.root):
            os.makedirs(self.root)

    @staticmethod
    def _hashdir(path, sha256):
        """ Append two levels of directory hierarchy based on provided hash """
        components = path.split(os.path.sep)
        return os.path.join(os.path.join(*components[0:-1]), sha256[0], sha256[1:3], components[-1])

    def delete(self, key):
        try:
            fname = os.path.join(self.root, key)
            if not os.path.isfile(fname):
                raise common.FatalError('File not found')
            else:
                os.unlink(os.path.join(self.root, key))
        except Exception as e:
            log.error("Cannot delete file %s: %s", key, e)
            raise common.FatalError(e)

    def put(self, key, filename=None, file=None, sha256=None):
        storage_key = self._hashdir(key, sha256)
        storage_path = os.path.join(self.root, storage_key)
        storage_dir = os.path.dirname(storage_path)
        if not os.path.isdir(storage_dir):
            try:
                os.makedirs(storage_dir)
            except Exception as e:
                if e.errno != os.errno.EEXIST:
                    # ignore EEXIST error (can be caused by dir already created in another thread)
                    log.critical("Cannot create path for given key '%s': %s", key, e)
                    raise common.FatalError(e)

        if filename:
            log.debug("Uploading from %s to %s", filename, storage_path)
            try:
                copy(filename, storage_path)
            except Exception as e:
                log.critical("Cannot upload file: %s", e)
                raise common.FatalError(e)
        elif file:
            log.debug("Uploading from <stream> to %s", storage_path)
            try:
                old_pos = file.tell()
                file.seek(0)
                with open(storage_path, 'wb') as f:
                    # 128 KiB is default readahead for big files
                    for chunk in iter(lambda: file.read(128*1024), b''):
                        f.write(chunk)
                file.seek(old_pos)
            except Exception as e:
                log.critical("Cannot upload file: %s", e)
                raise common.FatalError(e)

        return storage_key

    def get(self, key, stream):
        try:
            fname = os.path.join(self.root, key)
            if not os.path.isfile(fname):
                raise common.NotFound('File not found')
            else:
                f = open(fname, 'rb')
        except common.NotFound:
            raise
        except Exception as e:
            log.error("Cannot open file %s: %s", key, e)
            raise common.FatalError(e)

        for chunk in iter(lambda: f.read(4*1024*1024), b''):
            try:
                stream.write(chunk)
            except IOError:
                # remote side closed connection
                break
