#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from shutil import copy
from yapsy.IPlugin import IPlugin
import plugins


class FileStorage(plugins.IStoragePlugin):

    def configure(self, config):
        self.root = config['path']

    def delete(self, key):
        os.unlink(key)

    def put(self, key, filename=None, file=None):
        if os.path.dirname(filename):
            os.path.makedirs(os.path.dirname(filename))
        newpath = os.path.join(self.root, key)
        copy(filename, newpath)
        return filename

    def get(self, key):
        return os.path.join(self.root, key)
