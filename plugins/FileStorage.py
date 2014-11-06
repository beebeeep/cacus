#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from shutil import copy
from yapsy.IPlugin import IPlugin
import plugins

class FileStorage(plugins.IStoragePlugin):
    def configure(self, config):
        self.root = config['path']

    def put(self, key, filename):
        newpath = os.path.join(self.root, key)
        copy(filename, newpath)
        return newpath

    def get(self, key):
        return os.path.join(self.root, key)
