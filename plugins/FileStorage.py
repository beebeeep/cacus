import os
from shutils import copy
from yapsy.IPlugin import IPlugin
import plugins

class FileStorage(plugins.IStoragePlugin):
    def configure(self, config):
        self.root = config['path']
        print "Configuring with config ", config

    def put(self, key, filename):
        newpath = os.path.join(self.root, key)
        copy(filename, newpath)
        return newpath

    def get(self, key):
        return os.path.join(self.root, key)
