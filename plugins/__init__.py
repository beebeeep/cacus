#!/usr/bin/env python
# -*- coding: utf-8 -*-

from yapsy.IPlugin import IPlugin


class IStoragePlugin(IPlugin):

    def configure(self, config):
        raise NotImplementedError

    def put(self, key, filename):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError


class IMetadbPlugin(IPlugin):

    def configure(self, config):
        raise NotImplementedError

class PluginInitException(Exception):
    pass
