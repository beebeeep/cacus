#!/usr/bin/env python
# -*- coding: utf-8 -*-

from yapsy.IPlugin import IPlugin


class IStoragePlugin(IPlugin):

    def configure(self, config):
        raise Exception("Should be implemented")

    def put(self, key, filename):
        raise Exception("Should be implemented")

    def get(self, key):
        raise Exception("Should be implemented")


class IMetadbPlugin(IPlugin):

    def configure(self, config):
        raise Exception("Should be implemented")
