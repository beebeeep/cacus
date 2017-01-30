#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from yapsy.PluginManager import PluginManagerSingleton

import os
import common
from plugin import IStoragePlugin
#import plugin

loaded_plugins = {}
log = logging.getLogger('cacus.loader')
yapsy_log = logging.getLogger('yapsy')


def load_plugins():
    manager = PluginManagerSingleton.get()

    cwd = os.path.abspath(os.path.dirname(__file__))
    plugin_dirs = common.config.get('plugin_path', [])
    plugin_dirs.append(os.path.join(cwd, 'plugins'))
    log.debug("Searching plugins in %s", plugin_dirs)
    manager.setPluginPlaces(plugin_dirs)

    manager.setCategoriesFilter({'storage': IStoragePlugin})
    manager.collectPlugins()

    for category in ('storage',):
        try:
            cfg = common.config[category]
            for p in manager.getPluginsOfCategory(category):
                log.info("Found plugin %s", p.name)
                if p.name == cfg['type']:
                    manager.activatePluginByName(p.name)
                    log.info("Activating storage plugin %s", p.name)
                    p.plugin_object.configure(cfg)
                    loaded_plugins[category] = p
                    break
        except:
            log.exception('Unable to load plugin category %s', category)


def get_plugin(category):
    return loaded_plugins[category].plugin_object
