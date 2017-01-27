#!/usr/bin/env python
# -*- coding: utf-8 -*-

from yapsy.PluginManager import PluginManagerSingleton

import sys
import common
import plugins
import logging

loaded_plugins = {}
log = logging.getLogger('cacus.loader')
yapsy_log = common.setup_logger('yapsy')


def load_plugins():
    manager = PluginManagerSingleton.get()
    manager.setPluginPlaces(['plugins/'])
    manager.setCategoriesFilter({
        'storage': plugins.IStoragePlugin,
        })

    manager.locatePlugins()
    manager.collectPlugins()

    for category in ('storage',):
        try:
            cfg = common.config[category]
            for plugin in manager.getPluginsOfCategory(category):
                log.info("Found plugin %s", plugin.name)
                if plugin.name == cfg['type']:
                    manager.activatePluginByName(plugin.name)
                    log.info("Activating storage plugin %s", plugin.name)
                    plugin.plugin_object.configure(cfg)
                    loaded_plugins[category] = plugin
                    break
        except:
            log.exception('Unable to load plugin category %s', category)
            sys.exit(1)


def get_plugin(category):
    return loaded_plugins[category].plugin_object

load_plugins()
