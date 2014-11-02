#!/usr/bin/env python

import yaml
from shutil import copy

def connect_elliptics(args):
    log = elliptics.Logger(args.log, elliptics.log_level.debug)

    node = elliptics.Node(log)
    node.add_remotes([
        elliptics.Address(host = 'localhost', port = 1025),
        elliptics.Address(host = 'localhost', port = 1026),
        elliptics.Address(host = 'localhost', port = 1027)])
    return node

def local_put(key, filename, cfg):
    copy(filename, "{0}/{1}".format(cfg['path'], key))


def put(key, filename, cfg):
    if cfg['type'] == 'local':
        local_put(key, filename, cfg)

def get(key, cfg):
    pass

