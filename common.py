#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import pymongo
import hashlib


def connect_mongo(cfg):
    if cfg['type'] == 'single_mongo':
        return pymongo.Connection(host = cfg['host'], port = cfg['port'])

def load_config(config_file):
    with open(config_file) as cfg:
        config = yaml.load(cfg)
        return config

def get_hashes(file):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    fpos = file.tell()
    file.seek(0)

    for chunk in iter(lambda: file.read(4096), b''):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        sha512.update(chunk)

    file.seek(fpos)

    return {'md5': md5.digest(), 'sha1': sha1.digest(), 'sha256': sha256.digest(), 'sha512': sha512.digest()}

config = None
db = None
