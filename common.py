#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import pymongo
import hashlib
import logging
import sys
import time
from pyme import core


def connect_mongo(cfg):
    if cfg['type'] == 'single_mongo':
        return pymongo.Connection(host = cfg['host'], port = cfg['port'])

def load_config(config_file):
    config = None
    with open(config_file) as cfg:
        config = yaml.load(cfg)
    ctx = core.Context()
    keys = [x for x in ctx.op_keylist_all(config['gpg']['signer'],1)]
    if len(keys) < 1:
        logging.critical("Cannot find suitable keys for %s", config['gpg']['signer'])
        sys.exit(1)

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

# As far as mongodb does not accept dot symbol in document keys
# we should replace all dots in filenames (that are used as keys) with smth else
def sanitize_filename(file):
    return file.replace(".", "___")

def desanitize_filename(file):
    return file.replace("___", ".")

class RepoLockTimeout(Exception):
    pass

class RepoLock:
    def __init__(self, collection, repo, env, timeout = 30):
        self.collection = collection
        self.repo = repo
        self.env = env
        self.timeout = timeout
        self.log = logging.getLogger("cacus.RepoLock")
    def __enter__(self):
        self.log.debug("Trying to lock %s/%s", self.repo, self.env)
        while True:
            try:
                db_cacus.locks.find_and_modify(
                        query =  {'repo': self.repo, 'env': self.env, 'locked': 0},
                            update =  {
                            '$set': {'repo': self.repo, 'env': self.env, 'locked': 1},
                            '$currentDate': { 'modified': {'$type': 'date'} } },
                        upsert =  True)
                self.log.debug("%s/%s locked", self.repo, self.env)
                break
            except pymongo.errors.DuplicateKeyError as e:
                time.sleep(1)
                self.timeout -= 1
                if self.timeout <= 0:
                    raise RepoLockTimeout("Timeout while trying to lock repo {0}/{1}".format(self.repo, self.env))
            except:
                self.log.error("Error while locking %s/%s: %s", self.repo, self.env, sys.exc_info())
                break
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            db_cacus.locks.find_and_modify(
                    query =  {'repo': self.repo, 'env': self.env, 'locked': 1},
                        update =  {
                        '$set': {'repo': self.repo, 'env': self.env, 'locked': 0},
                        '$currentDate': { 'modified': {'$type': 'date'} } },
                    upsert =  True)
        except pymongo.errors.DuplicateKeyError as e:
            pass
        except:
            self.log.error("Error while unlocking %s/%s: %s", self.repo, self.env, sys.exc_info())



config = None
db_repos = None
db_cacus = None
