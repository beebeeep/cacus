#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import pymongo
import hashlib
import sys
import time
import requests
import logging
import logging.handlers
import StringIO
from pyme import core
from pyme.constants.sig import mode


class Enum(set):

    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError


def setup_logger(name):
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)-4.4s] %(name)s: %(message)s")

    dst = globals()['config']['logging']['destinations']
    if dst['console']:
        h = logging.StreamHandler()
        h.setFormatter(logFormatter)
        log.addHandler(h)
    if dst['file']:
        h = logging.handlers.WatchedFileHandler(dst['file'])
        h.setFormatter(logFormatter)
        log.addHandler(h)
    if dst['syslog']:
        h = logging.handlers.SysLogHandler(facility=dst['syslog'])
        h.setFormatter(logging.Formatter("[%(levelname)-4.4s] %(name)s: %(message)s"))
        log.addHandler(h)

    return log


def connect_mongo(cfg):
    if cfg['type'] == 'single_mongo':
        return pymongo.Connection(host=cfg['host'], port=cfg['port'])


def load_config(config_file):
    config = None
    with open(config_file) as cfg:
        config = yaml.load(cfg)
    ctx = core.Context()
    keys = [x for x in ctx.op_keylist_all(config['gpg']['signer'], 1)]
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


def download_file(url, filename):
    log = logging.getLogger("cacus.downloader")
    try:
        total_bytes = 0
        r = requests.get(url, stream=True)
        if r.status_code == 200:
            with open(filename, 'w') as f:
                for chunk in r.iter_content(64*1024):
                    total_bytes += len(chunk)
                    f.write(chunk)
            result = {'result': globals()['status'].OK, 'msg': 'OK'}
            log.debug("GET %s %s %s bytes %s sec", url, r.status_code, total_bytes, r.elapsed.total_seconds())
        else:
            r.close()
            result = {'result': globals()['status'].NOT_FOUND, 'msg': 'GET {}: 404'.format(url)}
        r.close()
    except (requests.ConnectionError, requests.HTTPError) as e:
        result = {'result': globals()['status'].ERROR, 'msg': str(e)}
    except requests.Timeout as e:
        result = {'result': globals()['status'].TIMEOUT, 'msg': str(e)}
    return result


def gpg_sign(data, signer_email):
    sig = core.Data()
    plain = core.Data(data)
    ctx = core.Context()
    ctx.set_armor(1)
    signer = ctx.op_keylist_all(signer_email, 1).next()
    ctx.signers_add(signer)
    ctx.op_sign(plain, sig, mode.DETACH)
    sig.seek(0, 0)
    return sig.read()


class myStringIO(StringIO.StringIO):

    def __init__(self, *args, **kwargs):
        StringIO.StringIO.__init__(self, *args, **kwargs)

    def __enter__(self):
        self.seek(0)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # close() on StringIO will free memory buffer, so 'with' statement is destructive
        self.close()


class RepoLockTimeout(Exception):
    pass


class RepoLock:

    def __init__(self, collection, repo, env, timeout=30):
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
                    query={'repo': self.repo, 'env': self.env, 'locked': 0},
                    update={
                        '$set': {'repo': self.repo, 'env': self.env, 'locked': 1},
                        '$currentDate': {'modified': {'$type': 'date'}}},
                    upsert=True)
                self.log.debug("%s/%s locked", self.repo, self.env)
                break
            except pymongo.errors.DuplicateKeyError:
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
                query={'repo': self.repo, 'env': self.env, 'locked': 1},
                update={
                    '$set': {'repo': self.repo, 'env': self.env, 'locked': 0},
                    '$currentDate': {'modified': {'$type': 'date'}}},
                upsert=True)
            self.log.debug("%s/%s unlocked", self.repo, self.env)
        except pymongo.errors.DuplicateKeyError:
            pass
        except:
            self.log.error("Error while unlocking %s/%s: %s", self.repo, self.env, sys.exc_info())

config = None
db_repos = None
db_cacus = None
status = Enum(['OK', 'NO_CHANGES', 'NOT_FOUND', 'ERROR', 'TIMEOUT'])
