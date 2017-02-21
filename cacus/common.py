#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import yaml
import uuid
import gnupg
import pymongo
import hashlib
import requests
import logging
import logging.handlers
import StringIO
from binascii import hexlify
from threading import Event
from itertools import chain, repeat
from tornado.ioloop import IOLoop


config = None
db = None
db_packages = None
db_sources = None
db_cacus = None
gpg = None
default_arches = ['all', 'amd64', 'i386']


class FatalError(Exception):
    http_code = 500


class TemporaryError(Exception):
    http_code = 409


class Timeout(Exception):
    http_code = 504


class NotFound(Exception):
    http_code = 404


class Conflict(Exception):
    http_code = 409


class DistroLockTimeout(Exception):
    http_code = 409


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


def initialize(config_file):
    global config, db, gpg
    if not config_file:
        if os.path.isfile('/etc/cacus.yml'):
            config_file = '/etc/cacus.yml'
        else:
            config_file = '/etc/cacus-default.yml'
    with open(config_file) as cfg:
        config = yaml.load(cfg)

    try:
        gpg = gnupg.GPG(homedir=config['gpg']['home'])
        keys = [x for x in gpg.list_keys(secret=True) if config['gpg']['sign_key'] in x['keyid']]
        if len(keys) < 1:
            raise Exception("Cannot find secret key with ID {}".format(config['gpg']['sign_key']))
    except Exception as e:
        logging.critical("GPG initialization error: %s", e)
        sys.exit(1)

    config['repo_daemon']['repo_base'] = config['repo_daemon']['repo_base'].rstrip('/')
    config['repo_daemon']['storage_subdir'] = config['repo_daemon']['storage_subdir'].rstrip('/').lstrip('/')
    connect_mongo()


def connect_mongo():
    global db_cacus, db_packages, db_sources
    config['db']['connect'] = False
    db = pymongo.MongoClient(**(config['db']))
    db_cacus = db['cacus']
    db_packages = db['packages']
    db_sources = db['sources']


def create_cacus_indexes():
    log = logging.getLogger("cacus.common")
    log.info("Creating indexes for cacus.distros...")
    db_cacus.distros.create_index('distro', unique=True)
    db_cacus.distros.create_index('snapshot')

    log.info("Creating indexes for cacus.components...")
    db_cacus.components.create_index(
        [('distro', pymongo.DESCENDING),
         ('component', pymongo.DESCENDING)],
        unique=True)
    db_cacus.components.create_index('snapshot')

    log.info("Creating indexes for cacus.repos...")
    db_cacus.repos.create_index(
        [('distro', pymongo.DESCENDING),
         ('component', pymongo.DESCENDING),
         ('architecture', pymongo.DESCENDING)],
        unique=True)

    log.info("Creating indexes for cacus.locks...")
    db_cacus.locks.create_index([
        ('distro', pymongo.DESCENDING),
        ('comp', pymongo.DESCENDING)],
        unique=True)


def create_packages_indexes(distros=None):
    log = logging.getLogger("cacus.common")
    if not distros:
        distros = db_packages.collection_names()

    for distro in distros:
        log.info("Creating indexes for packages.%s...", distro)
        db_packages[distro].create_index(
            [('Package', pymongo.DESCENDING),
             ('Version', pymongo.DESCENDING)],
            unique=True)
        db_packages[distro].create_index('components')

        db_sources[distro].create_index(
            [('Source', pymongo.DESCENDING),
             ('Version', pymongo.DESCENDING)],
            unique=True)
        db_sources[distro].create_index('components')


def get_hashes(file=None, filename=None):
    if filename:
        file = open(filename)

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

    if filename:
        file.close()

    return {'md5': md5.digest(), 'sha1': sha1.digest(), 'sha256': sha256.digest(), 'sha512': sha512.digest()}


def sanitize_filename(file):
    """ As far as mongodb does not accept dot symbol in document keys
    we should replace all dots in filenames (that are used as keys) with smth else
    """
    return file.replace(".", "___")


def desanitize_filename(file):
    return file.replace("___", ".")


def download_file(url, filename=None, md5=None, sha1=None, sha256=None):
    log = logging.getLogger("cacus.downloader")
    if not filename:
        filename = os.path.join(config['duploader_daemon']['incoming_root'], "cacus_tmp_" + str(uuid.uuid1()))

    try:
        total_bytes = 0
        log.debug("Downloading %s to %s", url, filename)
        r = requests.get(url, stream=True)
        if r.status_code == 200:
            _md5 = hashlib.md5()
            _sha1 = hashlib.sha1()
            _sha256 = hashlib.sha256()
            with open(filename, 'w') as f:
                for chunk in r.iter_content(4*1024*1024):
                    total_bytes += len(chunk)
                    f.write(chunk)
                    _md5.update(chunk)
                    _sha1.update(chunk)
                    _sha256.update(chunk)
                _md5 = _md5.digest()
                _sha1 = _sha1.digest()
                _sha256 = _sha256.digest()
            if sha256 and sha256 != _sha256:
                raise TemporaryError("SHA256 mismatch for {}: got {} instead of {}".format(url, hexlify(_sha256), hexlify(sha256)))
            if sha1 and sha1 != _sha1:
                raise TemporaryError("SHA1 mismatch for {}: got {} instead of {}".format(url, hexlify(_sha1), hexlify(sha1)))
            if md5 and md5 != _md5:
                raise TemporaryError("MD5 mismatch for {}: got {} instead of {}".format(url, hexlify(_md5), hexlify(md5)))
        elif r.status_code == 404:
            r.close()
            raise NotFound("{} returned {} {}".format(url, r.status_code, r.reason))
        else:
            r.close()
            raise TemporaryError("{} returned {} {}".format(url, r.status_code, r.reason))
        log.debug("GET %s %s %s bytes %s sec", url, r.status_code, total_bytes, r.elapsed.total_seconds())
        r.close()
    except (requests.ConnectionError, requests.HTTPError) as e:
        raise TemporaryError("Cannot fetch {}: {}".format(url, e))
    except requests.Timeout as e:
        raise Timeout("Cannot fetch {}: {}".format(url, e))
    except IOError as e:
        raise FatalError("Cannot fetch {} to {}: {}".format(url, filename, e))

    return filename


def gpg_sign(data):
    signature = gpg.sign(data, default_key=config['gpg']['sign_key'], detach=True, clearsign=False)
    return signature.data


def with_retries(fun, *args, **kwargs):
    delays = config['retry_delays']
    # repeat last delay infinitely
    delays = chain(delays[:-1], repeat(delays[-1]))
    exc = Exception("Don't blink!")
    for try_ in xrange(config['retry_count']):
            try:
                result = fun(*args, **kwargs)
            except (Timeout, TemporaryError, DistroLockTimeout) as e:
                exc = e
                pass
            except (FatalError, NotFound, Exception):
                raise
            else:
                break
            time.sleep(delays.next())
    else:
        raise exc
    return result


class myStringIO(StringIO.StringIO):

    def __init__(self, *args, **kwargs):
        StringIO.StringIO.__init__(self, *args, **kwargs)

    def __enter__(self):
        self.seek(0)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # close() on StringIO will free memory buffer, so 'with' statement is destructive
        self.close()


class ProxyStream(object):
    """ stream-like object for streaming result of blocking function to
        client of Tornado server
    """
    def __init__(self, handler, headers=[]):
        self._handler = handler
        self._headers = headers
        self._headers_set = False

    def sync_write(self, data, event):
        self._handler.write(data)
        self._handler.flush(callback=lambda: event.set())

    def write(self, data):
        if not self._handler.dead:
            if not self._headers_set:
                # send headers once we got first chunk of data (i.e storage is responding and found requested key)
                for header in self._headers:
                    self._handler.set_header(*header)
                self._headers_set = True

            event = Event()
            # write() and sync() should be called from thread where ioloop is running
            # so schedule write & flush for next iteration
            IOLoop.current().add_callback(self.sync_write, data, event)
            event.wait()
            return 0    # len(data)
        else:
            raise IOError("Client has closed connection")


class DistroLock:
    """ Poor man's implementation of distributed lock in mongodb.
    Ostrich algorithm used for dealing with deadlocks. You can always add some retries if returning 409 is not an option
    """

    def __init__(self, distro, comps=None, timeout=30):
        self.distro = distro
        if not comps:
            self.comps = [x['component'] for x in db_cacus.components.find({'distro': distro}, {'component': 1})]
        else:
            self.comps = comps
        self.timeout = timeout
        self.log = logging.getLogger("cacus.RepoLock")

    def _unlock(self, comps):
        for comp in comps:
            try:
                db_cacus.locks.find_one_and_update(
                    {'distro': self.distro, 'comp': comp, 'locked': 1},
                    {
                        '$set': {'distro': self.distro, 'comp': comp, 'locked': 0},
                        '$currentDate': {'modified': {'$type': 'date'}}
                    },
                    upsert=True)
                self.log.debug("%s/%s unlocked", self.distro, comp)
            except pymongo.errors.DuplicateKeyError:
                pass
            except:
                self.log.error("Error while unlocking %s/%s: %s", self.distro, comp, sys.exc_info())

    def __enter__(self):
        self.log.debug("Trying to lock %s/%s", self.distro, self.comps)
        while True:
            locked = []
            for comp in self.comps:
                try:
                    db_cacus.locks.find_one_and_update(
                        {'distro': self.distro, 'comp': comp, 'locked': 0},
                        {
                            '$set': {'distro': self.distro, 'comp': comp, 'locked': 1},
                            '$currentDate': {'modified': {'$type': 'date'}}
                        },
                        upsert=True)
                    self.log.debug("%s/%s locked", self.distro, comp)
                    locked.append(comp)
                except pymongo.errors.DuplicateKeyError:
                    self._unlock(locked)
                    time.sleep(1)
                    self.timeout -= 1
                    if self.timeout > 0:
                        break   # try to lock all comps once again
                    else:
                        raise DistroLockTimeout("Timeout while trying to lock distro {0}/{1}".format(self.distro, comp))
                except:
                    self.log.error("Error while locking %s/%s: %s", self.distro, comp, sys.exc_info())
                    self._unlock(locked)
                    raise FatalError("Error while locking {}/{}: {}", self.distro, comp, sys.exc_info())
            else:
                break       # good, we just locked all comps

    def __exit__(self, exc_type, exc_value, traceback):
        self._unlock(self.comps)
