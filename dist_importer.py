#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import logging
import requests
from minidinstall import ChangeFile
from HTMLParser import HTMLParser

import repo_manage
import common

log = logging.getLogger('cacus.importer')


class ImportException(Exception):
    pass


def _checkFile(url):
    r = requests.head(url)
    return r.status_code == 200


class RepoDirIndexParser(HTMLParser):
    def __init__(self, base_url):
        HTMLParser.__init__(self)
        self._base_url = base_url
        self._changes_re = re.compile("(?P<changes>(?P<pkg>[-+.A-Za-z0-9]+)_(?P<ver>[-.A-Za-z0-9]+)_(?P<arch>amd64|all|i386)\.changes)")
        self.changes = []

    def handle_data(self, data):
        m = self._changes_re.search(data)
        if m:
            self.changes.append(self._base_url + m.group('changes'))


def import_package(changefile=None, repo=None, env='unstable'):
    pkg_files = []
    base_url = 'http://dist.yandex.ru/{}/{}'.format(repo, env)
    changes = ChangeFile.ChangeFile()
    changes.load_from_file(changefile)
    try:
        log.info("Importing %s-%s to %s %s", changes['source'], changes['version'], repo, env)
    except KeyError as e:
        log.error("Cannot find field %s in %s, skipping package", e[0], file)
        raise ImportException("Cannot find field %s in %s, skipping package", e[0].format(file))
    for f in (x[2] for x in changes.getFiles()):
        if f.endswith('.deb') or f.endswith('.udeb'):
            if f.find('_amd64') >= 0:
                url = '/'.join((base_url, 'amd64', f))
            elif f.find('_all') >= 0:
                url = '/'.join((base_url, 'all', f))
            elif f.find('_i386') >= 0:
                url = '/'.join((base_url, 'i386', f))
            else:
                log.warning("%s: unknown arch!", f)
                sys.exit(1)
        else:
            url = '/'.join((base_url, 'source', f))

        if not _checkFile(url):
            log.error("%s (%s): file not found", url, f)
            raise ImportException("%s not found".format(url))
        else:
            pkg_files.append(url)

    downloaded = []
    for url in pkg_files:
        file = os.path.join(common.config['storage']['temp_dir'], url.split('/')[-1])
        result = common.download_file(url, file)
        if result['result'] != common.status.OK:
            raise ImportException("Cannot download {}: {}".format(url, result['msg']))
        downloaded.append(file)

    try:
        repo_manage.upload_package(repo, env, downloaded, changes, skipUpdateMeta=True)
    except repo_manage.UploadPackageError as e:
        log.error("Cannot upload package: %s", e)
        raise ImportException("Cannot upload package: {}".format(e))

    #cleanup
    for file in downloaded:
        os.unlink(file)


def import_repo(url=None, repo='common', env='unstable'):
    parser = RepoDirIndexParser(url)
    index = requests.get(url, timeout=120)
    parser.feed(index.text)
    changes_files = parser.changes
    for url in changes_files:
        try:
            file = os.path.join(common.config['storage']['temp_dir'], url.split('/')[-1])
            result = common.download_file(url, file)
            if result['result'] == common.status.OK:
                import_package(file, repo, env)
            else:
                log.error("Cannot download %s", file)
            os.unlink(file)
        except ImportException as e:
            log.error("Cannot import %s: %s", file, e)

    for arch in ('amd64', 'all', 'i386'):
        log.info("Updating '%s/%s/%s' repo metadata", repo, env, arch)
        repo_manage.update_repo_metadata(repo, env, arch)

    log.info("Import from %s completed, uploaded %s packages to %s %s", url, len(changes_files), repo, env)
