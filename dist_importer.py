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
        p = common.db_repos[repo].find_one({'Source': changes['source'], 'Version': changes['version']})
        if p:
            log.warning("%s_%s is already uploaded to repo '%s', environment '%s'",
                        changes['source'], changes['version'], repo, p['environment'])
            if p['environment'] != env:
                log.warning("Dmoving %s_%s in repo '%s' from '%s' to '%s'",
                            changes['source'], changes['version'], repo, p['environment'], env)
                repo_manage.dmove_package(pkg=changes['source'], ver=changes['version'], repo=repo,
                                          src=p['environment'], dst=env, skipUpdateMeta=True)
            return None
        else:
            log.info("Importing %s_%s to %s/%s", changes['source'], changes['version'], repo, env)
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
            raise ImportException("{} not found".format(url))
        else:
            pkg_files.append(url)

    downloaded = []
    for url in pkg_files:
        file = os.path.join(common.config['storage']['temp_dir'], url.split('/')[-1])
        result = common.download_file(url, file)
        if result['result'] != common.status.OK:
            [os.unlink(x) for x in downloaded]
            raise ImportException("Cannot download {}: {}".format(url, result['msg']))
        downloaded.append(file)

    try:
        repo_manage.upload_package(repo, env, downloaded, changes, skipUpdateMeta=True)
    except repo_manage.UploadPackageError as e:
        log.error("Cannot upload package: %s", e)
        [os.unlink(x) for x in downloaded]
        raise ImportException("Cannot upload package: {}".format(e))

    # cleanup
    for file in downloaded:
        os.unlink(file)


def import_repo(repo_url=None, repo='common', env='unstable'):
    parser = RepoDirIndexParser(repo_url)
    index = requests.get(repo_url, stream=True, timeout=120)
    for chunk in index.iter_content(64*1024):
        parser.feed(chunk)
    changes_files = parser.changes
    log.info("Found %s packages to import", len(changes_files))
    for url in changes_files:
            file = os.path.join(common.config['storage']['temp_dir'], url.split('/')[-1])
            result = common.download_file(url, file)
            if result['result'] == common.status.OK:
                try:
                    import_package(file, repo, env)
                except ImportException as e:
                    log.error("Cannot import %s: %s", file, e)
                os.unlink(file)
            else:
                log.error("Cannot download %s", file)

    for arch in ('amd64', 'all', 'i386'):
        log.info("Updating '%s/%s/%s' repo metadata", repo, env, arch)
        repo_manage.update_repo_metadata(repo, env, arch)

    log.info("Import from %s completed, uploaded %s packages to %s %s", repo_url, len(changes_files), repo, env)
