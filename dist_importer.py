#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import pprint
from minidinstall import ChangeFile, DebianSigVerifier
from functools import partial

import repo_manage
import common

log = logging.getLogger('cacus.importer')


def import_repo(path = None, repo = 'common', env = 'unstable'):
    changes_files = [f for f in map(partial(os.path.join, path), os.listdir(path))
            if f.endswith('changes') and os.path.isfile(f)]
    count = 0
    for file in changes_files:
        pkg_files = []
        changes = ChangeFile.ChangeFile()
        changes.load_from_file(file)
        log.info("Importing %s-%s to %s %s", changes['source'], changes['version'], repo, env)
        for f in (x[2] for x in changes.getFiles()):
            filename = ""
            if f.endswith('.deb') or f.endswith('.udeb'):
                count += 1
                if f.find('_amd64') >= 0:
                    filename = os.path.join(path, 'amd64', f)
                elif f.find('_all') >= 0 :
                    filename = os.path.join(path, 'all', f)
                elif f.find('_i386') >= 0:
                    filename = os.path.join(path, 'i386', f)
                else:
                    log.warning("%s: unknown arch!", f)
                    sys.exit(1)
            else:
                filename = os.path.join(path, 'source', f)

            if not os.path.isfile(filename):
                log.error("%s (%s): file not found", filename, f)
                #sys.exit(1)
                break
            else:
                pkg_files.append(filename)
        else:   # if we don't break'ed because of some error
            repo_manage.upload_package(repo, env, pkg_files, changes, skipUpdateMeta = True)
    for arch in ('amd64', 'all', 'i386'):
        log.info("Updating '%s/%s/%s' repo metadata", repo, env, arch)
        repo_manage.update_repo_metadata(repo, env, arch)

    log.info("Import from %s completed, uploaded %s packages to %s %s", path, count, repo, env)
