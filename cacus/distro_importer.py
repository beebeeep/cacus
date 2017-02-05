#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import uuid
import logging
from debian import deb822

import repo_manage
import common

log = logging.getLogger('cacus.importer')


def import_distro(url):
    release_url = os.path.join('Release')
    release_gpg_url = os.path.join('Release.gpg')
    release_filename = os.path.join(common.config['duploader_daemon']['incoming_root'], str(uuid.uuid1()))
    release_gpg_filename = os.path.join(common.config['duploader_daemon']['incoming_root'], str(uuid.uuid1()))
    common.download_file(release_url, release_filename)
    common.download_file(release_gpg_url, release_gpg_filename)

    with open(release_filename) as f:
        release = deb822.Release(f)
