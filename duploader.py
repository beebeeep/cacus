#!/usr/bin/env python

import os
import sys
import logging
import pyinotify
import pprint
import time
import re
from binascii import hexlify

import repo_manage
import common

chksum_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<fname>[-+_.a-z0-9]+)$')
files_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<section>\w+) (?P<priority>\w+) (?P<fname>[-+_.a-z0-9]+)$')

log = logging.getLogger('cacus.duploader')

# see https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-debianchangesfiles
def _read_section(hash_name, changes, files):
    while True:
        line = changes.readline().rstrip()
        m = re.match(chksum_re, line)
        if not m:
            m = re.match(files_re, line)
            if not m:
                return line

        fname = m.group('fname')
        if not files.has_key(fname):
            files[fname] = {}
        files[fname][hash_name] = m.group('hash')
        if files[fname].has_key('size'):
            if files[fname]['size'] != int(m.group('size')):
                raise Exception("Size differs!")
        else:
            files[fname]['size'] = int(m.group('size'))

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, repo = None):
        self.repo = repo
        self.log = logging.getLogger('cacus.duploader.{0}'.format(repo))

    def process_IN_CLOSE_WRITE(self, event):
        self.log.info("Got file %s", event.pathname)

        # this will only work if .changes file are uploaded AFTER .deb, .dsc etc 
        if event.pathname.endswith(".changes"):
            incoming_files = {}
            current_hash = None
            with open(event.pathname) as changes:
                while True:
                    line = changes.readline()
                    if not line:
                        break
                    line = line.rstrip()

                    # scan .changes file for sections with files list and its md5, sha1 and sha256 hashes
                    if line == 'Checksums-Sha1:':
                        line = _read_section('sha1', changes, incoming_files)
                    if line == 'Checksums-Sha256:':
                        line = _read_section('sha256', changes, incoming_files)
                    if line == 'Files:':
                        line = _read_section('md5', changes, incoming_files)

            # find uploaded .deb file, check hashes and upload package to storage
            for file, attrs in incoming_files.iteritems():
                if file.endswith('.deb'):
                    deb = event.path + '/' + file
                    with open(deb) as f:
                        hashes = common.get_hashes(f)
                    for alg in ('md5', 'sha1', 'sha256'):
                        if hexlify(hashes[alg]) != attrs[alg]:
                            raise Exception("hash mismatch!")
                    # all new packages are going to unstable
                    # TODO: take kinda distributed lock before updating metadata and uploading file to storage 
                    log.info("Uploading %s to repo '%s', environment 'unstable'", deb, self.repo)
                    repo_manage.upload_packages(self.repo, 'unstable', [deb])
                    log.info("Updating '%s' repo metadata", self.repo)
                    repo_manage.update_repo_metadata(self.repo, 'unstable')
                    break

def start_duploader():
    for repo, param in common.config['repos'].iteritems():
        handler = EventHandler(repo = repo)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.ThreadedNotifier(wm, handler)
        wdd = wm.add_watch(param['incoming_dir'], pyinotify.ALL_EVENTS)
        log.info("Starting notifier for repo '%s' at %s", repo, param['incoming_dir'])
        notifier.start()


