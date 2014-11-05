#!/usr/bin/env python

import os
import sys
import logging
import pyinotify
import pprint
import time
import re
from binascii import hexlify
from minidinstall import DebianSigVerifier, ChangeFile, GPGSigVerifier

import repo_manage
import common

chksum_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<fname>[-+_.a-z0-9]+)$')
files_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<section>\w+) (?P<priority>\w+) (?P<fname>[-+_.a-z0-9]+)$')

log = logging.getLogger('cacus.duploader')

# TODO: get keyrings from APT config Dir::Etc::trusted
verifier = DebianSigVerifier.DebianSigVerifier(keyrings = ['/etc/apt/trusted.gpg'])

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, repo = None):
        self.repo = repo
        self.log = logging.getLogger('cacus.duploader.{0}'.format(repo))

    def process_IN_CLOSE_WRITE(self, event):
        self.log.info("Got file %s", event.pathname)

        # this will only work if .changes file are uploaded AFTER .deb, .dsc etc 
        # TODO: mb we should start new thread and just wait several seconds until all necessary files becomes available
        if event.pathname.endswith(".changes"):
            incoming_files = [event.pathname]
            current_hash = None
            changes = ChangeFile.ChangeFile()
            changes.load_from_file(event.pathname)

            for s in changes['files']:
                if s:
                    m = re.match(changes.md5_re, s)
                    if m:
                        filename = event.path + '/' + m.group('file')
                        incoming_files.append(filename)

            try:
                changes.verify(event.path)
                verifier.verify(event.pathname)
            except ChangeFile.ChangeFileException as e:
                log.error("Checksum verification failed: %s", e)
                for f in incoming_files:
                    os.unlink(f)
            except GPGSigVerifier.GPGSigVerificationFailure as e:
                log.error("PGP signature verification failed: %s", e)
                for f in incoming_files:
                    os.unlink(f)

            for file in incoming_files:
                if file.endswith('.deb'):
                    # all new packages are going to unstable
                    # TODO: take kinda distributed lock before updating metadata and uploading file to storage 
                    log.info("Uploading %s to repo '%s', environment 'unstable'", file, self.repo)
                    repo_manage.upload_packages(self.repo, 'unstable', [file])
                    log.info("Updating '%s' repo metadata", self.repo)
                    repo_manage.update_repo_metadata(self.repo, 'unstable')
                    for f in incoming_files:
                        os.unlink(f)
                    break

def start_duploader():
    for repo, param in common.config['repos'].iteritems():
        handler = EventHandler(repo = repo)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.ThreadedNotifier(wm, handler)
        wdd = wm.add_watch(param['incoming_dir'], pyinotify.ALL_EVENTS)
        log.info("Starting notifier for repo '%s' at %s", repo, param['incoming_dir'])
        notifier.start()


