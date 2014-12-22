#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import pyinotify
import pprint
import time
import re
from binascii import hexlify
from minidinstall import DebianSigVerifier, ChangeFile, GPGSigVerifier
from tornado.ioloop import IOLoop
import threading

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
        self.uploaded_files = set()
        self.uploaded_event = threading.Event()

    def _processChangesFile(self, event):
        self.log.info("Processing .changes file %s", event.pathname)
        incoming_files = [event.pathname]
        current_hash = None
        changes = ChangeFile.ChangeFile()
        changes.load_from_file(event.pathname)
        changes.filename = event.pathname

        # .changes file contatins all incoming files and its checksums, so 
        # check if all files are available of wait for them
        for f in changes.getFiles():
            filename = os.path.join(event.path, f[2])
            self.log.info("Looking for %s from .changes", filename)
            while True:
                if filename in self.uploaded_files:
                    self.uploaded_files.remove(filename)
                    incoming_files.append(filename)
                    break
                else:
                    self.log.debug("Could not find %s, waiting...", filename)
                    self.uploaded_event.wait(1)

        # TODO: add reject dir and metadb collection and store all rejected files there
        try:
            changes.verify(event.path)
            verifier.verify(changes.filename)
        except ChangeFile.ChangeFileException as e:
            self.log.error("Checksum verification failed: %s", e)
            for f in incoming_files:
                os.unlink(f)
        except GPGSigVerifier.GPGSigVerificationFailure as e:
            self.log.error("PGP signature verification failed: %s", e)
            for f in incoming_files:
                os.unlink(f)

        # all new packages are going to unstable
        # TODO: take kinda distributed lock before updating metadata and uploading file to storage 
        self.log.info("Uploading %s to repo '%s', environment 'unstable'", incoming_files, self.repo)
        repo_manage.upload_package(self.repo, 'unstable', incoming_files, changes = changes)
        for f in incoming_files:
            os.unlink(f)

    def process_IN_CLOSE_WRITE(self, event):
        self.log.info("Got file %s", event.pathname)
        if event.pathname.endswith(".changes"):
            thread = threading.Thread(target = self._processChangesFile, args = (event,))
            #thread.daemon = True
            thread.start()
        else:
            # store uploaded file and send event to all waiting threads
            self.uploaded_files.add(event.pathname)
            self.uploaded_event.set()
            self.uploaded_event.clear()

def handle_files(notifier):
    pass

def start_duploader():
    for repo, param in common.config['repos'].iteritems():
        handler = EventHandler(repo = repo)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.ThreadedNotifier(wm, handler)
        wdd = wm.add_watch(param['incoming_dir'], pyinotify.ALL_EVENTS)
        log.info("Starting notifier for repo '%s' at %s", repo, param['incoming_dir'])
        notifier.start()


def start_tornado_duploader():
    # tornado is cool but we need to implement async processing of all incoming files...
    # not sure we really need this now
    wm = pyinotify.WatchManager()
    for repo, param in common.config['repos'].iteritems():
        wdd = wm.add_watch(param['incoming_dir'], pyinotify.IN_CLOSE_WRITE)
    ioloop = IOLoop.instance()
    notifier = pyinotify.TornadoAsyncNotifier(wm, ioloop, callback = handle_files)
    ioloop.start()
