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


        ################################################## TODO ########################
        ####    Надо разобраться с пакетами, состоящими из нескольких Binary и одного Source
        ####    типа yandex-sakila-mongo
        ####
        self.log.info("Got file %s", event.pathname)

        # this will only work if .changes file are uploaded AFTER .deb, .dsc etc 
        # TODO: mb we should start new thread and just wait several seconds until all necessary files becomes available
        if event.pathname.endswith(".changes"):
            incoming_files = [event.pathname]
            current_hash = None
            changes = ChangeFile.ChangeFile()
            changes.load_from_file(event.pathname)
            changes.filename = event.pathname

            for f in changes.getFiles():
                filename = os.path.join(event.path, f[2])
                incoming_files.append(filename)

            # TODO: add reject dir and metadb collection and store all rejected files there
            try:
                changes.verify(event.path)
                verifier.verify(changes.filename)
            except ChangeFile.ChangeFileException as e:
                log.error("Checksum verification failed: %s", e)
                for f in incoming_files:
                    os.unlink(f)
            except GPGSigVerifier.GPGSigVerificationFailure as e:
                log.error("PGP signature verification failed: %s", e)
                for f in incoming_files:
                    os.unlink(f)

            # all new packages are going to unstable
            # TODO: take kinda distributed lock before updating metadata and uploading file to storage 
            log.info("Uploading %s to repo '%s', environment 'unstable'", incoming_files, self.repo)
            repo_manage.upload_package(self.repo, 'unstable', incoming_files, changes = changes)
            log.info("Updating '%s' repo metadata", self.repo)
            repo_manage.update_repo_metadata(self.repo, 'unstable')
            for f in incoming_files:
                os.unlink(f)

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
