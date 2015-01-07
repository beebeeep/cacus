#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import pyinotify
import pprint
import time
import re
import gpgme
import threading
from binascii import hexlify
from minidinstall import ChangeFile, DebianSigVerifier
from io import BytesIO
from tornado.ioloop import IOLoop

import repo_manage
import common

chksum_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<fname>[-+_.a-z0-9]+)$')
files_re = re.compile('^ (?P<hash>[0-9A-Za-z]+) (?P<size>\d+) (?P<section>\w+) (?P<priority>\w+) (?P<fname>[-+_.a-z0-9]+)$')

log = logging.getLogger('cacus.duploader')


# consider using gpgme instead
verifier = DebianSigVerifier.DebianSigVerifier(keyrings = common.config['gpg']['keyrings'])

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
            signer = "stub"
            """
            ### gpgme suffers from some multithread issues sometimes:
            ### _gpgme_ath_mutex_lock: Assertion `*lock == ((ath_mutex_t) 0)' failed.
            ### TODO: manage this shit end switch to gpgme
            ### (minidinstall calls external gpgv process, i don't like it)
            ctx = gpgme.Context()
            cleartext = BytesIO('')
            signer = None
            with open(changes.filename, 'r') as f:
                result = ctx.verify(f, 0, cleartext)
                if result[0].validity != gpgme.VALIDITY_FULL:
                    raise Exception("File signed with untrusted key {0}".format(result[0].fpr))
                signer_key = ctx.get_key(result[0].fpr)
                uid = signer_key.uids[0]
                signer = "{0} <{1}>".format(uid.name, uid.email)
            """
        except ChangeFile.ChangeFileException as e:
            self.log.error("Checksum verification failed: %s", e)
        except gpgme.GpgmeError as e:
            self.log.error("Cannot check PGP signature: %s", e)
        except Exception as e:
            self.log.error("%s verification failed: %s", event.pathname, e)
        else:
            # all new packages are going to unstable
            # TODO: take kinda distributed lock before updating metadata and uploading file to storage 
            self.log.info("%s: signed by %s: OK, checksums: OK, uploading to repo '%s', environment 'unstable'", event.pathname, signer, self.repo)
            repo_manage.upload_package(self.repo, 'unstable', incoming_files, changes = changes)

        # in any case, clean up all incoming files
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
