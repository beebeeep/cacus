#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import pyinotify
import pprint
import time
import re
import threading
from binascii import hexlify
from minidinstall import ChangeFile, DebianSigVerifier
from io import BytesIO
from tornado.ioloop import IOLoop
from pyme import core, errors

import repo_manage
import common

log = logging.getLogger('cacus.duploader')


class EventHandler(pyinotify.ProcessEvent):

    def __init__(self, distro=None):
        self.distro = distro
        self.log = logging.getLogger('cacus.duploader.{0}'.format(distro))
        self.uploaded_files = set()
        self.uploaded_files_lock = threading.Lock()
        self.uploaded_event = threading.Event()

    def _gpgCheck(self, filename):
        ctx = core.Context()
        file = core.Data(file=filename)
        plain = core.Data()
        ctx.op_verify(file, None, plain)
        result = ctx.op_verify_result()
        signer_key = ctx.get_key(result.signatures[0].fpr, 0)
        uid = signer_key.uids[0]
        signer = "{0} <{1}>".format(uid.name, uid.email)
        if result.signatures[0].status != 0:
            raise Exception("File signed with untrusted key {0} ({1})".format(signer_key, signer))
        return signer

    def _processChangesFile(self, event):
        self.log.info("Processing .changes file %s", event.pathname)
        incoming_files = [event.pathname]
        current_hash = None
        changes = ChangeFile.ChangeFile()
        changes.load_from_file(event.pathname)
        changes.filename = event.pathname

        if common.config['duploader_daemon']['gpg_check']:
            try:
                signer = self._gpgCheck(changes.filename)
            except errors.GPGMEError as e:
                self.log.error("Cannot check PGP signature: %s", e)
                map(os.unlink, incoming_files)
                return
            except Exception as e:
                self.log.error("%s verification failed: %s", event.pathname, e)
                map(os.unlink, incoming_files)
                return
        else:
            signer = "<not checked>"

        self.log.info("%s: signed by %s: OK, looking for incoming files", event.pathname, signer)

        # .changes file contatins all incoming files and its checksums, so
        # check if all files are available or wait for them
        for f in changes.getFiles():
            filename = os.path.join(event.path, f[2])
            self.log.info("Looking for %s from .changes", filename)
            while True:
                # uploaded_files stores all files in incoming directory uploaded so far
                if filename in self.uploaded_files:
                    # eeeh, we're under GIL, yea? do we really need to take a lock here?
                    with self.uploaded_files_lock:
                        self.uploaded_files.remove(filename)
                    incoming_files.append(filename)
                    break
                else:
                    self.log.debug("Could not find %s, waiting...", filename)
                    r = self.uploaded_event.wait(common.config['duploader_daemon']['incoming_wait_timeout'])
                    if not r:
                        # we don't get all files from .changes in time, clean up and exit
                        # TODO: add to rejected
                        map(os.unlink, incoming_files)
                        return

        # TODO: add reject dir and metadb collection and store all rejected files there
        try:
            changes.verify(event.path)
        except ChangeFile.ChangeFileException as e:
            self.log.error("Checksum verification failed: %s", e)
        else:
            # all new packages are going to unstable
            self.log.info("%s-%s: sign: OK, checksums: OK, uploading to distro '%s', environment 'unstable'",
                          changes['source'], changes['version'], self.distro)
            repo_manage.upload_package(self.distro, 'unstable', incoming_files, changes=changes)

        # in any case, clean up all incoming files
        map(os.unlink, incoming_files)

    def process_IN_CLOSE_WRITE(self, event):
        self.log.info("Got file %s", event.pathname)
        if event.pathname.endswith(".changes"):
            thread = threading.Thread(target=self._processChangesFile, args=(event,))
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
    for distro, param in common.config['duploader_daemon']['distributions'].iteritems():
        handler = EventHandler(distro=distro)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.ThreadedNotifier(wm, handler)
        wdd = wm.add_watch(param['incoming_dir'], pyinotify.ALL_EVENTS)
        log.info("Starting notifier for distribution '%s' at %s", distro, param['incoming_dir'])
        notifier.start()
