#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import pyinotify
import time
import threading
from minidinstall import ChangeFile
from pyme import core, errors

import repo_manage
import common

log = logging.getLogger('cacus.duploader')


################################### TODO #############################
# 1. unlink files after some time to allow debrelease/dupload/dput to do their job
#######################################################################

class EventHandler(pyinotify.ProcessEvent):

    def __init__(self, settings):
        self.distro = settings['distro']
        self.gpg_check = settings.get('gpg_check', True)
        self.strict = settings.get('strict', True)
        self.incoming_wait_timeout = settings.get('incoming_wait_timeout', 5)
        self.log = logging.getLogger('cacus.duploader.{0}'.format(self.distro))
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

    def _process_single_deb(self, distro, component, file):
        if os.path.isfile(file) and file in self.uploaded_files:
            # if file is still exists and wasn't picked by some _processChangesFile(),
            # assume that it was meant to be uploaded as signle package
            with self.uploaded_files_lock:
                self.uploaded_files.remove(file)
            self.log.debug("Uploading %s to %s/%s", file, distro, component)
            try:
                common.with_retries(repo_manage.upload_package, distro, component, [file], changes=None, forceUpdateMeta=True)
            except Exception as e:
                self.log.error("Error while uploading DEB %s: %s", file, e)
            os.unlink(file)
        elif file in self.uploaded_files:
            self.log.debug("Hm, strange, I was supposed to upload %s, but it's missing now", file)

    def _processChangesFile(self, event):
        self.log.info("Processing .changes file %s", event.pathname)
        incoming_files = [event.pathname]
        changes = ChangeFile.ChangeFile()
        changes.load_from_file(event.pathname)
        changes.filename = event.pathname

        if self.gpg_check:
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
                        self.log.debug("Taking %s for processing", filename)
                        self.uploaded_files.remove(filename)
                    incoming_files.append(filename)
                    break
                else:
                    self.log.debug("Could not find %s, waiting...", filename)
                    r = self.uploaded_event.wait(self.incoming_wait_timeout)
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
            # TODO set default component / add per-component upload dirs
            # for now all new packages are going to component 'unstable'
            self.log.info("%s-%s: sign: OK, checksums: OK, uploading to distro '%s', component 'unstable'",
                          changes['source'], changes['version'], self.distro)
            try:
                common.with_retries(repo_manage.upload_package, self.distro, 'unstable', incoming_files, changes=changes, forceUpdateMeta=True)
                self.log.warn("OK")
            except Exception as e:
                self.log.error("Error while uploading file: %s", e)

        # in any case, clean up all incoming files
        map(os.unlink, incoming_files)

    def process_IN_CLOSE_WRITE(self, event):
        self.log.info("Got file %s", event.pathname)
        if event.pathname.endswith(".changes"):
            thread = threading.Thread(target=self._processChangesFile, args=(event,))
            # thread.daemon = True
            thread.start()
        else:
            # store uploaded file and send event to all waiting threads
            self.uploaded_files.add(event.pathname)
            self.uploaded_event.set()
            self.uploaded_event.clear()

        # if repo is not strict, single .deb file could be uploaded to repo,
        # so schedule uploader worker after 2*incoming timeout (i.e. deb was not picked by _processChangesFile)
        if not self.strict and (event.pathname.endswith('.deb') or event.pathname.endswith('.udeb')):
            uploader = threading.Timer(2*self.incoming_wait_timeout, self._process_single_deb, args=(self.distro, 'unstable', event.pathname))
            uploader.daemon = True
            uploader.start()


def start_duploader():
    watchers = {}
    while True:
        # check out for any new distros in DB (except read-only snapshots) and create watchers for them if any
        new_watchers = list(common.db_cacus.distros.find({'snapshot': {'$exists': False}}))
        for watcher in new_watchers:
            if watcher['distro'] not in watchers:
                incoming_dir = os.path.join(common.config['duploader_daemon']['incoming_root'], watcher['distro'])
                try:
                    if not os.path.isdir(incoming_dir):
                        log.debug("Creating incoming dir '%s'", incoming_dir)
                        os.mkdir(incoming_dir)
                except Exception as e:
                    log.error("Cannot create dir for incoming files '%s': %s", incoming_dir, e)
                    continue
                handler = EventHandler(watcher)
                wm = pyinotify.WatchManager()
                notifier = pyinotify.ThreadedNotifier(wm, handler)
                wdd = wm.add_watch(incoming_dir, pyinotify.ALL_EVENTS)
                log.info("Starting notifier for distribution '%s' at %s", watcher['distro'], incoming_dir)
                notifier.start()
                watchers[watcher['distro']] = notifier

        abandoned = set(watchers.keys()) - set(x['distro'] for x in new_watchers)
        for watcher in abandoned:
            log.info("Removing notifier for distribution '%s'", watcher)
            watchers[watcher].stop()
            del(watchers[watcher])
        time.sleep(5)
