#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import atexit
import pyinotify
import threading
from binascii import hexlify
from debian import deb822

import common
import repo_manage


class EventHandler(pyinotify.ProcessEvent):

    def __init__(self, repo_manager, settings, component):
        self.repo_manager = repo_manager
        self.distro = settings['distro']
        self.component = component
        self.gpg_check = settings.get('gpg_check', True)
        self.strict = settings.get('strict', True)
        self.incoming_wait_timeout = settings.get('incoming_wait_timeout', 5)
        self.log = repo_manager.log
        self.uploaded_files = {}
        self.uploaded_files_lock = threading.Lock()
        self.uploaded_event = threading.Event()

    def _gpgCheck(self, data):
        result = self.repo_manager.gpg.verify(data)
        if not result.valid:
            if result.status:
                raise Exception("signed with {}, status '{}'".format(result.key_id, result.status))
            else:
                raise Exception("Bad PGP data")
        return result.username

    def _process_single_deb(self, distro, component, file):
        if os.path.isfile(file) and file in self.uploaded_files:
            # if file is still exists and wasn't picked by some _processChangesFile(),
            # assume that it was meant to be uploaded as signle package
            with self.uploaded_files_lock:
                self.uploaded_files.pop(file)
            self.log.debug("Uploading %s to %s/%s", file, distro, component)
            try:
                common.with_retries(self.repo_manager.config['retry_count'], self.repo_manager.config['retry_delays'],
                                    self.repo_manager.upload_package, distro, component, [file], changes=None, forceUpdateMeta=True)
            except Exception as e:
                self.log.error("Error while uploading DEB %s: %s", file, e)
            os.unlink(file)
        elif file in self.uploaded_files:
            self.log.debug("Hm, strange, I was supposed to upload %s, but it's missing now", file)

    def _verifyChangesFile(self, changes, hashes):
        for file in changes['Files']:
            name = file['name']
            if file['md5sum'] != hexlify(hashes[name]['md5']):
                raise Exception(name)
        for file in changes['Checksums-Sha1']:
            name = file['name']
            if file['sha1'] != hexlify(hashes[name]['sha1']):
                raise Exception(name)
        for file in changes['Checksums-Sha256']:
            name = file['name']
            if file['sha256'] != hexlify(hashes[name]['sha256']):
                raise Exception(name)

    def _processChangesFile(self, event):
        self.log.info("Processing .changes file %s", event.pathname)
        incoming_files = [event.pathname]
        hashes = {}

        with open(event.pathname) as f:
            changes = deb822.Changes(f)

        if self.gpg_check:
            try:
                signer = self._gpgCheck(changes.raw_text)
            except Exception as e:
                self.log.error("%s verification failed: %s", event.pathname, e)
                map(os.unlink, incoming_files)
                return
        else:
            signer = "<not checked>"

        self.log.info("%s: signed by %s: OK, looking for incoming files", event.pathname, signer)

        # .changes file contatins all incoming files and its checksums, so
        # check if all files are available or wait for them
        for f in changes['Files']:
            filename = os.path.join(event.path, f['name'])
            self.log.info("Looking for %s from .changes", filename)
            while True:
                # uploaded_files stores all files in incoming directory uploaded so far
                if filename in self.uploaded_files:
                    with self.uploaded_files_lock:
                        self.log.debug("Taking %s for processing", filename)
                        hashes[f['name']] = self.uploaded_files.pop(filename)
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
            self._verifyChangesFile(changes, hashes)
        except Exception as e:
            self.log.error("Checksum verification failed: %s", e)
        else:
            self.log.info("%s-%s: sign: OK, checksums: OK, uploading to distro '%s', component '%s'",
                          changes['source'], changes['version'], self.distro, self.component)
            try:
                common.with_retries(self.repo_manager.config['retry_count'], self.repo_manager.config['retry_delays'],
                                    self.repo_manager.upload_package, self.distro, self.component,
                                    incoming_files, changes=changes, forceUpdateMeta=True)
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
            self.uploaded_files[event.pathname] = self.repo_manager.get_hashes(filename=event.pathname)
            self.uploaded_event.set()
            self.uploaded_event.clear()

        # if repo is not strict, single .deb file could be uploaded to repo,
        # so schedule uploader worker after 2*incoming timeout (i.e. deb was not picked by _processChangesFile)
        if not self.strict and (event.pathname.endswith('.deb') or event.pathname.endswith('.udeb')):
            self.log.info("Will upload it within %s seconds", 2*self.incoming_wait_timeout)
            uploader = threading.Timer(2*self.incoming_wait_timeout, self._process_single_deb, args=(self.distro, 'unstable', event.pathname))
            uploader.daemon = True
            uploader.start()


class Duploader(repo_manage.RepoManager):

    def _cleanup(self, watchers):
        for distro, distro_watchers in watchers.items():
            for comp, notifier in distro_watchers.items():
                self.log.info("Removing notifier for '%s/%s'", distro, comp)
                notifier.stop()
                del distro_watchers[comp]
            del watchers[distro]

    def run(self):
        self.watchers = {}
        atexit.register(self._cleanup, self.watchers)
        incoming_root = self.config['duploader_daemon']['incoming_root']
        if not os.path.isdir(incoming_root):
            os.mkdir(incoming_root)

        try:
            while True:
                # check out for any new distros in DB (except read-only snapshots) and create watchers for each component of distro, if any
                distros = list(self.db.cacus.distros.find({'snapshot': {'$exists': False}, 'imported': {'$exists': False}}))
                for distro_settings in distros:
                    distro = distro_settings['distro']
                    if distro not in self.watchers:
                        self.watchers[distro] = {}

                    components = [x['component'] for x in self.db.cacus.components.find({'distro': distro})]
                    for comp in components:
                        if comp not in self.watchers[distro]:
                            incoming_dir = os.path.join(incoming_root, distro, comp)
                            try:
                                if not os.path.isdir(incoming_dir):
                                    self.log.debug("Creating incoming dir '%s'", incoming_dir)
                                    os.makedirs(incoming_dir, mode=0777)
                            except Exception as e:
                                self.log.error("Cannot create dir for incoming files '%s': %s", incoming_dir, e)
                                continue
                            handler = EventHandler(self, distro_settings, comp)
                            wm = pyinotify.WatchManager()
                            notifier = pyinotify.ThreadedNotifier(wm, handler)
                            wm.add_watch(incoming_dir, pyinotify.ALL_EVENTS)
                            self.log.info("Starting notifier for '%s/%s' at %s, strict: %s", distro, comp, incoming_dir, distro_settings['strict'])
                            notifier.start()
                            self.watchers[distro][comp] = notifier

                    abandoned = set(self.watchers[distro].keys()) - set(components)
                    for comp in abandoned:
                        self.log.info("Removing notifier for '%s/%s'", distro, comp)
                        self.watchers[distro][comp].stop()
                        del(self.watchers[distro][comp])
                time.sleep(5)
        except KeyboardInterrupt:
            self._cleanup(self.watchers)


def start_daemon(config):
    duploader = Duploader(config)
    duploader.run()
