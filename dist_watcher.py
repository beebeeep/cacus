#!/home/dmiga/venv/bin/python2.7

import pyinotify
import threading
import requests
import logging
import signal
import re
import os

log = logging.getLogger(name="dist_watcher")
logFormatter = logging.Formatter("%(asctime)s [%(levelname)-4.4s] %(name)s: %(message)s")
log.setLevel(logging.DEBUG)
h = logging.StreamHandler()
h.setFormatter(logFormatter)
log.addHandler(h)

sign_ok_re = re.compile(r'Good signature on "\/repo\/(?P<repo>\w+)\/mini-dinstall\/incoming\/(?P<changes>(?P<pkg>[-.A-Za-z0-9]+)_(?P<ver>[-.A-Za-z0-9]+)_(?P<arch>amd64|all|i386)\.changes)"$')
uploaded_re = re.compile(r'Successfully installed (?P<pkg>[-_A-Za-z0-9]+) (?P<ver>.+?) to unstable')
changes = set()
changes_lock = threading.Lock()

def process_sign(match):
    repo = match.group('repo')
    file = match.group('file')
    with changes_lock:
        changes.add( (repo, file) )

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, filename):
        log.debug("Initiating file watcher on %s", filename)
        self._filename = filename
        self._file = self._openFile(filename)

    def _openFile(self, filename):
        file = open(filename, 'r')
        file.seek(0, 2)       #scroll down to the EOF
        return file

    def process_IN_MOVE_SELF(self, event):
        log.debug("Watched file %s was moved", self._filename)
        # TODO handle this

    def process_IN_DELETE_SELF(self, event):
        log.debug("Watched file %s was deleted", self._filename)
        # TODO handle this

    def process_IN_MODIFY(self, event):
        log.info("MODIFY %s", event.pathname)

        fsize = os.stat(self._filename).st_size
        pos = self._file.tell()
        if fsize < pos:
            log.debug("Current pos in %s is %s > file size %s, reopen file", self._filename, pos, fsize)
            self._file.close()
            self._file = self._openFile(self._filename)

        while True:
            line = self._file.readline()
            if line:
                log.debug("Read from %s: '%s'", self._filename, line.rstrip())
                self.processLine(line)
            else:
                break

class DinstalledHandler(EventHandler):
    def __init__(self, *args, **kwargs):
        self.changesFiles = {}
        super(DinstalledHandler, self).__init__(*args, **kwargs)

    def _notifyCacus(self, repo, file):
        log.info("BOOM %s %s", repo, file)

    def processLine(self, line):
        match = sign_ok_re.search(line)
        if match:
            repo = match.group('repo')
            pkg = match.group('pkg')
            ver = match.group('ver')
            changes = match.group('changes')
            self.changesFiles['{}_{}'.format(pkg,ver)] = {'changes': changes, 'repo': repo}
            log.debug("Found ok signature for %s: package %s_%s", changes, pkg, ver)
        else:
            match = uploaded_re.search(line)
            if match:
                pkg = match.group('pkg')
                ver = match.group('ver')
                try:
                    changes = self.changesFiles.pop('{}_{}'.format(pkg,ver))
                    thread = threading.Thread(target=self._notifyCacus, args=(changes['repo'],changes['changes']))
                    thread.start()
                except KeyError:
                    log.error("Got %s_%s uploaded to unstable, but cannot find information about it", pkg, ver)

filename = '/tmp/testlog'
wm = pyinotify.WatchManager()
notifier = pyinotify.ThreadedNotifier(wm, DinstalledHandler(filename))
notifier.start()
wdd = wm.add_watch(filename, pyinotify.IN_MODIFY , rec=True)

while True:
    try:
        signal.pause()
    except KeyboardInterrupt:
        notifier.stop()
        break
