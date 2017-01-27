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

sign_ok_re = re.compile(r'Good signature on "\/repo\/(?P<repo>\w+)\/mini-dinstall\/incoming\/(?P<changes>(?P<pkg>[-+.A-Za-z0-9]+)_(?P<ver>[-.A-Za-z0-9]+)_(?P<arch>amd64|all|i386)\.changes)"$')
uploaded_re = re.compile(r'Successfully installed (?P<pkg>[-_A-Za-z0-9]+) (?P<ver>.+?) to unstable')
#robot-dmover : common yandex-music-utils 15.13.0.7.de20eaa240e8 testing -> stable
dmoved_re = re.compile(r'(?P<who>.+?)\s+:\s+(?P<repo>.+?)\s+(?P<pkg>[-_A-Za-z0-9]+)\s+(?P<ver>.+?)\s+(?P<src>\w+)\s+->\s+(?P<dst>\w+)$')

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
        fsize = os.stat(self._filename).st_size
        pos = self._file.tell()
        if fsize < pos:
            log.debug("Current pos in %s is %s > file size %s, reopen file", self._filename, pos, fsize)
            self._file.close()
            self._file = self._openFile(self._filename)

        while True:
            line = self._file.readline()
            if line:
                #log.debug("Read from %s: '%s'", self._filename, line.rstrip())
                self.processLine(line)
            else:
                break

class DmovedHandler(EventHandler):
    def _notifyCacus(self, repo, pkg, ver, src, dst):
        log.info("%s_%s was dmoved in %s from %s to %s", pkg, ver, repo, src, dst)
        try:
            url = "http://cacus.haze.yandex.net/debian/api/v1/dmove/{}".format(repo)
            response = requests.post(
                    url,
                    data={'pkg': pkg, 'ver': ver, 'from': src, 'to': dst},
                    timeout=5)
            log.info("POST %s %s %s", url, response.status_code, response.elapsed.total_seconds())
        except Exception as e:
            log.error("Error requesting %s: %s", url, e)

    def processLine(self, line):
        match = dmoved_re.search(line)
        if match:
            repo = match.group('repo')
            pkg = match.group('pkg')
            ver = match.group('ver')
            src = match.group('src')
            dst = match.group('dst')
            self._notifyCacus(repo, pkg, ver, src, dst)

class DinstalledHandler(EventHandler):
    def __init__(self, *args, **kwargs):
        self.changesFiles = {}
        super(DinstalledHandler, self).__init__(*args, **kwargs)

    def _notifyCacus(self, repo, file):
        try:
            url = "http://cacus.haze.yandex.net/debian/api/v1/dist-push/{}?file={}".format(repo, file)
            response = requests.post(url, timeout=5)
            log.info("POST %s %s %s", url, response.status_code, response.elapsed.total_seconds())
        except Exception as e:
            log.error("Error requesting %s: %s", url, e)

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
            # notify cacus if package was uploaded to unstable
            if match:
                pkg = match.group('pkg')
                ver = match.group('ver')
                try:
                    changes = self.changesFiles.pop('{}_{}'.format(pkg,ver))
                    thread = threading.Thread(target=self._notifyCacus, args=(changes['repo'],changes['changes']))
                    thread.start()
                except KeyError:
                    log.error("Got %s_%s uploaded to unstable, but cannot find information about it", pkg, ver)


notifiers = []
for filename in ['/tmp/testlog', '/var/log/mini-dinstall-yandex-precise.log', '/var/log/mini-dinstall-common.log']:
    wm = pyinotify.WatchManager()
    n = pyinotify.ThreadedNotifier(wm, DinstalledHandler(filename))
    wdd = wm.add_watch(filename, pyinotify.IN_MODIFY , rec=True)
    n.start()
    notifiers.append( (n,wm,wdd) )

filename = '/var/log/dmove.log'
wm = pyinotify.WatchManager()
n = pyinotify.ThreadedNotifier(wm, DmovedHandler(filename))
wdd = wm.add_watch(filename, pyinotify.IN_MODIFY , rec=True)
n.start()
notifiers.append( (n,wm,wdd) )

while True:
    try:
        signal.pause()
    except KeyboardInterrupt:
        for n in notifiers:
            n[0].stop()
        break
