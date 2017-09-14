#!/usr/bin/env python

import time
from shutil import copy
import os

from fixtures.cacus import *
from fixtures.packages import *

def test_upload_package(distro, duploader, deb_pkg):
    time.sleep(1)   # XXX give duploader some time to pick up distro
    comp = distro['components'][0]
    incoming = os.path.join(duploader.config['duploader_daemon']['incoming_root'],
                            distro['distro'], comp, os.path.basename(deb_pkg['debfile']))
    copy(deb_pkg['debfile'], incoming)
    time.sleep(5)
    assert package_is_in_repo(duploader, deb_pkg['control'], distro['distro'], comp)


def test_upload_source(full_distro, duploader, deb_pkg):
    time.sleep(1)   # XXX give duploader some time to pick up distro
    comp = full_distro['components'][0]
    incoming = os.path.join(duploader.config['duploader_daemon']['incoming_root'],
                            full_distro['distro'], comp)
    for file in deb_pkg['files']:
        print file
        copy(file, incoming)
    time.sleep(5)
    assert package_is_in_repo(duploader, deb_pkg['control'], full_distro['distro'], comp)
    assert source_is_in_repo(duploader, deb_pkg['control'], full_distro['distro'], comp)
