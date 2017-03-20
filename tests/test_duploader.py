#!/usr/bin/env python

import time
from shutil import copy
import os

from fixtures.cacus import *
from fixtures.packages import *


def test_upload_package(distro, duploader, deb_pkg):
    comp = distro['components'][0]
    incoming = os.path.join(duploader.config['duploader_daemon']['incoming_root'],
                            distro['distro'], comp, os.path.basename(deb_pkg['file']))
    copy(deb_pkg['file'], incoming)
    time.sleep(3)
    assert package_is_in_repo(duploader, deb_pkg['control'], distro['distro'], comp)
