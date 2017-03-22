#!/usr/bin/env python

import os
import subprocess

import pytest
from debian import debfile, deb822


@pytest.yield_fixture(scope='session')
def deb_pkg():
    os.chdir(os.path.join(os.path.dirname(__file__), 'contrib/testpackage'))
    assert subprocess.call(['debuild', '--no-lintian', '-uc', '-us']) == 0

    files = [os.path.abspath('../testpackage_0.1_amd64.changes')]
    with open(files[0]) as f:
        changes = deb822.Changes(f)
        for x in (os.path.abspath(os.path.join('..', x['name'])) for x in changes['Files']):
            files.append(x)
            if x.endswith('.deb'):
                deb = x
    control = debfile.DebFile(deb).debcontrol()

    yield {'control': control, 'debfile': deb, 'files': files}

    subprocess.call(['debclean'])
    map(os.unlink, files)
