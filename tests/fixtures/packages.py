#!/usr/bin/env python

import os
import shutil
import tempfile
import subprocess

import pytest
from debian import deb822


@pytest.yield_fixture
def deb_pkg():
    base = tempfile.mkdtemp('_cacustest')
    os.chdir(base)
    os.makedirs('./testpkg/usr/bin')
    with open('./testpkg/usr/bin/hello', 'w') as f:
        f.write("#/bin/sh\n\necho 'hello world!'\n")
    os.chmod('./testpkg/usr/bin/hello', 0755)
    os.makedirs('./testpkg/DEBIAN')

    control = deb822.Deb822(
        {'Package': 'helloworld',
         'Version': '1.0-1',
         'Section': 'base',
         'Priority': 'optional',
         'Architecture': u'all',
         'Depends': 'dash',
         'Maintainer': 'John Doe <john@example.com>',
         'Description': 'Hello World'})
    with open('./testpkg/DEBIAN/control', 'w') as f:
        f.write(control.dump())

    assert subprocess.call(["dpkg-deb", "--build", "testpkg"]) == 0

    yield os.path.join(base, "testpkg.deb")
    os.chdir('/')
    shutil.rmtree(base)
