#!/usr/bin/env python

import os
import time
import email
import random
import shutil
import tempfile
import subprocess

import pytest
from debian import debfile, deb822, changelog


@pytest.yield_fixture(scope='session')
def package(request):

    class Packager(object):
        tmp_dirs = []

        def get(self, version, deadweight=100):
            tmp_dir = tempfile.mkdtemp('_cacustestpkg')
            pkg_dir = os.path.join(tmp_dir, 'testpackage-{}'.format(version))
            tpl_path = os.path.join(os.path.dirname(__file__), 'contrib/testpackage')
            shutil.copytree(tpl_path, pkg_dir)
            self.tmp_dirs.append(tmp_dir)

            os.chdir(pkg_dir)

            with open('data', 'w') as f:
                for x in range(deadweight):
                    f.write(chr(random.randint(0, 255)))

            with open('debian/changelog', 'w') as f:
                ch = changelog.Changelog()
                ch.new_block(package='testpackage', version=changelog.Version(version), distributions='unstable',
                             urgency='low', author='John Doe <johnd@example.com>', date=email.utils.formatdate(time.mktime(time.localtime())))
                ch.add_change('')
                ch.add_change('  * test change in version {}'.format(version))
                ch.add_change('')
                ch.write_to_open_file(f)

            assert subprocess.call(['debuild', '--no-lintian', '-uc', '-us']) == 0

            files = [os.path.abspath('../testpackage_{}_amd64.changes'.format(version))]
            with open(files[0]) as f:
                changes = deb822.Changes(f)
                for x in (os.path.abspath(os.path.join('..', x['name'])) for x in changes['Files']):
                    files.append(x)
                    if x.endswith('.deb'):
                        deb = x
            control = debfile.DebFile(deb).debcontrol()

            return {'control': control, 'debfile': deb, 'debsize': os.stat(deb).st_size, 'files': files}

        def cleanup(self):
            for dir in self.tmp_dirs:
                shutil.rmtree(dir)

    p = Packager()
    yield p
    p.cleanup()


@pytest.fixture(scope='session')
def deb_pkg(package):
    return package.get('0.1')
