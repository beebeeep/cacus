#!/usr/bin/env python

import importlib
import os
import signal
import shutil
import tempfile
import gnupg
from multiprocessing import Process
from debian import deb822

import pytest
from pytest_mongo import factories

for f in ['/usr/bin/mongod', '/usr/local/bin/mongod']:
    if os.path.isfile(f):
        mongod = f
        break

mongo_proc = factories.mongo_proc(port=None, logsdir='/tmp', executable=mongod)
mongo = factories.mongodb('mongo_proc')


@pytest.fixture
def distro_gen(repo_manager):

    class Generator(object):
        def get(self, name='testdistro', description='desription', components=['comp1', 'comp2'], gpg_check=False,
                strict=False, simple=True, incoming_wait_timeout=10, retention=2, quota=None):
            repo_manager.create_distro(name, description, components=components, gpg_check=gpg_check,
                                       strict=strict, simple=simple, retention=retention,
                                       incoming_wait_timeout=incoming_wait_timeout, quota=quota)
            return {'distro': name, 'components': components}

    return Generator()

@pytest.fixture
def distro(distro_gen):
    return distro_gen.get()

@pytest.fixture
def full_distro(distro_gen):
    return distro_gen.get(simple=False, strict=True)

@pytest.yield_fixture(scope='session')
def storage():
    dir = tempfile.mkdtemp('_cacustest')
    yield dir
    shutil.rmtree(dir)


@pytest.fixture
def cacus_config(request, storage):
    # take first available secret key from current user
    os.environ['PATH'] += ':/usr/local/bin'
    gpg = gnupg.GPG(homedir='~/.gnupg')
    keyid = gpg.list_keys(True)[0]['keyid']
    config = {
        'duploader_daemon': {'incoming_root': os.path.join(storage, 'incoming')},
        'gpg': {'home': '~/.gnupg', 'sign_key': keyid},
        'lock_cleanup_timeout': 3600,
        'logging': {
            'app': {'console': False, 'file': '/tmp/cacus-test.log', 'syslog': False},
            'access': {'console': False, 'file': '/tmp/cacus-test.log', 'syslog': False},
            'level': 'debug'
        },
        'plugin_path': ['/opt/cacus/plugins', os.path.join(os.path.dirname(__file__), '../../plugins')],
        'repo_daemon': {
            'port': 8088, 'proxy_storage': True, 'repo_base': '/debian', 'storage_subdir': '',
            'privileged_nets': [ '128.0.0.0/8' ], 'auth_secret': 'DLBcyOXUuRK0VFygWDe2+iXAihV6vHVNurasw38Rc+Q='
        },
        'retry_count': 3,
        'retry_delays': [2, 5, 10, 30, 60, 90],
        'storage': {'path': os.path.join(storage, 'pool'), 'type': 'FileStorage'}
    }
    return config


@pytest.fixture
def repo_manager(request, cacus_config, mongo):

    repo_manage = importlib.import_module('cacus.repo_manage')
    return repo_manage.RepoManager(config=cacus_config, mongo=mongo)


@pytest.yield_fixture
def duploader(request, cacus_config, mongo):
    module = importlib.import_module('cacus.duploader')
    duploader = module.Duploader(config=cacus_config, mongo=mongo, watcher_update_timeout=0.1)
    duploader_process = Process(target=duploader.run)
    duploader_process.start()
    yield duploader
    os.kill(duploader_process.pid, signal.SIGTERM)


def package_is_in_repo(manager, package, distro, component):
    packages = manager.db.cacus.repos.find_one({
        'distro': distro, 'component': component, 'architecture': package['Architecture']})['packages_file']
    with open(os.path.join(manager.config['storage']['path'], packages)) as f:
        for pkg in deb822.Packages.iter_paragraphs(f):
            if pkg['Package'] == package['Package'] and pkg['Version'] == package['Version']:
                if os.path.isfile(os.path.join(manager.config['storage']['path'], pkg['Filename'])):
                    return True
    return False


def source_is_in_repo(manager, package, distro, component):
    sources = manager.db.cacus.components.find_one({
        'distro': distro, 'component': component})['sources_file']
    with open(os.path.join(manager.config['storage']['path'], sources)) as f:
        for pkg in deb822.Sources.iter_paragraphs(f):
            if pkg['Source'] == package['Package'] and pkg['Version'] == package['Version']:
                for file in (x['name'] for x in pkg['Files']):
                    if os.path.isfile(os.path.join(manager.config['storage']['path'], file)):
                        return True
    return False
