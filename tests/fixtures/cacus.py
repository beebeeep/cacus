#!/usr/bin/env python

import importlib
import os
import shutil
import tempfile

import pytest
from pytest_mongo import factories

mongo_proc = factories.mongo_proc(port=None, logsdir='/tmp')
mongo = factories.mongodb('mongo_proc')


@pytest.fixture
def distro(repo_manager):
    repo_manager.create_distro('testdistro', 'description',
                               components=['comp1', 'comp2'],
                               gpg_check=False, strict=False, simple=True,
                               incoming_wait_timeout=10)
    return {'distro': 'testdistro', 'components': ['comp1', 'comp2']}


@pytest.yield_fixture
def storage():
    dir = tempfile.mkdtemp('_cacustest')
    yield dir
    shutil.rmtree(dir)


@pytest.fixture
def repo_manager(request, storage, mongo):
    config = {
        'duploader_daemon': {'incoming_root': os.path.join(storage, 'incoming')},
        'gpg': {'home': '/home/midanil/.gnupg', 'sign_key': '7A69013C'},
        'lock_cleanup_timeout': 3600,
        'logging': {
            'destinations': {'console': False, 'file': '/tmp/cacus-test.log', 'syslog': False},
            'level': 'debug'
        },
        'plugin_path': ['/opt/cacus/plugins', os.path.join(os.path.dirname(__file__), '../../plugins')],
        'repo_daemon': {'port': 8088, 'proxy_storage': True, 'repo_base': '/debian', 'storage_subdir': 'storage'},
        'retry_count': 3,
        'retry_delays': [2, 5, 10, 30, 60, 90],
        'storage': {'path': os.path.join(storage, 'pool'), 'type': 'FileStorage'}
    }

    repo_manage = importlib.import_module('cacus.repo_manage')
    return repo_manage.RepoManager(config=config, mongo=mongo)
