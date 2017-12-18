#!/usr/bin/env python

import os
import time
import logging

class MyLogger(logging.getLoggerClass()):
    def makeRecord(self, name, lvl, fn, lno, msg, args, exc_info, func=None, extra=None):
        if not extra:
            extra = {}
        extra['user'] = 'Test'
        return super(MyLogger, self).makeRecord(name, lvl, fn, lno, msg, args, exc_info, func, extra)

logging.setLoggerClass(MyLogger)

import pytest

from fixtures.cacus import *
from fixtures.packages import *


def test_snapshot_name(repo_manager):
    assert repo_manager._get_snapshot_name('distro', 'name') == 'distro@name'


def test_create_repo(repo_manager):
    repo_manager.create_distro('testdistro', 'description',
                               components=['comp1', 'comp2'],
                               gpg_check=False, strict=False, simple=True,
                               incoming_wait_timeout=10)

    d = repo_manager.db.cacus.distros.find_one({'distro': 'testdistro'})
    c = [x['component'] for x in repo_manager.db.cacus.components.find(
        {'distro': 'testdistro'})]
    assert d['distro'] == 'testdistro'
    assert d['description'] == 'description'
    assert d['simple'] == True
    assert 'comp1' in c
    assert 'comp2' in c
    repo_manager.create_distro('testdistro', 'description',
                               components=['comp1'],
                               gpg_check=True, strict=True, simple=False,
                               incoming_wait_timeout=10)
    d = repo_manager.db.cacus.distros.find_one({'distro': 'testdistro'})
    c = [x['component'] for x in repo_manager.db.cacus.components.find(
        {'distro': 'testdistro'})]
    assert d['simple'] == False
    assert d['gpg_check'] == True
    assert 'comp1' in c
    assert 'comp2' not in c


def test_upload_and_retention_policy(distro, repo_manager, package):
    comp = distro['components'][0]
    debs = []
    uploaded = []
    for x in range(1, 4):
        # create versions 0.1, 0.2 and 0.3
        debs.append(package.get('0.{}'.format(x)))

    for deb in debs:
        # upload next version
        result = repo_manager.upload_package(distro['distro'], comp, [deb['debfile']], changes=None)
        uploaded.append(result)
        for pkg in result:
            # check if pkg uploaded successfully
            d = repo_manager.db.packages[distro['distro']].find_one({'Package': pkg['Package'], 'Version': pkg['Version']})
            assert d is not None
            assert os.path.isfile(os.path.join(repo_manager.config['storage']['path'], d['storage_key']))
            assert package_is_in_repo(repo_manager, pkg, distro['distro'], comp)

    # check if ver 0.1 was deleted from distro due to retention policy
    deleted = uploaded[0][0]

    assert not package_is_in_repo(repo_manager, deleted, distro['distro'], comp)
    assert not os.path.isfile(os.path.join(repo_manager.config['storage']['path'], deleted['storage_key']))


def test_copy_remove_package(distro, repo_manager, deb_pkg):
    src = distro['components'][0]
    dst = distro['components'][1]
    deb = repo_manager.upload_package(distro['distro'], src, [deb_pkg['debfile']], None)[0]
    repo_manager.copy_package(deb['Package'], deb['Version'], deb['Architecture'], distro['distro'], dst)
    assert package_is_in_repo(repo_manager, deb, distro['distro'], dst)
    repo_manager.remove_package(deb['Package'], deb['Version'], deb['Architecture'], distro['distro'], dst)
    assert not package_is_in_repo(repo_manager, deb, distro['distro'], dst)

def test_purge_package(distro, repo_manager, deb_pkg):
    comp = distro['components'][0]
    deb = repo_manager.upload_package(distro['distro'], comp, [deb_pkg['debfile']], None)[0]
    assert package_is_in_repo(repo_manager, deb, distro['distro'], comp)
    repo_manager.purge_package(pkg=deb['Package'], ver=deb['Version'], distro=distro['distro'])
    assert not package_is_in_repo(repo_manager, deb, distro['distro'], comp)
    assert not os.path.isfile(os.path.join(repo_manager.config['storage']['path'], deb['storage_key']))


def test_create_update_snapshot(distro, repo_manager, package):

    # test indices
    repo_manager.create_snapshot(distro['distro'], 'testsnap')
    s = repo_manager.db.cacus.distros.find_one({'distro': repo_manager._get_snapshot_name(distro['distro'], 'testsnap')})
    assert s['snapshot'] == {'origin': distro['distro'], 'name': 'testsnap'}

    for comp in distro['components']:
        for arch in repo_manager.default_arches:
            orig_pkgs = repo_manager.db.cacus.repos.find_one({'distro': distro['distro'],
                                                              'component': comp, 'architecture': arch})['packages_file']
            sn_pkgs = repo_manager.db.cacus.repos.find_one({'distro': s['distro'],
                                                            'component': comp, 'architecture': arch})['packages_file']
            assert orig_pkgs == sn_pkgs
        orig_srcs = repo_manager.db.cacus.components.find_one({'distro': distro['distro'], 'component': comp})['sources_file']
        sn_srcs = repo_manager.db.cacus.components.find_one({'distro': s['distro'], 'component': comp})['sources_file']
        assert orig_srcs == sn_srcs

    # test packages
    deb1 = package.get('0.1')
    deb2 = package.get('0.2')
    comp = distro['components'][0]
    snap1 = repo_manager._get_snapshot_name(distro['distro'], 'snap1')
    snap2 = repo_manager._get_snapshot_name(distro['distro'], 'snap2')

    pkg1 = repo_manager.upload_package(distro['distro'], comp, [deb1['debfile']], changes=None)[0]
    repo_manager.create_snapshot(distro['distro'], 'snap1')
    assert package_is_in_repo(repo_manager, pkg1, snap1, comp, meta=False)

    repo_manager.create_snapshot(distro['distro'], 'snap2', from_snapshot='snap1')
    pkg2 = repo_manager.upload_package(distro['distro'], comp, [deb2['debfile']], changes=None)[0]
    repo_manager.create_snapshot(distro['distro'], 'snap1')
    assert package_is_in_repo(repo_manager, pkg2, snap1, comp, meta=False)
    assert not package_is_in_repo(repo_manager, pkg2, snap2, comp, meta=False)


def test_distro_quotas(distro_gen, repo_manager, package):

    distro = distro_gen.get(quota=4096)
    comp = distro['components'][0]
    deb1 = package.get('0.1', deadweight=2048)
    deb2 = package.get('0.2', deadweight=102400)

    pkg1 = repo_manager.upload_package(distro['distro'], comp, [deb1['debfile']], changes=None)[0]
    assert package_is_in_repo(repo_manager, pkg1, distro['distro'], comp)
    distro_settings = repo_manager.db.cacus.distros.find_one({'distro': distro['distro']})
    assert distro_settings['quota_used'] == deb1['debsize']

    with pytest.raises(repo_manager.common.FatalError):
        repo_manager.upload_package(distro['distro'], comp, [deb2['debfile']], changes=None)

    repo_manager.purge_package(pkg=pkg1['Package'], ver=pkg1['Version'], distro = distro['distro'])
    distro_settings = repo_manager.db.cacus.distros.find_one({'distro': distro['distro']})
    assert distro_settings['quota_used'] == 0


def test_delete_snapshot(distro, repo_manager):
    n = repo_manager._get_snapshot_name(distro['distro'], 'testsnap')
    repo_manager.create_snapshot(distro['distro'], 'testsnap')
    repo_manager.delete_snapshot(distro['distro'], 'testsnap')
    assert repo_manager.db.cacus.distros.find_one({'distro': n}) == None
    assert repo_manager.db.cacus.components.find_one({'distro': n}) == None
    assert repo_manager.db.cacus.repos.find_one({'distro': n}) == None


def test_index_used_by_snapshot(distro, repo_manager):
    for comp in distro['components']:
        for arch in repo_manager.default_arches:
            pkgs = repo_manager.db.cacus.repos.find_one({'distro': distro['distro'], 'component': comp, 'architecture': arch})['packages_file']
            assert repo_manager._index_used_by_snapshot(distro['distro'], packages=pkgs) == False
        srcs = repo_manager.db.cacus.components.find_one({'distro': distro['distro'], 'component': comp})['sources_file']
        assert repo_manager._index_used_by_snapshot(distro['distro'], sources=srcs) == False

    repo_manager.create_snapshot(distro['distro'], 'testsnap')
    for comp in distro['components']:
        for arch in repo_manager.default_arches:
            pkgs = repo_manager.db.cacus.repos.find_one({'distro': distro['distro'], 'component': comp, 'architecture': arch})['packages_file']
            assert repo_manager._index_used_by_snapshot(distro['distro'], packages=pkgs) == True
        srcs = repo_manager.db.cacus.components.find_one({'distro': distro['distro'], 'component': comp})['sources_file']
        assert repo_manager._index_used_by_snapshot(distro['distro'], sources=srcs) == True


def test_delete_unused_index(distro, repo_manager):
    pass
