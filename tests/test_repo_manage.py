#!/usr/bin/env python

from fixtures.cacus import *


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


def test_upload_package(distro, repo_manager):
    pass


def test_create_snapshot(distro, repo_manager):
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
