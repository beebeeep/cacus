#!/usr/bin/env python
import pytest


@pytest.fixture
def distro(repo_manager):
    repo_manager.create_distro('testdistro', 'description',
                               components=['comp1', 'comp2'],
                               gpg_check=False, strict=False, simple=True,
                               incoming_wait_timeout=10)
    return {'distro': 'testdistro', 'components': ['comp1', 'comp2']}


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


def test_index_used_by_snapshot(distro, repo_manager):
    pkgs = repo_manager.db.cacus.repos.find_one({'distro': distro['distro']})['packages_file']
    assert repo_manager._index_used_by_snapshot(distro['distro'], packages=pkgs) == False
    repo_manager.create_snapshot(distro['distro'], 'testsnap')
    assert repo_manager._index_used_by_snapshot(distro['distro'], packages=pkgs) == True
    repo_manager.delete_snapshot(distro['distro'], 'testsnap')
    assert repo_manager._index_used_by_snapshot(distro['distro'], packages=pkgs) == False
