#!/usr/bin/env python


def test_snapshot_name(cacus):
    assert cacus.repo_manage._get_snapshot_name('distro', 'name') == 'distro@name'


def test_create_repo(cacus):
    cacus.repo_manage.create_distro('testdistro', 'description',
                                    components=['comp1', 'comp2'],
                                    strict=False, gpg_check=False,
                                    incoming_wait_timeout=10)

    d = cacus.common.db_cacus.distros.find_one({'distro': 'testdistro'})
    c = [x['component'] for x in cacus.common.db_cacus.components.find(
        {'distro': 'testdistro'})]
    assert d['distro'] == 'testdistro'
    assert d['description'] == 'description'
    assert 'comp1' in c
    assert 'comp2' in c
