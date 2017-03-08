#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Cacus distro importer.

Note that current implementation is _importer_, not mirrorer. Original distro is ripped to extract packages
and build _own_ repo indices (Packages, Release etc) under same component names - using only supported one.
That means that imported distro will be signed with cacus' key and will not preserve indices and features
that are not supported - like Translation, diffs, Contents etc. Though main behaviour (i.e. delivering packages)
remains pretty same.
"""

import os
import re
import logging
import binascii
import urllib

from debian import deb822

import repo_manage
import common

log = logging.getLogger('cacus.importer')


def _urljoin(*args):
    """ Sane joining of URL fragments
    urlparse.urljoin and urllib.basejoin are ridiculously inconsistent
    """
    args = [str(x) for x in args]
    url = args[0]
    for arg in args[1:]:
        if url.endswith('/'):
            url = url + arg
        else:
            url = url + '/' + arg
    return url


def import_distro(base_url, distro, components=None, arches=None):
    if not components:
        components = set()
    if not arches:
        arches = set(['amd64', 'i386', 'all'])

    release_url = _urljoin(base_url, 'dists', distro, 'Release')
    release_filename = common.download_file(release_url)
    packages = 0
    errors = []

    try:
        with open(release_filename) as f:
            release = deb822.Release(f)

        # since we don't know list of components in distro, lock distro on some fake component name
        with common.DistroLock(distro, ['__cacusimport']):
            # remove all packages imported - we will recreate distro collection from scratch
            # note that this does not affect APT API of distro - indices are still in place i
            # and will be updated once we finish import
            common.db_packages[distro].drop()
            common.create_packages_indexes([distro])

            # TODO add LZMA (.xz) support. Appears that debian.deb822 can handle .gz automagically, but barely supports .xz
            packages_re = re.compile("(?P<comp>[-_a-zA-Z0-9]+)\/(?P<arch>binary-(?:{}))\/Packages.(?P<ext>[g]z)".format("|".join(arches)))
            for entry in release['SHA256']:
                m = packages_re.match(entry['name'])
                if m:
                    components.add(m.group('comp'))
                    log.debug("Found %s/%s/%s", distro, m.group('comp'), m.group('arch'))
                    p, e = import_repo(base_url, distro, m.group('ext'), m.group('comp'), m.group('arch'), entry['sha256'])
                    packages += p
                    errors.extend(e)
            meta = {'distro': distro, 'imported': {'from': base_url},
                    'description': release.get('Description', 'N/A')}
            common.db_cacus.distros.find_one_and_update({'distro': distro},
                                                        {'$set': meta},
                                                        upsert=True)

        repo_manage.update_distro_metadata(distro, components, arches, force=True)
    finally:
        try:
            os.unlink(release_filename)
        except:
            pass
    log.info("Distribution %s: imported %s packages, %s import errors", distro, packages, len(errors))


def import_repo(base_url, distro, ext, comp, arch, sha256):
    packages_url = _urljoin(base_url, 'dists', distro, comp, arch, 'Packages.' + ext)
    packages_filename = common.download_file(packages_url, sha256=binascii.unhexlify(sha256))
    pkgs = 0
    errs = []
    try:
        with open(packages_filename) as f:
            for package in deb822.Packages.iter_paragraphs(f):
                try:
                    import_package(base_url, distro, comp, package)
                    pkgs += 1
                except Exception as e:
                    log.error("Error importing package %s_%s_%s: %s",
                              package['Package'], package['Version'], package['Architecture'], e)
                    errs.append(package)
    finally:
        try:
            os.unlink(packages_filename)
        except:
            pass
    return pkgs, errs


def import_package(base_url, distro, comp, meta):
    package = meta['Package']
    version = meta['Version']
    arch = meta['Architecture']
    log.debug("Importing package %s_%s_%s to %s/%s", package, version, meta['Architecture'], distro, comp)
    # TODO: full import option. For now we import only metadata and just proxying requests for actual files to original repo
    doc = {
        'Package': package,
        'Version': version,
        'Architecture': arch,
        # remove Filename from original meta - will be replaced by our own:
        'storage_key': _urljoin("extstorage/", urllib.quote_plus(base_url), urllib.quote_plus(meta.pop('Filename'))),
        'meta': meta
        # TODO import dsc and sources
    }
    common.db_packages[distro].find_one_and_update({'Package': package, 'Version': version, 'Architecture': arch},
                                                   {'$set': doc, '$addToSet': {'components': comp}},
                                                   upsert=True)
