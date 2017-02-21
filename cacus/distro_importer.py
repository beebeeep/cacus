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

        # TODO add LZMA (.xz) support. Appears that debian.deb822 can handle .gz automagically, but barely supports .xz
        packages_re = re.compile("(?P<comp>[-_a-zA-Z0-9]+)\/(?P<arch>binary-(?:{}))\/Packages.(?P<ext>[g]z)".format("|".join(arches)))
        for entry in release['SHA256']:
            m = packages_re.match(entry['name'])
            if m:
                components.add(m.group('comp'))
                logging.debug("Found %s/%s/%s", distro, m.group('comp'), m.group('arch'))
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
    logging.info("Distribution %s: imported %s packages, %s import errors", distro, packages, len(errors))


def import_repo(base_url, distro, ext, comp, arch, sha256):
    packages_url = _urljoin(base_url, 'dists', distro, comp, arch, 'Packages.' + ext)
    packages_filename = common.download_file(packages_url, sha256=binascii.unhexlify(sha256))
    pkgs = 0
    errs = []
    # TODO: cleanup (?) previous distro collection in db_packages and create indexes there
    try:
        with open(packages_filename) as f:
            for package in deb822.Packages.iter_paragraphs(f):
                try:
                    import_package(base_url, distro, comp, package)
                    pkgs += 1
                except Exception as e:
                    logging.error("Error importing package %s_%s_s: %s",
                                  package['Package'], package['Version'], package['Architecture'], e)
                    errs.append(package)
    finally:
        try:
            os.unlink(packages_filename)
        except:
            pass
    return pkgs, errs


def import_package(base_url, distro, comp, package):
    package = package['Package']
    version = package['Version']
    logging.debug("Importing package %s_%s_%s to %s/%s", package, version, package['Architecture'], distro, comp)
    # TODO: full import option. For now we import only metadata and just proxying requests for actual files to original repo
    package['storage_key'] = _urljoin("extstorage/", urllib.quote_plus(base_url), urllib.quote_plus(package.pop('Filename')))
    doc = {
        'Package': package,
        'Version': version
        # TODO import dsc and sources
    }
    common.db_packages[distro].find_one_and_update({'Package': package, 'Version': version},
                                                   {'$set': doc, '$addToSet': {'components': comp}},
                                                   upsert=True)
