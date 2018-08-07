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
import binascii
import urllib
import gzip
import queue
import threading

from debian import deb822

from . import repo_manage


class DistroImporter(repo_manage.RepoManager):

    @staticmethod
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

    def __init__(threads, *args, **kwargs):
        self._download_queue = queue.Queue()
        self._downloaders = []
        for i in range(threads):
            t = threading.Thread(target=self._downloader_task)
            t.start()
            self._downloaders.append(t)

        super(DistroImporter, self).__init__(*args, **kwargs)

    def import_distro(self, base_url, distro, components=None, arches=None, download_packages=False):
        if not components:
            components = set()
        if not arches:
            arches = set(['amd64', 'i386', 'all'])

        release_url = self._urljoin(base_url, 'dists', distro, 'Release')
        release_filename = self.download_file(release_url)
        packages = 0
        errors = []

        try:
            with open(release_filename) as f:
                release = deb822.Release(f)

            # since we don't know list of components in distro, lock distro on some fake component name
            with self.lock(distro, ['__cacusimport']):
                # remove all packages imported - we will recreate distro collection from scratch
                # note that this does not affect APT API of distro - indices are still in place i
                # and will be updated once we finish import
                self.db.packages[distro].drop()
                self.create_packages_indexes([distro])

                # TODO add LZMA (.xz) support. Appears that debian.deb822 can handle .gz automagically, but barely supports .xz
                packages_re = re.compile("(?P<comp>[-_a-zA-Z0-9]+)\/(?P<arch>binary-(?:{}))\/Packages.(?P<ext>[g]z)".format("|".join(arches)))
                for entry in release['SHA256']:
                    m = packages_re.match(entry['name'])
                    if m:
                        components.add(m.group('comp'))
                        self.log.debug("Found %s/%s/%s", distro, m.group('comp'), m.group('arch'))
                        p, e = self.import_repo(base_url, distro, m.group('ext'), m.group('comp'), m.group('arch'), entry['sha256'], download_packages)
                        packages += p
                        errors.extend(e)
                meta = {'distro': distro, 'imported': {'from': base_url},
                        'description': release.get('Description', 'N/A')}
                self.db.cacus.distros.find_one_and_update({'distro': distro},
                                                          {'$set': meta},
                                                          upsert=True)

            self.update_distro_metadata(distro, components, arches)
        finally:
            try:
                os.unlink(release_filename)
            except:
                pass
        self.log.info("Distribution %s: imported %s packages, %s import errors", distro, packages, len(errors))

    def import_repo(self, base_url, distro, ext, comp, arch, sha256, download_packages=False):
        packages_url = self._urljoin(base_url, 'dists', distro, comp, arch, 'Packages.' + ext)
        packages_filename = self.download_file(packages_url, sha256=binascii.unhexlify(sha256))
        pkgs = 0
        errs = []
        try:
            # TODO: LZMA support
            with gzip.open(packages_filename) as f:
                for package in deb822.Packages.iter_paragraphs(f):
                    try:
                        self.import_package(base_url, distro, comp, package, download_packages)
                        pkgs += 1
                    except Exception as e:
                        self.log.error("Error importing package %s_%s_%s: %s",
                                       package['Package'], package['Version'], package['Architecture'], e)
                        errs.append(package)
        finally:
            try:
                os.unlink(packages_filename)
            except:
                pass
        return pkgs, errs

    def import_package(self, base_url, distro, comp, meta, download=False):
        package = meta['Package']
        version = meta['Version']
        arch = meta['Architecture']
        self.log.debug("Importing package %s_%s_%s to %s/%s", package, version, meta['Architecture'], distro, comp)
        if download:
            filename = meta.pop('Filename')
            pkg_filename = self.download_file("{}/{}".format(base_url, filename), sha256=binascii.unhexlify(meta['sha256']))
            base_key = "{0}/pool/{1}".format(distro, filename)
            try:
                storage_key = self.storage.put(base_key, filename=pkg_filename, sha256=meta['sha256'])
            finally:
                try:
                    os.unlink(pkg_filename)
                except:
                    pass
        else:
            storage_key = self._urljoin("extstorage/", urllib.parse.quote_plus(base_url), urllib.parse.quote_plus(meta.pop('Filename')))
        doc = {
            'Package': package,
            'Version': version,
            'Architecture': arch,
            # remove Filename from original meta - will be replaced by our own:
            'storage_key': storage_key,
            'meta': meta
            # TODO import dsc and sources
        }
        self.db.packages[distro].find_one_and_update({'Package': package, 'Version': version, 'Architecture': arch},
                                                     {'$set': doc, '$addToSet': {'components': comp}},
                                                     upsert=True)

    def _downloader_task(self):
        while True:
            url = self._download_queue.get()
