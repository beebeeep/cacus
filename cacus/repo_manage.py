#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import hashlib
import StringIO
from debian import debfile, deb822
from binascii import hexlify
from datetime import datetime
from bson import binary
from pymongo.collection import ReturnDocument

import common


class RepoManager(common.Cacus):

    def create_distro(self, distro, description, components,  simple, strict=None, quota=None,
                      gpg_check=None, incoming_wait_timeout=None, retention=None, gpg_key=None):
        if gpg_key and not self._check_key(gpg_key):
            raise common.CacusError("Cannot find key {} in keychain".format(gpg_key))
        old_distro = self.db.cacus.distros.find_one_and_update(
            {'distro': distro},
            {
                '$set': {
                    'gpg_check': gpg_check, 'strict': strict, 'simple': simple, 'retention': retention, 'quota': quota,
                    'description': description, 'incoming_wait_timeout': incoming_wait_timeout, 'gpg_key': gpg_key
                },
                '$inc': {
                    'quota_used': 0
                }
            },
            return_document=ReturnDocument.BEFORE,
            upsert=True)
        self.log.info("%s distro '%s', simple: %s, components: %s", "Updated" if old_distro else "Created", distro, simple, ', '.join(components))

        old_components = [x['component'] for x in self.db.cacus.components.find({'distro': distro}, {'component': 1})]

        for comp in components:
            self.db.cacus.components.find_one_and_update(
                {'distro': distro, 'component': comp},
                {'$set': {'distro': distro, 'component': comp}},
                upsert=True)

        to_delete = set(old_components) - set(components)
        if to_delete:
            with self.lock(distro, to_delete):
                for deleted in to_delete:
                    self._delete_component(distro, deleted)

        self.create_packages_indexes(distros=[distro])

        # even empty distro deserves to have proper Release file and Package&Sources indices
        try:
            with self.lock(distro):
                self.update_distro_metadata(distro)
        except common.DistroLockTimeout as e:
            raise common.TemporaryError(e.message)

        return old_distro

    def remove_distro(self, distro):
        with self.lock(distro):
            # Transactions? Bitch, please!
            self.log.info("Removing distro '%s'", distro)
            result = self.db.cacus.distros.delete_one({'distro': distro, 'snapshot': {'$exists': False}})
            if result.deleted_count < 1:
                self.log.warning("Distro %s not found", distro)
                raise common.NotFound("Distro not found")

            self.db.cacus.distros.delete_many({'snapshot.origin': distro})
            for component in self.db.cacus.components.find({'distro': distro}, {'sources_file': 1}):
                self._delete_unused_index(distro, sources=component.get('sources_file', None))
            self.db.cacus.components.delete_many({'distro': distro})

            for repo in self.db.cacus.repos.find({'distro': distro}, {'packages_file': 1}):
                self._delete_unused_index(distro, packages=repo.get('packages_file', None))
            self.db.cacus.repos.delete_many({'distro': distro})

            for file in self.db.packages[distro].find({}, {'storage_key': 1}):
                self.storage.delete(file['storage_key'])
            for file in self.db.sources[distro].find({}, {'storage_key': 1}):
                self.storage.delete(file['storage_key'])

        return "Distro '{}' was successfully removed".format(distro)

    def _index_used_by_snapshot(self, distro, sources=None, packages=None):
        if sources:
            collection = 'components'
            field = 'sources_file'
            value = sources
        elif packages:
            collection = 'repos'
            field = 'packages_file'
            value = packages
        else:
            return

        for snapshot in self.db.cacus[collection].find({'snapshot.origin': distro}, {field: 1}):
            if snapshot[field] == value:
                return True
        return False

    def _delete_unused_index(self, distro, sources=None, packages=None):
        if not self._index_used_by_snapshot(distro, sources=sources, packages=packages):
            key = sources or packages
            self.log.debug("Removing old index '%s'", key)
            try:
                self.storage.delete(key)
            except common.NotFound:
                self.log.warning("Cannot find old index '%s'", key)
            except common.FatalError:
                self.log.warning("Cannot delete old index '%s'", key)

    def _apply_retention_policy(self, distro, comp, sources, debs, skipUpdateMeta=False):
        """ Removes old packages according to distro's retention policy
        Note that package will be removed only from indices, and will stay in DB & storage,
        since it's pretty tricky to determine whether it's still used in some snapshot
        XXX: should be called under DistroLock
        TODO: full cleanup """
        settings = self.db.cacus.distros.find_one({'distro': distro})
        if not settings.get('retention', False):
            self.log.info("No retention policy defined for distro '{}'".format(distro))
            return
        else:
            keep = settings['retention']
        sources_to_delete = []
        debs_to_delete = []
        for source in (x for x in sources if x):
            all_sources = sorted(self.db.sources[distro].find({'Package': source['Package'], 'components': comp},
                                                              {'Package': 1, 'Version': 1, '_id': 1, 'components': 1}),
                                 key=lambda x: common.DebVersion(x['Version']))

            if len(all_sources) > keep:
                sources_to_delete.extend(all_sources[0:-keep])

        for deb in (x for x in debs if x):
            all_debs = sorted(self.db.packages[distro].find({'Package': deb['Package'], 'components': comp,
                                                             'source': {'$nin': [x['_id'] for x in sources_to_delete]}},
                                                            {'Package': 1, 'Version': 1, 'Architecture': 1, 'components': 1}),
                              key=lambda x: common.DebVersion(x['Version']))
            if len(all_debs) > keep:
                debs_to_delete.extend(all_debs[0:-keep])

        for source in sources_to_delete:
            self.log.warn("Removing %s_%s from %s/%s due to retention policy", source['Package'], source['Version'], distro, comp)
            self.remove_package(pkg=source['Package'], ver=source['Version'], distro=distro, comp=comp,
                                source_pkg=True, skipUpdateMeta=skipUpdateMeta, locked=True, purge=True)
        for deb in debs_to_delete:
            self.log.warn("Removing %s_%s_%s from %s/%s due to retention policy", deb['Package'], deb['Version'], deb['Architecture'], distro, comp)
            self.remove_package(pkg=deb['Package'], ver=deb['Version'], distro=distro, comp=comp,
                                source_pkg=False, skipUpdateMeta=skipUpdateMeta, locked=True, purge=True)

    def _process_deb_file(self, file):
        with open(file) as f:
            hashes = self.get_hashes(file=f)

        doc = {
            'size': os.stat(file).st_size,
            'sha512': binary.Binary(hashes['sha512'].digest()),
            'sha256': binary.Binary(hashes['sha256'].digest()),
            'sha1': binary.Binary(hashes['sha1'].digest()),
            'md5': binary.Binary(hashes['md5'].digest())
            }

        try:
            deb = debfile.DebFile(file)
        except debfile.DebError as e:
            self.log.critical("Cannot load debfile %s: %s", file, e)
            raise common.FatalError("Cannot load debfile {0}: {1}".format(file, e))
        doc.update(deb.debcontrol())

        return doc, hashes

    def _process_source_file(self, file):
        with open(file) as f:
            hashes = self.get_hashes(file=f)

        filename = os.path.basename(file)
        dsc = None

        doc = {
                'name': filename,
                'size': os.stat(file).st_size,
                'sha512': binary.Binary(hashes['sha512'].digest()),
                'sha256': binary.Binary(hashes['sha256'].digest()),
                'sha1': binary.Binary(hashes['sha1'].digest()),
                'md5': binary.Binary(hashes['md5'].digest())
                }
        if file.endswith('.dsc'):
            with open(file) as f:
                dsc = deb822.Dsc(f)
                dsc = dict((k, v) for k, v in dsc.items() if not k.startswith('Checksums-') and k != 'Files')

        return doc, dsc, hashes

    def _create_release(self, distro, settings=None, ts=None):

        self.log.info("Creating Release for distribution %s", distro)
        packages = list(self.db.cacus.repos.find({'distro': distro}))
        sources = list(self.db.cacus.components.find({'distro': distro}))
        if settings:
            distro_settings = settings
        else:
            distro_settings = self.db.cacus.distros.find_one({'distro': distro})
        now = ts if ts else datetime.utcnow()
        if 'snapshot' in distro_settings:
            origin = 'Snapshot "{}" of distro "{}"'.format(distro, distro_settings['snapshot']['origin'])
        else:
            origin = distro
        label = distro_settings.get('label', distro)
        suite = distro_settings.get('suite', distro).replace('/', '-')
        codename = distro_settings.get('codename', distro).replace('/', '-')

        # see https://wiki.debian.org/RepositoryFormat#Architectures -
        # 'all' arch goes with other arhes' indice and shall not be listed in Release
        arches = set(x['architecture'] for x in packages if x['architecture'] != 'all')

        release = u""
        release += u"Origin: {}\n".format(origin)
        release += u"Label: {}\n".format(label)
        release += u"Suite: {}\n".format(suite)
        release += u"Codename: {}\n".format(codename)
        release += u"Date: {}\n".format(now.strftime("%a, %d %b %Y %H:%M:%S +0000"))
        release += u"Architectures: {}\n".format(' '.join(arches))
        release += u"Components: {}\n".format(' '.join(x['component'] for x in sources))
        release += u"Description: {}\n".format(distro_settings.get('description', 'Do not forget the description'))

        release += u"MD5Sum:\n"
        release += "\n".join(
                u" {} {} {}/binary-{}/Packages".format(hexlify(file['md5']), file['size'], file['component'], file['architecture'])
                for file in packages) + u"\n"
        release += "\n".join(
                u" {} {} {}/source/Sources".format(hexlify(file['md5']), file['size'], file['component'])
                for file in sources)
        release += u"\nSHA1:\n"
        release += "\n".join(
                u" {} {} {}/binary-{}/Packages".format(hexlify(file['sha1']), file['size'], file['component'], file['architecture'])
                for file in packages) + u"\n"
        release += "\n".join(
                u" {} {} {}/source/Sources".format(hexlify(file['sha1']), file['size'], file['component'])
                for file in sources)
        release += u"\nSHA256:\n"
        release += "\n".join(
                u" {} {} {}/binary-{}/Packages".format(hexlify(file['sha256']), file['size'], file['component'], file['architecture'])
                for file in packages) + u"\n"
        release += "\n".join(
                u" {} {} {}/source/Sources".format(hexlify(file['sha256']), file['size'], file['component'])
                for file in sources)
        release += u"\n"

        release_gpg = self.gpg_sign(release.encode('utf-8'), distro_settings.get('gpg_key', None))

        return release, release_gpg

    def upload_package(self, distro, comp, files, changes, skipUpdateMeta=False):
        """ Uploads package from incoming dir to distro.

        Arguments:
            distro - distribution to upload packag
            comp - component within distribution
            changes - array of files belonging to package in scope:
                .deb for binary packages (at least one required)
                .dsc, .tar.[gx]z, .changes for sources (optional)
            skipUpdateMeta - whether to update distro metadata
        """

        distro_settings = self.db.cacus.distros.find_one({'distro': distro})
        distro_component = self.db.cacus.components.find_one({'distro': distro, 'component': comp})
        incoming_bytes = 0
        if not distro_settings:
            raise common.NotFound("Distribution '{}' was not found".format(distro))
        if not distro_component:
            raise common.NotFound("Component '{}' of distribution '{}' was not found".format(comp, distro))

        if distro_settings['strict'] and not any(x.endswith('.changes') for x in files):
            raise common.FatalError("Strict mode enabled for '{}', will not upload package without signed .changes file".format(distro))
        if distro_settings['quota'] is not None:
            incoming_bytes = sum(os.stat(file).st_size for file in files)
            if incoming_bytes > distro_settings['quota'] - distro_settings['quota_used']:
                raise common.FatalError("Quota exceeded for distro '{distro}': you are using {quota_used} bytes of {quota}".format(**distro_settings))

        src_pkg = {}
        debs = []
        affected_arches = set()
        for file in files:
            if file.endswith('.deb') or file.endswith('.udeb'):
                deb, hashes = self._process_deb_file(file)
                ext = 'deb' if file.endswith('.deb') else 'udeb'
                base_key = "{}/pool/{}_{}_{}.{}".format(distro, deb['Package'], deb['Version'], deb['Architecture'], ext)
                self.log.info("Uploading %s as %s to distro '%s' component '%s'", os.path.basename(file), base_key, distro, comp)
                storage_key = self.storage.put(base_key, filename=file, sha256=hashes['sha256'])

                # All debian packages are going to "packages" db, prepare documents to insert
                debs.append({
                    'Package': deb['Package'],
                    'Version': deb['Version'],
                    'Architecture': deb['Architecture'],
                    'storage_key': storage_key,
                    'meta': deb
                })

            else:
                # All other files are stored in "sources" db, fill the "files" array and prepare source document
                if 'files' not in src_pkg:
                    src_pkg['files'] = []
                source, dsc, hashes = self._process_source_file(file)
                filename = os.path.basename(file)
                base_key = "{0}/pool/{1}".format(distro, filename)
                self.log.info("Uploading %s to distro '%s' component '%s'", base_key, distro, comp)
                storage_key = self.storage.put(base_key, filename=file, sha256=hashes['sha256'])
                source['storage_key'] = storage_key
                src_pkg['files'].append(source)
                if dsc:
                    src_pkg['dsc'] = dsc

            if changes:
                src_pkg['Package'] = changes['Source']
                src_pkg['Version'] = changes['Version']

        affected_arches.update(x['Architecture'] for x in debs)

        if affected_arches:
            # critical section. updating meta DB
            try:
                # block whole distro since we will possibly update not only 'comp' component
                with self.lock(distro):
                    components_to_update = set([comp])
                    if src_pkg:
                        src = self.db.sources[distro].find_one_and_update(
                                {'Package': src_pkg['Package'], 'Version': src_pkg['Version']},
                                {'$set': src_pkg, '$addToSet': {'components': comp}},
                                return_document=ReturnDocument.AFTER,
                                upsert=True)
                    for deb in debs:
                        if src_pkg:
                            # refer to source package, if any
                            deb['source'] = src['_id']
                        result = self.db.packages[distro].find_one_and_update(
                            {'Package': deb['Package'], 'Version': deb['Version'], 'Architecture': deb['Architecture']},
                            {'$set': deb, '$addToSet': {'components': comp}},
                            return_document=ReturnDocument.AFTER,
                            upsert=True)
                        components_to_update.update(result['components'])

                    if distro_settings['quota'] is not None:
                        distro_settings = self.db.cacus.distros.find_one_and_update(
                            {'distro': distro},
                            {'$inc': {'quota_used': incoming_bytes}},
                            return_document=ReturnDocument.AFTER,
                            upsert=False)
                        self.log.info("Updated quotas for distro %s: used %s out of %s", distro, distro_settings['quota_used'], distro_settings['quota'])

                    self._apply_retention_policy(distro, comp, sources=[src_pkg], debs=debs, skipUpdateMeta=skipUpdateMeta)

                    if not skipUpdateMeta:
                        if 'all' in affected_arches:
                            affected_arches = None      # update all arches in case of "all" arch package
                        self.update_distro_metadata(distro, components_to_update, affected_arches)
            except common.DistroLockTimeout as e:
                self.log.error("Error updating distro: %s", e)
                raise common.TemporaryError("Cannot lock distro: {0}".format(e))
        else:
            self.log.info("No changes made in '%s/%s', skipping metadata update", distro, comp)
        return debs

    def _update_packages(self, distro, comp, arch, now):
        """ Updates Packages index
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        packages = self._generate_packages_file(distro, comp, arch)
        size = packages.tell()
        md5.update(packages.getvalue())
        sha1.update(packages.getvalue())
        sha256.update(packages.getvalue())

        # Packages may be used by distro snapshots, so we keep all versions under unique filename
        base_key = "{}/{}/{}/Packages_{}".format(distro, comp, arch, sha256.hexdigest())
        storage_key = self.storage.put(base_key, file=packages, sha256=sha256)

        old_repo = self.db.cacus.repos.find_one_and_update(
                {'distro': distro, 'component': comp, 'architecture': arch},
                {'$set': {
                    'distro': distro,
                    'component': comp,
                    'architecture': arch,
                    'md5': binary.Binary(md5.digest()),
                    'sha1': binary.Binary(sha1.digest()),
                    'sha256': binary.Binary(sha256.digest()),
                    'size': size,
                    'packages_file': storage_key,
                    'lastupdated': now
                    }},
                return_document=ReturnDocument.BEFORE,
                upsert=True)

        # check whether previous index is not used by some snapshot and remove it from storage
        if old_repo and 'packages_file' in old_repo and old_repo['packages_file'] != storage_key:
            self._delete_unused_index(distro, packages=old_repo['packages_file'])

    def _update_sources(self, distro, comp, now):
        """ Updates Sources index
        """

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sources = self._generate_sources_file(distro, comp)
        size = sources.tell()
        md5.update(sources.getvalue())
        sha1.update(sources.getvalue())
        sha256.update(sources.getvalue())

        base_key = "{}/{}/source/Sources_{}".format(distro, comp, sha256.hexdigest())
        storage_key = self.storage.put(base_key, file=sources, sha256=sha256)

        old_component = self.db.cacus.components.find_one_and_update(
                {'distro': distro, 'component': comp},
                {'$set': {
                    'distro': distro,
                    'component': comp,
                    'md5': binary.Binary(md5.digest()),
                    'sha1': binary.Binary(sha1.digest()),
                    'sha256': binary.Binary(sha256.digest()),
                    'size': size,
                    'sources_file': storage_key,
                    'lastupdated': now
                    }},
                return_document=ReturnDocument.BEFORE,
                upsert=True)

        # check whether previous index is not used by some snapshot and remove it from storage
        if old_component and 'sources_file' in old_component and old_component['sources_file'] != storage_key:
            self._delete_unused_index(distro, sources=old_component['sources_file'])

    def update_distro_metadata(self, distro, comps=None, arches=None):
        """ Updates distro's indices (Packages,Sources and Release file)
        Note that components should be already locked
        """
        now = datetime.utcnow()
        if not comps:
            comps = [x['component'] for x in self.db.cacus.components.find({'distro': distro})]
        if not arches:
            arches = set(x['architecture'] for x in self.db.cacus.repos.find({'distro': distro}, {'architecture': 1}))
            arches.update(self.default_arches)

        if not comps or not arches:
            raise common.NotFound("Distro {} is not found or empty".format(distro))

        self.log.info("Updating metadata for distro '%s', components: %s, arches: %s", distro, ', '.join(comps), ', '.join(arches))

        # for all components, updates Packages (for each architecture) and Sources index files
        for comp in comps:
            self._update_sources(distro, comp, now)
            for arch in arches:
                self._update_packages(distro, comp, arch, now)

        # now create Release file
        release, release_gpg = self._create_release(distro, ts=now)

        # Release file and its digest is small enough to put directly into metabase
        self.db.cacus.distros.find_one_and_update(
                {'distro': distro},
                {'$set': {
                    'distro': distro,
                    'lastupdated': now,
                    'release_file': release,
                    'release_gpg': release_gpg
                    }},
                upsert=True)

    def _generate_sources_file(self, distro, comp):
        data = StringIO.StringIO()
        component = self.db.sources[distro].find(
            {'components': comp, 'dsc': {'$exists': True}},
            {'dsc': 1, 'files': 1})
        for pkg in component:
            for k, v in pkg['dsc'].iteritems():
                data.write("{0}: {1}\n".format(k.capitalize(), v))
            data.write("Directory: {}\n".format(self.config['repo_daemon']['storage_subdir']))
            # c-c-c-c-combo!
            files = [x for x in pkg['files'] if reduce(lambda a, n: a or x['name'].endswith(n), ['tar.gz', 'tar.xz', '.dsc'], False)]

            def gen_para(algo, files):
                for f in files:
                    data.write(" {0} {1} {2}\n".format(hexlify(f[algo]), f['size'], f['storage_key']))

            data.write("Files: \n")
            gen_para('md5', files)
            data.write("Checksums-Sha1: \n")
            gen_para('sha1', files)
            data.write("Checksums-Sha256: \n")
            gen_para('sha256', files)

            data.write("\n")
        # to prevent generating of empty file
        data.write("\n")
        return data

    def _generate_packages_file(self, distro, comp, arch):
        self.log.debug("Generating Packages for %s/%s/%s", distro, comp, arch)
        data = StringIO.StringIO()
        # see https://wiki.debian.org/RepositoryFormat#Architectures - 'all' arch goes with other arhes' Packages index
        repo = self.db.packages[distro].find({'components': comp, 'Architecture': {'$in': [arch, 'all']}})
        for pkg in repo:
            path = pkg['storage_key']
            if not path.startswith('extstorage'):
                path = os.path.join(self.config['repo_daemon']['storage_subdir'], path)
            data.write("Filename: {0}\n".format(path))

            for k, v in pkg['meta'].iteritems():
                if k == 'md5':
                    string = "MD5sum: {0}\n".format(hexlify(v))
                elif k == 'sha1':
                    string = "SHA1: {0}\n".format(hexlify(v))
                elif k == 'sha256':
                    string = "SHA256: {0}\n".format(hexlify(v))
                elif k == 'sha512':
                    string = "SHA512: {0}\n".format(hexlify(v))
                elif not v:
                    continue
                else:
                    string = "{0}: {1}\n".format(k.capitalize().encode('utf-8'), unicode(v).encode('utf-8'))
                data.write(string)
            data.write("\n")
        # to prevent generating of empty file
        data.write("\n")
        return data

    def remove_package(self, pkg=None,  ver=None, arch=None, distro=None, comp=None, source_pkg=False, purge=False, skipUpdateMeta=False, locked=False):
        """ Removes package from specified distro/component """

        self.log.info("Removing %s_%s from %s/%s", pkg, ver, distro, comp)

        affected_arches = []
        try:
            with self.lock(distro, [comp], already_locked=locked):
                if source_pkg:
                    # remove source package (if any) and all binary packages within it from component
                    result = self.db.sources[distro].find_one_and_update(
                        {'Package': pkg, 'Version': ver, 'components': comp},
                        {'$pullAll': {'components': [comp]}},
                        upsert=False,
                        return_document=ReturnDocument.AFTER
                    )
                    if result:
                        binaries = self.db.packages[distro].update_many(
                            {'source': result['_id']},
                            {'$pullAll': {'components': [comp]}})
                        if binaries.modified_count:
                            affected_arches = [x['Architecture'] for x in
                                               self.db.packages[distro].find({'source': result['_id']}, {'Architecture': 1})]
                else:
                    if not arch:
                        # dummy selector for all arches
                        arch = {'$exists': True}
                    result = self.db.packages[distro].find_one_and_update(
                        {'Package': pkg, 'Version': ver, 'Architecture': arch, 'components': comp},
                        {'$pullAll': {'components': [comp]}},
                        upsert=False,
                        return_document=ReturnDocument.AFTER
                    )
                    affected_arches = [result['Architecture']] if result else []
                if not result:
                    msg = "Cannot find package '{}_{}' in '{}/{}'".format(pkg, ver, distro, comp)
                    self.log.error(msg)
                    raise common.NotFound(msg)

                msg = "Package '{}_{}' was removed from '{}/{}'".format(pkg, ver, distro, comp)
                self.log.info(msg)

                if purge and result['components'] == []:
                    self.purge_package(pkg=result['Package'], ver=result['Version'], distro=distro, skipUpdateMeta=True, locked=True)

                if not skipUpdateMeta:
                    if 'all' in affected_arches:
                        affected_arches = None      # update all arches in case we have 'all' arch in scope
                    self.log.info("Updating '%s' distro metadata for component %s, arch: %s", distro, comp, affected_arches)
                    self.update_distro_metadata(distro, [comp], affected_arches)
                return msg
        except common.DistroLockTimeout as e:
            raise common.TemporaryError(e.message)

    def purge_package(self, pkg=None,  ver=None, arch=None, distro=None, skipUpdateMeta=False, locked=False):
        """ Removes package from all components and wipes it (all sources, debs etc) from storage
        XXX: note that purging package may break existing distro snapshots!
        """

        self.log.info("Purging %s_%s from distro %s", pkg, ver, distro)

        affected_arches = set()
        affected_comps = set()
        try:
            with self.lock(distro, comps=None, already_locked=locked):
                freed = 0
                result = self.db.sources[distro].find_one_and_delete({'Package': pkg, 'Version': ver})
                if result:
                    # found source package matching query, remove this package, its non-deb files and all debs it consists of
                    for f in result['files']:
                        self.storage.delete(f['storage_key'])
                        freed += f['size']
                    source = result['_id']
                    while True:
                        result = self.db.packages[distro].find_one_and_delete({'source': source})
                        if result:
                            affected_arches.add(result['Architecture'])
                            affected_comps.update(result['components'])
                            self.storage.delete(result['storage_key'])
                            freed += result['meta']['size']
                        else:
                            break
                else:
                    # try to find in packages db
                    selector = {'Package': pkg, 'Version': ver}
                    if arch:
                        selector['Architecture'] = arch

                    result = self.db.packages[distro].find_one_and_delete(selector)
                    if result:
                        affected_arches.update(result['Architecture'])
                        affected_comps.update(result['components'])
                        self.storage.delete(result['storage_key'])
                        freed += result['meta']['size']
                    else:
                        raise common.NotFound("Package not found")

                self.db.cacus.distros.update_one({'distro': distro},  {'$inc': {'quota_used': -freed}})
                self.log.info("Purged %s_%s from distro %s, %s bytes freed", pkg, ver, distro, freed)
                if not skipUpdateMeta:
                    if 'all' in affected_arches:
                        affected_arches = None      # update all arches in case we have 'all' arch in scope
                    self.update_distro_metadata(distro, affected_comps, affected_arches)
        except common.DistroLockTimeout as e:
            raise common.TemporaryError(e.message)

        return "Package {}_{} was removed from {}".format(pkg, ver, distro)

    def copy_package(self, pkg=None, ver=None, arch=None, distro=None, src=None, dst=None, source_pkg=False, skipUpdateMeta=False):
        affected_arches = []
        if not self.db.cacus.components.find_one({'distro': distro, 'component': dst}, {'_id': 1}):
            raise common.NotFound("Component '{}' was not found in distro '{}'".format(dst, distro))

        try:
            with self.lock(distro, [src, dst]):
                if source_pkg:
                    # move source package (if any) and all binary packages within it
                    result = self.db.sources[distro].find_one_and_update(
                        {'Package': pkg, 'Version': ver, 'components': src},
                        {'$addToSet': {'components': dst}},
                        projection={'components': 1},
                        upsert=False,
                        return_document=ReturnDocument.BEFORE
                    )
                    if result:
                        binaries = self.db.packages[distro].update_many(
                            {'source': result['_id']},
                            {'$addToSet': {'components': dst}})
                        if binaries.modified_count:
                            affected_arches = [x['Architecture'] for x in
                                               self.db.packages[distro].find({'source': result['_id']}, {'Architecture': 1})]

                else:
                    if not arch:
                        # dummy selector for all arches
                        arch = {'$exists': True}
                    # touch only one specified package
                    result = self.db.packages[distro].find_one_and_update(
                        {'Package': pkg, 'Version': ver, 'Architecture': arch, 'components': src},
                        {'$addToSet': {'components': dst}},
                        projection={'components': 1, 'Architecture': 1, 'component': 1},
                        upsert=False,
                        return_document=ReturnDocument.BEFORE
                    )
                    affected_arches = [result['Architecture']] if result else []
                if not result:
                    msg = "Cannot find package '{}_{}' in '{}/{}'".format(pkg, ver, distro, src)
                    self.log.error(msg)
                    raise common.NotFound(msg)
                elif dst in result['components']:
                    msg = "Package '{}_{}' is already in '{}/{}'".format(pkg, ver, distro, dst)
                    self.log.warning(msg)
                    return msg

                msg = "Package '{}_{}' was copied in distro '{}' from '{}' to '{}'".format(pkg, ver, distro, src, dst)
                self.log.info(msg)

                if not skipUpdateMeta:
                    if 'all' in affected_arches:
                        affected_arches = None      # update all arches in case we have 'all' arch in scope
                    self.log.info("Updating '%s' distro metadata for components %s and %s, arches: %s", distro, src, dst, affected_arches)
                    self.update_distro_metadata(distro, [src, dst], affected_arches)
                return msg
        except common.DistroLockTimeout as e:
            raise common.TemporaryError(e.message)

    def _delete_component(self, distro, comp):
        """ Delete component
        Remove mentions of component in packages in sources, clean up indices.
        NB it's internal function - for user all component management is performed via distro settings
        """

        self.log.info("Deleting component '%s' from distro '%s'", comp, distro)

        self.db.sources['distro'].update_many(
            {'components': comp},
            {'$pullAll': {'components': [comp]}})
        self.db.packages['distro'].update_many(
            {'components': comp},
            {'$pullAll': {'components': [comp]}})

        # XXX: Packages and Sources indices are not being cleaned up here, source of garbage in storage:
        self.db.cacus.repos.remove({'distro': distro, 'component': comp})
        self.db.cacus.components.remove({'distro': distro, 'component': comp})

    @staticmethod
    def _get_snapshot_name(distro, name):
        # TODO: snapshot name sanity check
        return "{}@{}".format(distro, name)

    def delete_snapshot(self, distro, name):
        snapshot_name = self._get_snapshot_name(distro, name)
        if not self.db.cacus.distros.find_one({'snapshot': {'name': name, 'origin': distro}}):
            raise common.NotFound("Snapshot '{}' does not exist".format(name))

        try:
            with self.lock(distro):
                # XXX: Packages and Sources indices are not being cleaned up here, source of garbage in storage:
                self.db.cacus.components.remove({'snapshot': {'origin': distro, 'name': name}})
                self.db.cacus.repos.remove({'snapshot': {'origin': distro, 'name': name}})
                self.db.cacus.distros.remove({'snapshot': {'origin': distro, 'name': name}})
        except common.DistroLockTimeout:
            raise common.TemporaryError("Cannot lock distro '{}'".format(distro))

        return "Snapshot '{}' was deleted".format(snapshot_name)

    def create_snapshot(self, distro, name, from_snapshot=None, allow_update=True):
        """ Creates distribution snapshot distro -> distro/name
        Important note about implementation: as far as distro snapshot meant to be lightweight and
        cheap to create, snapshotting is implemented by just copying existing APT indices (Packages, Sources etc) -
        i.e. snapshot will be read-only by design (which is good) and packages database won't store
        any information about whether current package in included in some snapshot or not (which is bad because
        we won't be able to determine whether this package is orphaned and can be deleted from storage).
        """

        snapshot_name = self._get_snapshot_name(distro, name)
        snapshot_info = {'origin': distro, 'name': name}

        if from_snapshot:
            distro = self._get_snapshot_name(distro, from_snapshot)

        existing = self.db.cacus.distros.find_one({'distro': snapshot_name})
        if existing:
            if allow_update:
                self.delete_snapshot(distro, name)
                action = "updated"
            else:
                raise common.Conflict("Snapshot '{}' already exists".format(name))
        else:
            action = "created"
        origin = self.db.cacus.distros.find_one({'distro': distro})
        if not origin:
            raise common.NotFound("Distro or snapshot '{}' not found".format(distro))

        try:
            with self.lock(distro):
                for component in self.db.cacus.components.find({'distro': distro}):
                    component['distro'] = snapshot_name
                    component['snapshot'] = snapshot_info
                    component.pop('_id')
                    self.db.cacus.components.insert(component)
                    for repo in self.db.cacus.repos.find({'distro': distro, 'component': component['component']}):
                        repo['distro'] = snapshot_name
                        repo['snapshot'] = snapshot_info
                        repo.pop('_id')
                        self.db.cacus.repos.insert(repo)

                now = datetime.utcnow()
                snapshot = origin
                snapshot.pop('_id')
                snapshot['snapshot'] = snapshot_info
                release, release_gpg = self._create_release(snapshot_name, settings=snapshot, ts=now)
                snapshot.update({
                    'distro': snapshot_name,
                    'lastupdated': now,
                    'release_file': release,
                    'release_gpg': release_gpg
                    })

                self.db.cacus.distros.insert(snapshot)
        except common.DistroLockTimeout:
            raise common.TemporaryError("Cannot lock distro '{}'".format(distro))

        return "Snapshot '{}' was successfully {}".format(snapshot_name, action)
