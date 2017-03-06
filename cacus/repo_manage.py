#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import stat
import hashlib
import logging
from debian import debfile, deb822
from binascii import hexlify
from datetime import datetime
from bson import binary
from pymongo.collection import ReturnDocument

import common
import plugin

log = logging.getLogger('cacus.repo_manage')


class UploadPackageError(Exception):
    pass


class UpdateRepoMetadataError(Exception):
    pass


def _process_deb_file(file):
    with open(file) as f:
        hashes = common.get_hashes(file=f)

    doc = {
        'size': os.stat(file)[stat.ST_SIZE],
        'sha512': binary.Binary(hashes['sha512']),
        'sha256': binary.Binary(hashes['sha256']),
        'sha1': binary.Binary(hashes['sha1']),
        'md5': binary.Binary(hashes['md5'])
        }

    try:
        deb = debfile.DebFile(file)
    except debfile.DebError as e:
        log.critical("Cannot load debfile %s: %s", file, e)
        raise common.FatalError("Cannot load debfile {0}: {1}".format(file, e))
    doc.update(deb.debcontrol())

    return doc


def _process_source_file(file):
    with open(file) as f:
        hashes = common.get_hashes(file=f)

    filename = os.path.basename(file)
    dsc = None

    doc = {
            'name': filename,
            'size': os.stat(file)[stat.ST_SIZE],
            'sha512': binary.Binary(hashes['sha512']),
            'sha256': binary.Binary(hashes['sha256']),
            'sha1': binary.Binary(hashes['sha1']),
            'md5': binary.Binary(hashes['md5'])
            }
    if file.endswith('.dsc'):
        with open(file) as f:
            dsc = deb822.Dsc(f)
            dsc = dict((k, v) for k, v in dsc.items() if not k.startswith('Checksums-') and k != 'Files')

    return doc, dsc


def _create_release(distro, settings=None, ts=None):

    log.info("Creating Release for distribution %s", distro)
    packages = list(common.db_cacus.repos.find({'distro': distro}))
    sources = list(common.db_cacus.components.find({'distro': distro}))
    if settings:
        distro_settings = settings
    else:
        distro_settings = common.db_cacus.distros.find_one({'distro': distro})
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

    release_gpg = common.gpg_sign(release.encode('utf-8'))

    return release, release_gpg


def upload_package(distro, comp, files, changes, skipUpdateMeta=False, forceUpdateMeta=False):
    """ Uploads package from incoming dir to distro.

    Arguments:
        distro - distribution to upload packag
        comp - component within distribution
        changes - array of files belonging to package in scope:
            .deb for binary packages (at least one required)
            .dsc, .tar.[gx]z, .changes for sources (optional)
        skipUpdateMeta, forceUpdateMeta - whether to update distro metadata
    """

    src_pkg = {}
    debs = []
    affected_arches = set()
    for file in files:
        if file.endswith('.deb') or file.endswith('.udeb'):
            deb = _process_deb_file(file)
            ext = 'deb' if file.endswith('.deb') else 'udeb'
            base_key = "{}/pool/{}_{}_{}.{}".format(distro, deb['Package'], deb['Version'], deb['Architecture'], ext)
            log.info("Uploading %s as %s to distro '%s' component '%s'", os.path.basename(file), base_key, distro, comp)
            storage_key = plugin.get_plugin('storage').put(base_key, filename=file)

            # All debian packages are going to "packages" db, prepare documents to insert
            debs.append({
                'Package': deb['Package'],
                'Version': deb['Version'],
                'Architecture': deb['Architecture'],
                'storage_key': storage_key,
                'meta': deb
            })

        else:
            filename = os.path.basename(file)
            base_key = "{0}/pool/{1}".format(distro, filename)
            log.info("Uploading %s to distro '%s' component '%s'", base_key, distro, comp)
            storage_key = plugin.get_plugin('storage').put(base_key, filename=file)

            # All other files are stored in "sources" db, fill the "files" array and prepare source document
            if 'files' not in src_pkg:
                src_pkg['files'] = []
            source, dsc = _process_source_file(file)
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
            with common.DistroLock(distro, [comp]):
                if src_pkg:
                    src = common.db_sources[distro].find_one_and_update(
                            {'Package': src_pkg['Package'], 'Version': src_pkg['Version']},
                            {'$set': src_pkg, '$addToSet': {'components': comp}},
                            return_document=ReturnDocument.AFTER,
                            upsert=True)

                for deb in debs:
                    if src_pkg:
                        # refer to source package, if any
                        deb['source'] = src['_id']
                    common.db_packages[distro].find_one_and_update(
                        {'Package': deb['Package'], 'Version': deb['Version'], 'Architecture': deb['Architecture']},
                        {'$set': deb, '$addToSet': {'components': comp}},
                        upsert=True)

                if not skipUpdateMeta:
                    if len(affected_arches) == 1 and 'all' in affected_arches:
                        affected_arches = None      # update all arches in case of "all" arch package
                    update_distro_metadata(distro, [comp], affected_arches, force=forceUpdateMeta)
        except common.DistroLockTimeout as e:
            log.error("Error updating distro: %s", e)
            raise common.TemporaryError("Cannot lock distro: {0}".format(e))
    else:
        log.info("No changes made on distro %s/%s, skipping metadata update", distro, comp)
    return debs


def _update_packages(distro, comp, arch, now, force=False):
    """ Updates Packages index
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    packages = _generate_packages_file(distro, comp, arch)
    size = packages.tell()
    md5.update(packages.getvalue())
    sha1.update(packages.getvalue())
    sha256.update(packages.getvalue())

    old_repo = common.db_cacus.repos.find_one({'distro': distro, 'component': comp, 'architecture': arch}, {'packages_file': 1})
    if not force and old_repo and 'packages_file' in old_repo and md5.hexdigest() in old_repo['packages_file']:
        log.warn("Packages file for %s/%s/%s not changed, skipping update", distro, comp, arch)
        return

    # Packages may be used by distro snapshots, so we keep all versions under unique filename
    base_key = "{}/{}/{}/Packages_{}".format(distro, comp, arch, sha256.hexdigest())
    storage_key = plugin.get_plugin('storage').put(base_key, file=packages)

    old_repo = common.db_cacus.repos.find_one_and_update(
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

    # Do not delete old indices from storage as they may be used by some distro snapshot
    if not force and old_repo and 'packages_file' in old_repo:
        old_key = old_repo['packages_file']
        snapshots = common.db_cacus.repos.find(
            {'snapshot.origin': distro, 'component': comp, 'architecture': arch},
            {'packages_file': 1})
        for snapshot in snapshots:
            if snapshot['packages_file'] == old_key:
                break
        else:
            log.debug("Removing old Packages file %s", old_key)
            try:
                plugin.get_plugin('storage').delete(old_key)
            except common.NotFound:
                log.warning("Cannot find old Packages file")


def _update_sources(distro, comp, now, force):
    """ Updates Sources index
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sources = _generate_sources_file(distro, comp)
    size = sources.tell()
    md5.update(sources.getvalue())
    sha1.update(sources.getvalue())
    sha256.update(sources.getvalue())

    old_sources = common.db_cacus.components.find_one({'distro': distro, 'component': comp}, {'sources_file': 1})
    if not force and old_sources and md5.hexdigest() in old_sources.get('packages_file', ''):
        log.warn("Sources file for %s/%s not changed, skipping update", distro, comp)
        return
    base_key = "{}/{}/source/Sources_{}".format(distro, comp, md5.hexdigest())
    storage_key = plugin.get_plugin('storage').put(base_key, file=sources)

    old_component = common.db_cacus.components.find_one_and_update(
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

    # check whether previous indice is not used by some snapshot and remove it from storage
    if not force and old_component and 'sources_file' in old_component:
        old_key = old_component['sources_file']
        snapshots = common.db_cacus.components.find(
            {'snapshot': {'origin': distro}, 'component': comp},
            {'sources_file': 1})
        for snapshot in snapshots:
            if snapshot['sources_file'] == old_key:
                break
        else:
            log.debug("Removing old Sources file %s", old_key)
            try:
                plugin.get_plugin('storage').delete(old_key)
            except common.NotFound:
                log.warning("Cannot find old Sources file")


def update_distro_metadata(distro, comps=None, arches=None, force=False):
    """ Updates distro's indices (Packages,Sources and Release file)
    Note that components should be already locked
    """
    now = datetime.utcnow()
    if not comps:
        comps = common.db_cacus.repos.find({'distro': distro}).distinct('component')
    if not arches:
        arches = common.db_cacus.repos.find({'distro': distro}).distinct('architecture')
        arches.extend(common.default_arches)

    if not comps or not arches:
        raise common.NotFound("Distro {} is not found or empty".format(distro))

    log.info("Updating metadata for distro %s, components: %s, arches: %s", distro, ', '.join(comps), ', '.join(arches))

    # for all components, updates Packages (for each architecture) and Sources index files
    for comp in comps:
        _update_sources(distro, comp, now, force)
        for arch in arches:
            _update_packages(distro, comp, arch, now, force)

    # now create Release file
    release, release_gpg = _create_release(distro, ts=now)

    # Release file and its digest is small enough to put directly into metabase
    common.db_cacus.distros.find_one_and_update(
            {'distro': distro},
            {'$set': {
                'distro': distro,
                'lastupdated': now,
                'release_file': release,
                'release_gpg': release_gpg
                }},
            upsert=True)


def _generate_sources_file(distro, comp):
    data = common.myStringIO()
    component = common.db_sources[distro].find(
        {'components': comp, 'dsc': {'$exists': True}},
        {'dsc': 1, 'files': 1})
    for pkg in component:
        for k, v in pkg['dsc'].iteritems():
            data.write("{0}: {1}\n".format(k.capitalize(), v))
        data.write("Directory: {}\n".format(common.config['repo_daemon']['storage_subdir']))
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


def _generate_packages_file(distro, comp, arch):
    log.debug("Generating Packages for %s/%s/%s", distro, comp, arch)
    data = common.myStringIO()
    # see https://wiki.debian.org/RepositoryFormat#Architectures - 'all' arch goes with other arhes' Packages index
    repo = common.db_packages[distro].find({'components': comp, 'Architecture': {'$in': [arch, 'all']}})
    for pkg in repo:
        log.debug("Processing %s_%s", pkg['Package'], pkg['Version'])

        path = pkg['storage_key']
        if not path.startswith('extstorage'):
            path = os.path.join(common.config['repo_daemon']['storage_subdir'], path)
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
            else:
                string = "{0}: {1}\n".format(k.capitalize().encode('utf-8'), unicode(v).encode('utf-8'))
            data.write(string)
        data.write("\n")
    # to prevent generating of empty file
    data.write("\n")
    return data


def remove_package(pkg=None,  ver=None, arch=None, distro=None, comp=None, source_pkg=False, skipUpdateMeta=False):
    affected_arches = []
    try:
        with common.DistroLock(distro, [comp]):
            if source_pkg:
                # remove source package (if any) and all binary packages within it from component
                result = common.db_sources[distro].find_one_and_update(
                    {'Package': pkg, 'Version': ver, 'components': comp},
                    {'$pullAll': {'components': [comp]}},
                    projection={'Architecture': 1},
                    upsert=False,
                    return_document=ReturnDocument.BEFORE
                )
                if result:
                    binaries = common.db_packages[distro].update_many(
                        {'source': result['_id']},
                        {'$pullAll': {'components': [comp]}})
                    if binaries.modified_count:
                        affected_arches = [x['Architecture'] for x in
                                           common.db_packages[distro].find({'source': result['_id']}, {'Architecture': 1})]
            else:
                if not arch:
                    # dummy selector for all arches
                    arch = {'$exists': True}
                result = common.db_packages[distro].find_one_and_update(
                    {'Package': pkg, 'Version': ver, 'Architecture': arch, 'components': comp},
                    {'$pullAll': {'components': [comp]}},
                    projection={'Architecture': 1},
                    upsert=False,
                    return_document=ReturnDocument.BEFORE
                )
                affected_arches = [result['Architecture']] if result else []
            if not result:
                msg = "Cannot find package '{}_{}' in '{}/{}'".format(pkg, ver, distro, comp)
                log.error(msg)
                raise common.NotFound(msg)
            else:
                msg = "Package '{}_{}' was removed from '{}/{}'".format(pkg, ver, distro, comp)
                log.info(msg)
                if not skipUpdateMeta:
                    log.info("Updating '%s' distro metadata for component %s, arch: %s", distro, comp, affected_arches)
                    update_distro_metadata(distro, [comp], affected_arches)
                return msg
    except common.DistroLockTimeout as e:
        raise common.TemporaryError(e.message)


def copy_package(pkg=None, ver=None, arch=None, distro=None, src=None, dst=None, source_pkg=False, skipUpdateMeta=False):
    affected_arches = []
    try:
        with common.DistroLock(distro, [src, dst]):
            if source_pkg:
                # move source package (if any) and all binary packages within it
                result = common.db_sources[distro].find_one_and_update(
                    {'Package': pkg, 'Version': ver, 'components': src},
                    {'$addToSet': {'components': dst}},
                    projection={'components': 1},
                    upsert=False,
                    return_document=ReturnDocument.BEFORE
                )
                if result:
                    binaries = common.db_packages[distro].update_many(
                        {'source': result['_id']},
                        {'$addToSet': {'components': dst}})
                    if binaries.modified_count:
                        affected_arches = [x['Architecture'] for x in
                                           common.db_packages[distro].find({'source': result['_id']}, {'Architecture': 1})]

            else:
                if not arch:
                    # dummy selector for all arches
                    arch = {'$exists': True}
                # touch only one specified package
                result = common.db_packages[distro].find_one_and_update(
                    {'Package': pkg, 'Version': ver, 'Architecure': arch, 'components': src},
                    {'$addToSet': {'components': dst}},
                    projection={'components': 1, 'Architecture': 1, 'component': 1},
                    upsert=False,
                    return_document=ReturnDocument.BEFORE
                )
                affected_arches = [result['Architecture']] if result else []
            if not result:
                msg = "Cannot find package '{}_{}' in '{}/{}'".format(pkg, ver, distro, src)
                log.error(msg)
                raise common.NotFound(msg)
            elif dst in result['components']:
                msg = "Package '{}_{}' is already in '{}/{}'".format(pkg, ver, distro, dst)
                log.warning(msg)
                return msg

            msg = "Package '{}_{}' was copied in distro '{}' from '{}' to '{}'".format(pkg, ver, distro, src, dst)
            log.info(msg)

            if not skipUpdateMeta:
                log.info("Updating '%s' distro metadata for components %s and %s, arches: %s", distro, src, dst, affected_arches)
                update_distro_metadata(distro, [src, dst], affected_arches)
            return msg
    except common.DistroLockTimeout as e:
        raise common.TemporaryError(e.message)


def _get_snapshot_name(distro, name):
    # TODO: snapshot name sanity check
    return "{}@{}".format(distro, name)


def delete_snapshot(distro, name):
    snapshot_name = _get_snapshot_name(distro, name)
    if not common.db_cacus.distros.find_one({'snapshot': {'name': name, 'origin': distro}}):
        raise common.NotFound("Snapshot '{}' does not exist".format(name))

    try:
        with common.DistroLock(distro):
            # XXX: Packages and Sources indices are not being cleaned up here, source of garbage in storage:
            common.db_cacus.components.remove({'snapshot': {'origin': distro, 'name': name}})
            common.db_cacus.repos.remove({'snapshot': {'origin': distro, 'name': name}})
            common.db_cacus.distros.remove({'snapshot': {'origin': distro, 'name': name}})
    except common.DistroLockTimeout:
        raise common.TemporaryError("Cannot lock distro '{}'".format(distro))

    return "Snapshot '{}' was deleted".format(snapshot_name)


def create_snapshot(distro, name):
    """ Creates distribution snapshot distro -> distro/name
    Important note about implementation: as far as distro snapshot meant to be lightweight and
    cheap to create, snapshotting is implemented by just copying existing APT indices (Packages, Sources etc) -
    i.e. snapshot will be read-only by design (which is good) and packages database won't store
    any information about whether current package in included in some snapshot or not (which is bad because
    we won't be able to determine whether this package is orphaned and can be deleted from storage).
    """

    snapshot_name = _get_snapshot_name(distro, name)
    snapshot_info = {'origin': distro, 'name': name}

    existing = common.db_cacus.distros.find_one({'distro': snapshot_name})
    if existing:
        # raise common.Conflict("Snapshot '{}' already exists".format(name))
        delete_snapshot(distro, name)
        action = "updated"
    else:
        action = "created"
    origin = common.db_cacus.distros.find_one({'distro': distro})
    if not origin:
        raise common.NotFound("Distro '{}' not found".format(distro))

    try:
        with common.DistroLock(distro):
            for component in common.db_cacus.components.find({'distro': distro}):
                component['distro'] = snapshot_name
                component['snapshot'] = snapshot_info
                component.pop('_id')
                common.db_cacus.components.insert(component)
                for repo in common.db_cacus.repos.find({'distro': distro, 'component': component['component']}):
                    repo['distro'] = snapshot_name
                    repo['snapshot'] = snapshot_info
                    repo.pop('_id')
                    common.db_cacus.repos.insert(repo)

            now = datetime.utcnow()
            snapshot = origin
            snapshot.pop('_id')
            snapshot['snapshot'] = snapshot_info
            release, release_gpg = _create_release(snapshot_name, settings=snapshot, ts=now)
            snapshot.update({
                'distro': snapshot_name,
                'lastupdated': now,
                'release_file': release,
                'release_gpg': release_gpg
                })

            common.db_cacus.distros.insert(snapshot)
    except common.DistroLockTimeout:
        raise common.TemporaryError("Cannot lock distro '{}'".format(distro))

    return "Snapshot '{}' was successfully {}".format(snapshot_name, action)
