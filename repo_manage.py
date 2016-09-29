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
import plugin_loader
import common
import dist_importer
from dist_importer import ImportException

log = logging.getLogger('cacus.repo_manage')


class UploadPackageError(Exception):
    pass


class UpdateRepoMetadataError(Exception):
    pass


def upload_package(distro, env, files, changes, skipUpdateMeta=False):
    # files is array of files of .deb, .dsc, .tar.gz and .changes
    # these files are belongs to single package
    meta = {}
    affected_arches = set()
    for file in files:
        filename = os.path.basename(file)
        base_key = "{0}/pool/{1}".format(distro, filename)

        p = common.db_packages[distro].find_one({'Source': changes['source'], 'Version': changes['version']})
        if p:
            log.warning("%s is already uploaded to distro '%s', environment '%s'", base_key, distro, p['environment'])
            continue

        with open(file) as f:
            hashes = common.get_hashes(f)

        log.info("Uploading %s to distro '%s' environment '%s'", base_key, distro, env)
        storage_key = plugin_loader.get_plugin('storage').put(base_key, filename=file)
        #storage_key = os.path.join(common.config['repo_daemon']['storage_subdir'], storage_key)

        meta['environment'] = env
        meta['Source'] = changes['source']
        meta['Version'] = changes['version']

        if file.endswith('.deb') or file.endswith('.udeb'):
            if 'debs' not in meta:
                meta['debs'] = []

            doc = {
                'size': os.stat(file)[stat.ST_SIZE],
                'sha512': binary.Binary(hashes['sha512']),
                'sha256': binary.Binary(hashes['sha256']),
                'sha1': binary.Binary(hashes['sha1']),
                'md5': binary.Binary(hashes['md5']),
                'storage_key': storage_key
                }
            try:
                deb = debfile.DebFile(file)
            except debfile.DebError as e:
                log.critical("Cannot load debfile %s: %s", file, e)
                raise common.FatalError("Cannot load debfile {0}: {1}".format(file, e))

            affected_arches.add(deb.debcontrol()['Architecture'])
            for k, v in deb.debcontrol().iteritems():
                doc[k] = v
            meta['debs'].append(doc)

        else:
            if 'sources' not in meta:
                meta['sources'] = []

            meta['sources'].append({
                'name': filename,
                'size': os.stat(file)[stat.ST_SIZE],
                'sha512': binary.Binary(hashes['sha512']),
                'sha256': binary.Binary(hashes['sha256']),
                'sha1': binary.Binary(hashes['sha1']),
                'md5': binary.Binary(hashes['md5']),
                'storage_key': storage_key
                })

            if file.endswith('.dsc'):
                meta['dsc'] = {}
                with open(file) as f:
                    dsc = deb822.Dsc(f)
                    for k, v in dsc.iteritems():
                        if not k.startswith('Checksums-') and k != 'Files':
                            meta['dsc'][k] = v
    if affected_arches:
        # critical section. updating meta DB
        try:
            with common.RepoLock(distro, env):
                common.db_packages[distro].insert(meta)
                if not skipUpdateMeta:
                    log.info("Updating '%s/%s' distro metadata for arches: %s", distro, env, ', '.join(affected_arches))
                    update_distro_metadata(distro, [env], affected_arches)
        except common.RepoLockTimeout as e:
            log.error("Error updating distro: %s", e)
            raise common.TemporaryError("Cannot lock distro: {0}".format(e))
    else:
        log.info("No changes made on distro %s/%s, skipping metadata update", distro, env)


def update_distro_metadata(distro, envs=None, arches=None, force=False):
    now = datetime.utcnow()
    if not envs:
        envs = common.db_cacus.repos.find({'distro': distro}).distinct('environment')
    if not arches:
        arches = common.db_cacus.repos.find({'distro': distro}).distinct('architecture')
    # update all Packages files of specified architectures in specified environments
    for env in envs:
        for arch in arches:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            packages = generate_packages_file(distro, env, arch)
            size = packages.tell()
            md5.update(packages.getvalue())
            sha1.update(packages.getvalue())
            sha256.update(packages.getvalue())

            old_repo = common.db_cacus.repos.find_one({'distro': distro, 'environment': env, 'architecture': arch}, {'packages_file': 1})
            if not force and old_repo and 'packages_file' in old_repo and md5.hexdigest() in old_repo['packages_file']:
                log.warn("Packages file for %s/%s/%s not changed, skipping update", distro, env, arch)
                continue

            # we hold Packages under unique filename as far as we don't want to make assumptions whether 
            # our storage engine supports updating of keys
            base_key = "{}/{}/{}/Packages_{}".format(distro, env, arch, md5.hexdigest())
            storage_key = plugin_loader.get_plugin('storage').put(base_key, file=packages)
            #storage_key = os.path.join(common.config['repo_daemon']['storage_subdir'], storage_key)

            old_repo = common.db_cacus.repos.find_and_modify(
                    query={'distro': distro, 'environment': env, 'architecture': arch},
                    update={'$set': {
                        'distro': distro,
                        'environment': env,
                        'architecture': arch,
                        'md5': binary.Binary(md5.digest()),
                        'sha1': binary.Binary(sha1.digest()),
                        'sha256': binary.Binary(sha256.digest()),
                        'size': size,
                        'packages_file': storage_key,
                        'lastupdated': now
                        }},
                    new=False,
                    upsert=True)
            if not force and old_repo and 'packages_file' in old_repo:
                old_key = old_repo['packages_file']
                log.debug("Removing old Packages file %s", old_key)

                try:
                    plugin_loader.get_plugin('storage').delete(old_key)
                except common.NotFound:
                    log.warning("Cannot find old Packages file")

    # now create Release file for whole distro (aka "distribution" for Debian folks) including all envs and arches
    pkg_files = list(common.db_cacus.repos.find({'distro': distro}))
    release = u""
    release += u"Origin: {}\n".format(distro)
    release += u"Label: {}\n".format(distro)
    release += u"Suite: {}\n".format(env)
    release += u"Codename: {}\n".format(distro)
    release += u"Date: {}\n".format(now.strftime("%a, %d %b %Y %H:%M:%S +0000"))
    release += u"Architectures: {}\n".format(' '.join(x['architecture'] for x in pkg_files))
    release += u"Description: {}\n".format(common.config['duploader_daemon']['distributions'][distro]['description'])
    for file in pkg_files:
        release += u"MD5Sum:\n"
        release += u" {} {} {}/binary-{}/Packages\n".format(hexlify(file['md5']), file['size'], file['environment'], file['architecture'])
        release += u"SHA1:\n"
        release += u" {} {} {}/binary-{}/Packages\n".format(hexlify(file['sha1']), file['size'], file['environment'], file['architecture'])
        release += u"SHA256:\n"
        release += u" {} {} {}/binary-{}/Packages\n".format(hexlify(file['sha256']), file['size'], file['environment'], file['architecture'])

    ### TODO Sources file ####

    release_gpg = common.gpg_sign(release.encode('utf-8'), common.config['gpg']['signer'])

    # Release file and its digest is small enough to put directly into metabase
    common.db_cacus.distros.find_and_modify(
            query={'distro': distro},
            update={'$set': {
                'distro': distro,
                'lastupdated': now,
                'release_file': release,
                'release_gpg': release_gpg
                }},
            upsert=True)


def generate_packages_file(distro, env, arch):
    data = common.myStringIO()
    distro = common.db_packages[distro].find({'environment': env, 'debs.Architecture': arch})
    for pkg in distro:
        for deb in pkg['debs']:
            for k, v in deb.iteritems():
                if k == 'md5':
                    string = "MD5sum: {0}\n".format(hexlify(v))
                elif k == 'sha1':
                    string = "SHA1: {0}\n".format(hexlify(v))
                elif k == 'sha256':
                    string = "SHA256: {0}\n".format(hexlify(v))
                elif k == 'sha512':
                    string = "SHA512: {0}\n".format(hexlify(v))
                elif k == 'storage_key':
                    string = "Filename: {0}\n".format(os.path.join(common.config['repo_daemon']['storage_subdir'],v))
                else:
                    string = "{0}: {1}\n".format(k.capitalize().encode('utf-8'), unicode(v).encode('utf-8'))
                data.write(string)
            data.write("\n")
    return data


def dmove_package(pkg=None,  ver=None, distro=None, src=None, dst=None, skipUpdateMeta=False):
    try:
        with common.RepoLock(common.db_cacus.locks, distro, src):
            with common.RepoLock(common.db_cacus.locks, distro, dst):
                result = common.db_packages[distro].find_and_modify(
                    query={'Source': pkg, 'Version': ver, 'environment': {'$in': [src, dst]}},
                    update={'$set': {'environment': dst}},
                    fields={'debs.Architecture': 1, 'environment': 1},
                    upsert=False,
                    new=False
                )
                if not result:
                    msg = "Cannot find package '{}_{}' in distro '{}' at env {}".format(pkg, ver, distro, src)
                    log.error(msg)
                    raise common.NotFound(msg)
                elif result['environment'] == dst:
                    msg = "Package '{}_{}' is already in distro '{}' at env {}".format(pkg, ver, distro, src)
                    log.warning(msg)
                    return msg

                msg = "Package '{}_{}' was dmoved in distro '{}' from {} to {}".format(pkg, ver, distro, src, dst)
                log.info(msg)

                affected_arches = set()
                for d in result['debs']:
                    affected_arches.add(d['Architecture'])
                for arch in affected_arches:
                    if not skipUpdateMeta:
                        log.info("Updating '%s/%s/%s' distro metadata", distro, src, arch)
                        update_distro_metadata(distro, src, arch)
                        log.info("Updating '%s/%s/%s' distro metadata", distro, dst, arch)
                        update_distro_metadata(distro, dst, arch)
                return msg
    except common.RepoLockTimeout as e:
        raise common.TemporaryError(e)

"""
def dist_push(distro=None, changes=None):
    log.info("Got push for distro %s file %s", distro, changes)
    try:
        base_dir = common.config['duploader_daemon']['repos'][distro]['incoming_dir']
    except KeyError:
        log.error("Cannot find distro %s", distro)
        return common.Result('NOT_FOUND', 'No such distro')

    filename = os.path.join(base_dir, changes.split('/')[-1])
    url = "http://dist.yandex.ru/{}/unstable/{}".format(distro, changes)
    result = common.download_file(url, filename)
    if result.ok:
        try:
            dist_importer.import_package(filename, distro, 'unstable')
        except ImportException as e:
            return common.Result('ERROR', e)
        return common.Result('OK', 'Imported successfully')
    else:
        return result
"""
