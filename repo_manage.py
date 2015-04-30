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

import loader
import common
import dist_importer

log = logging.getLogger('cacus.repo_manage')


class UploadPackageError(Exception):
    pass


class UpdateRepoMetadataError(Exception):
    pass


def upload_package(repo, env, files, changes, skipUpdateMeta=False):
    # files is array of files of .deb, .dsc, .tar.gz and .changes
    # these files are belongs to single package
    meta = {}
    affected_arch = set()
    for file in files:
        filename = os.path.basename(file)
        base_key = "{0}/{1}".format(repo, filename)

        p = common.db_repos[repo].find_one({'Source': changes['source'], 'Version': changes['version']})
        if p:
            log.warning("%s is already uploaded to repo '%s', environment '%s'", base_key, repo, p['environment'])
            continue

        with open(file) as f:
            hashes = common.get_hashes(f)

        log.info("Uploading %s to repo '%s' environment '%s'", base_key, repo, env)
        storage_key = loader.get_plugin('storage').put(base_key, filename=file)
        if not storage_key:
            log.critical("Error uploading %s, skipping whole package", file)
            raise UploadPackageError("Cannot upload {0} to storage".format(file))
        storage_key = "/storage/" + storage_key

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
                raise UploadPackageError("Cannot load debfile {0}: {1}".format(file, e))

            affected_arch.add(deb.debcontrol()['Architecture'])
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
    if affected_arch:
        # critical section. updating meta DB
        try:
            with common.RepoLock(common.db_cacus.locks, repo, env):
                common.db_repos[repo].insert(meta)
                if not skipUpdateMeta:
                    for arch in affected_arch:
                        log.info("Updating '%s/%s/%s' repo metadata", repo, env, arch)
                        update_repo_metadata(repo, env, arch)
        except (common.RepoLockTimeout, UpdateRepoMetadataError) as e:
            log.error("Error updating repo: %s", e)
            raise UploadPackageError("Cannot lock repo: {0}".format(e))
    else:
        log.info("No changes made on repo %s/%s, skipping metadata update", repo, env)


def update_repo_metadata(repo, env, arch):
    """
    fname = "{0}/{1}/Packages.gz".format(common.config['repos'][repo]['repo_root'], env)
    log.info("Generating %s", fname)
    if not os.path.isdir(os.path.dirname(fname)):
        os.mkdir(os.path.dirname(fname))
    with gzip.GzipFile(fname, 'w') as packages_file:
        for data in generate_packages_file(repo, env, arch):
            packages_file.write(data)
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    packages = generate_packages_file(repo, env, arch)
    size = packages.tell()
    md5.update(packages.getvalue())
    sha1.update(packages.getvalue())
    sha256.update(packages.getvalue())

    old_repo = common.db_cacus[repo].find_one({'environment': env, 'architecture': arch}, {'packages_file': 1})
    if old_repo and 'packages_file' in old_repo and old_repo['packages_file'].find(md5.hexdigest()) >= 0:
        log.warn("Packages file for %s/%s/%s not changed, skipping update", repo, env, arch)
        return
    if size == 0:
        log.warn("Looks like %s/%s/%s repo is empty, nothing to update", repo, env, arch)
        return

    base_key = "{}/{}/{}/Packages_{}".format(repo, env, arch, md5.hexdigest())
    storage_key = loader.get_plugin('storage').put(base_key, file=packages)
    if not storage_key:
        log.critical("Error uploading new Packages", file)
        raise UpdateRepoMetadataError("Cannot upload Packages file to storage")

    """
    packages.seek(0)
    for chunk in iter(lambda: packages.read(4096), ''):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    #    size += len(chunk)
    """

    # We don't need to generate Release file on-the-fly: it's small enough to put it directly to metabase
    release = u""
    now = datetime.utcnow()
    release += u"Origin: {0}\n".format(repo)
    release += u"Label: {0}\n".format(repo)
    release += u"Suite: {0}\n".format(env)
    release += u"Codename: {0}/{1}\n".format(env, arch)
    release += u"Date: {0}\n".format(now.strftime("%a, %d %b %Y %H:%M:%S +0000"))
    release += u"Architectures: {0}\n".format(arch)
    release += u"Description: {0}\n".format(common.config['duploader_daemon']['repos'][repo]['description'])
    release += u"MD5Sum:\n {0}\t{1} Packages\n".format(md5.hexdigest(), size)
    release += u"SHA1:\n {0}\t{1} Packages\n".format(sha1.hexdigest(), size)
    release += u"SHA256:\n {0}\t{1} Packages\n".format(sha256.hexdigest(), size)

    release_gpg = common.gpg_sign(release.encode('utf-8'), common.config['gpg']['signer'])

    old_repo = common.db_cacus[repo].find_and_modify(
        query={'environment': env, 'architecture': arch},
        update={'$set': {
            'lastupdated': now,
            'md5': binary.Binary(md5.digest()),
            'sha1': binary.Binary(sha1.digest()),
            'sha256': binary.Binary(sha256.digest()),
            'size': size,
            'release_file': release,
            'release_gpg': release_gpg,
            'packages_file': storage_key
        }},
        new=False,
        upsert=True)
    if 'packages_file' in old_repo:
        old_key = old_repo['packages_file']
        log.debug("Removing old Packages file %s", old_key)
        loader.get_plugin('storage').delete(old_key)


def generate_packages_file(repo, env, arch):
    data = common.myStringIO()
    repo = common.db_repos[repo].find({'environment': env, 'debs.Architecture': arch})
    for pkg in repo:
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
                    string = "Filename: {0}\n".format(v)
                else:
                    string = "{0}: {1}\n".format(k.capitalize().encode('utf-8'), unicode(v).encode('utf-8'))
                data.write(string)
            data.write("\n")
    return data


def dmove_package(pkg=None,  ver=None, repo=None, src=None, dst=None, skipUpdateMeta=False):
    try:
        with common.RepoLock(common.db_cacus.locks, repo, src):
            with common.RepoLock(common.db_cacus.locks, repo, dst):
                result = common.db_repos[repo].find_and_modify(
                    query={'Source': pkg, 'Version': ver, 'environment': {'$in': [src, dst]}},
                    update={'$set': {'environment': dst}},
                    fields={'debs.Architecture': 1, 'environment': 1},
                    upsert=False,
                    new=False
                )
                if not result:
                    msg = "Cannot find package '{}_{}' in repo '{}' at env {}".format(pkg, ver, repo, src)
                    log.error(msg)
                    return {'result': common.status.NOT_FOUND, 'msg': msg}
                elif result['environment'] == dst:
                    msg = "Package '{}_{}' is already in repo '{}' at env {}".format(pkg, ver, repo, src)
                    log.warning(msg)
                    return {'result': common.status.NO_CHANGES, 'msg': msg}
                else:
                    msg = "Package '{}_{}' was dmoved in repo '{}' from {} to {}".format(pkg, ver, repo, src, dst)
                    log.info(msg)

                affected_arch = set()
                for d in result['debs']:
                    affected_arch.add(d['Architecture'])
                for arch in affected_arch:
                    if not skipUpdateMeta:
                        log.info("Updating '%s/%s/%s' repo metadata", repo, src, arch)
                        update_repo_metadata(repo, src, arch)
                        log.info("Updating '%s/%s/%s' repo metadata", repo, dst, arch)
                        update_repo_metadata(repo, dst, arch)
                return {'result': common.status.OK, 'msg': msg}
    except (common.RepoLockTimeout, UpdateRepoMetadataError) as e:
        msg = "Dmove failed: {}".format(e)
        return {'result': common.status.TIMEOUT, 'msg': msg}


def dist_push(repo=None, changes=None):
    log.info("Got push for repo %s file %s", repo, changes)
    try:
        base_dir = common.config['duploader_daemon']['repos'][repo]['incoming_dir']
    except KeyError:
        log.error("Cannot find repo %s", repo)
        return {'result': common.status.NOT_FOUND, 'msg': "No such repo"}

    filename = os.path.join(base_dir, changes.split('/')[-1])
    url = "http://dist.yandex.ru/{}/unstable/{}".format(repo, changes)
    result = common.download_file(url, filename)
    if result['result'] == common.status.OK:
        dist_importer.import_package(filename, repo, 'unstable')
