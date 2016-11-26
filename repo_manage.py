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


def upload_package(distro, comp, files, changes, skipUpdateMeta=False, forceUpdateMeta=False):
    # files is array of files of .deb, .dsc, .tar.gz and .changes
    # these files are belongs to single package
    meta = {}
    affected_arches = set()
    for file in files:
        filename = os.path.basename(file)
        base_key = "{0}/pool/{1}".format(distro, filename)

        p = common.db_packages[distro].find_one({'Source': changes['source'], 'Version': changes['version']})
        if p and not forceUpdateMeta:
            log.warning("%s is already uploaded to distro '%s', component '%s'", base_key, distro, p['component'])
            continue

        with open(file) as f:
            hashes = common.get_hashes(f)

        log.info("Uploading %s to distro '%s' component '%s'", base_key, distro, comp)
        storage_key = plugin_loader.get_plugin('storage').put(base_key, filename=file)
        #storage_key = os.path.join(common.config['repo_daemon']['storage_subdir'], storage_key)

        meta['component'] = comp
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
            with common.RepoLock(distro, comp):
                common.db_packages[distro].find_and_modify(
                        query={'Source': meta['Source'], 'Version': meta['Version']},
                        update={'$set': meta},
                        upsert=True)
                if not skipUpdateMeta:
                    log.info("Updating '%s/%s' distro metadata for arches: %s", distro, comp, ', '.join(affected_arches))
                    update_distro_metadata(distro, [comp], affected_arches, force=forceUpdateMeta)
        except common.RepoLockTimeout as e:
            log.error("Error updating distro: %s", e)
            raise common.TemporaryError("Cannot lock distro: {0}".format(e))
    else:
        log.info("No changes made on distro %s/%s, skipping metadata update", distro, comp)


def update_distro_metadata(distro, comps=None, arches=None, force=False):
    now = datetime.utcnow()
    if not comps:
        comps = common.db_cacus.repos.find({'distro': distro}).distinct('component')
    if not arches:
        arches = common.db_cacus.repos.find({'distro': distro}).distinct('architecture')
    # update all Packages files of specified architectures in specified components
    for comp in comps:
        for arch in arches:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            packages = generate_packages_file(distro, comp, arch)
            size = packages.tell()
            md5.update(packages.getvalue())
            sha1.update(packages.getvalue())
            sha256.update(packages.getvalue())

            old_repo = common.db_cacus.repos.find_one({'distro': distro, 'component': comp, 'architecture': arch}, {'packages_file': 1})
            if not force and old_repo and 'packages_file' in old_repo and md5.hexdigest() in old_repo['packages_file']:
                log.warn("Packages file for %s/%s/%s not changed, skipping update", distro, comp, arch)
                continue

            # we hold Packages under unique filename as far as we don't want to make assumptions whether 
            # our storage engine supports updating of keys
            base_key = "{}/{}/{}/Packages_{}".format(distro, comp, arch, md5.hexdigest())
            storage_key = plugin_loader.get_plugin('storage').put(base_key, file=packages)
            #storage_key = os.path.join(common.config['repo_daemon']['storage_subdir'], storage_key)

            old_repo = common.db_cacus.repos.find_and_modify(
                    query={'distro': distro, 'component': comp, 'architecture': arch},
                    update={'$set': {
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
                    new=False,
                    upsert=True)
            if not force and old_repo and 'packages_file' in old_repo:
                old_key = old_repo['packages_file']
                log.debug("Removing old Packages file %s", old_key)

                try:
                    plugin_loader.get_plugin('storage').delete(old_key)
                except common.NotFound:
                    log.warning("Cannot find old Packages file")
        # now update all Sources indices for each component
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sources = generate_sources_file(distro, comp)
        size = sources.tell()
        md5.update(sources.getvalue())
        sha1.update(sources.getvalue())
        sha256.update(sources.getvalue())
        
        old_sources = common.db_cacus.components.find_one({'disro': distro, 'component': comp}, {'sources_file': 1})
        if not force and old_sources and md5.hexdigest() in old_sources.get('packages_file', ''):
            log.warn("Sources file for %s/%s not changed, skipping update", distro, comp)
            continue
        base_key = "{}/{}/source/Sources_{}".format(distro, comp, md5.hexdigest())
        storage_key = plugin_loader.get_plugin('storage').put(base_key, file=sources)

        old_component = common.db_cacus.components.find_and_modify(
                query={'distro': distro, 'component': comp},
                update={'$set': {
                    'distro': distro,
                    'component': comp,
                    'md5': binary.Binary(md5.digest()),
                    'sha1': binary.Binary(sha1.digest()),
                    'sha256': binary.Binary(sha256.digest()),
                    'size': size,
                    'sources_file': storage_key,
                    'lastupdated': now
                    }},
                new=False,
                upsert=True)
        if not force and old_component and 'sources_file' in old_component:
            old_key = old_component['sources_file']
            log.debug("Removing old Sources file %s", old_key)
            try:
                plugin_loader.get_plugin('storage').delete(old_key)
            except common.NotFound:
                log.warning("Cannot find old Packages file")


    # now create Release file for whole distro (aka "distribution" for Debian folks) including all comps and arches
    packages = list(common.db_cacus.repos.find({'distro': distro}))
    sources = list(common.db_cacus.components.find({'distro': distro}))
    distro_settings = common.db_cacus.distros.find_one({'distro': distro})
    release = u""
    release += u"Origin: {}\n".format(distro)
    release += u"Label: {}\n".format(distro)
    release += u"Suite: {}\n".format(comp)
    release += u"Codename: {}\n".format(distro)
    release += u"Date: {}\n".format(now.strftime("%a, %d %b %Y %H:%M:%S +0000"))
    release += u"Architectures: {}\n".format(' '.join(x['architecture'] for x in packages))
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

def generate_sources_file(distro, comp):
    data = common.myStringIO()
    component = common.db_packages[distro].find({'component': comp, 'dsc': {'$exists': True}}, {'dsc': 1, 'sources': 1})
    for pkg in component:
        for k, v in pkg['dsc'].iteritems():
            if k == 'Source':
                data.write("Package: {0}\n".format(v))
            else:
                data.write("{0}: {1}\n".format(k.capitalize(), v))
        data.write("Directory: storage\n")
        # c-c-c-c-combo!
        files = [x for x in pkg['sources'] if reduce(lambda a,n: a or x['name'].endswith(n), ['tar.gz', 'tar.xz', '.dsc'], False)]

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
    return data

def generate_packages_file(distro, comp, arch):
    data = common.myStringIO()
    distro = common.db_packages[distro].find({'component': comp, 'debs.Architecture': arch})
    for pkg in distro:
        for deb in (x for x in pkg['debs'] if x['Architecture'] == arch):
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


def dmove_package(pkg=None,  ver=None, distro=None, src=None, dst=None, skipUpdateMeta=False, forceUpdateMeta=False):
    try:
        with common.RepoLock(distro, src):
            with common.RepoLock(distro, dst):
                result = common.db_packages[distro].find_and_modify(
                    query={'Source': pkg, 'Version': ver, 'component': {'$in': [src, dst]}},
                    update={'$set': {'component': dst}},
                    fields={'debs.Architecture': 1, 'component': 1},
                    upsert=False,
                    new=False
                )
                if not result:
                    msg = "Cannot find package '{}_{}' in distro '{}' at comp {}".format(pkg, ver, distro, src)
                    log.error(msg)
                    raise common.NotFound(msg)
                elif result['component'] == dst:
                    msg = "Package '{}_{}' is already in distro '{}' at comp {}".format(pkg, ver, distro, src)
                    log.warning(msg)
                    return msg

                msg = "Package '{}_{}' was dmoved in distro '{}' from {} to {}".format(pkg, ver, distro, src, dst)
                log.info(msg)

                if not skipUpdateMeta:
                    affected_arches = set(x['Architecture'] for x in result['debs'])
                    log.info("Updating '%s' distro metadata for components %s and %s, arches: %s", distro, src, dst, ', '.join(affected_arches))
                    update_distro_metadata(distro, [src, dst], affected_arches, force=forceUpdateMeta)
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
