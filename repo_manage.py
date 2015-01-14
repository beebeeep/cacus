#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import stat
import hashlib
import logging
import pprint
import gzip
from debian import debfile, deb822
from binascii import hexlify
from datetime import datetime
from pyme import core
from pyme.constants.sig import mode
from bson import binary

import loader
import common

log = logging.getLogger('cacus.repo_manage')

#def upload_package(repo, env, files, pkg_name = None, pkg_ver = None):
def upload_package(repo, env, files, changes):
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
        storage_key = "/storage/" + loader.get_plugin('storage').put(base_key, file)
        #storage_key = base_key

        meta['environment'] = env
        meta['Source'] = changes['source']
        meta['Version'] = changes['version']

        key_name = common.sanitize_filename(filename)

        if file.endswith('.deb') or file.endswith('.udeb'):
            if not meta.has_key('debs'):
                meta['debs'] = []

            doc = {
                    'size': os.stat(file)[stat.ST_SIZE],
                    'sha512': binary.Binary(hashes['sha512']),
                    'sha256': binary.Binary(hashes['sha256']),
                    'sha1': binary.Binary(hashes['sha1']),
                    'md5': binary.Binary(hashes['md5']),
                    'storage_key': storage_key
                    }
            deb = debfile.DebFile(file)
            affected_arch.add(deb.debcontrol()['Architecture'])
            for k,v in deb.debcontrol().iteritems():
                doc[k] = v
            meta['debs'].append(doc)

        else:
            if not meta.has_key('sources'):
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
                    for k,v in dsc.iteritems():
                        if not k.startswith('Checksums-') and k != 'Files':
                            meta['dsc'][k] = v

    # critical section. updating meta DB
    try:
        with common.RepoLock(common.db_cacus.locks, repo, env):
            common.db_repos[repo].insert(meta)
            for arch in affected_arch:
                log.info("Updating '%s/%s/%s' repo metadata", repo, env, arch)
                update_repo_metadata(repo, env, arch)
    except common.RepoLockTimeout as e:
        log.error("Error updating repo: %s", e)

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
    size = 0
    for data in generate_packages_file(repo, env, arch):
        data = data.encode('utf-8')
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
        size += len(data)

    #We don't need to generate Release file on-the-fly: it's small enough to put it directly to metabase
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

    sig = core.Data()
    plain = core.Data(release.encode('utf-8'))
    ctx = core.Context()
    ctx.set_armor(1)
    signer = ctx.op_keylist_all(common.config['gpg']['signer'],1).next()
    ctx.signers_add(signer)
    ctx.op_sign(plain, sig, mode.DETACH)
    sig.seek(0,0)
    release_gpg = sig.read()

    common.db_cacus[repo].update({'environment': env, 'architecture': arch}, {'$set': {
        'lastupdated': now,
        'md5': binary.Binary(md5.digest()),
        'sha1': binary.Binary(sha1.digest()),
        'sha256': binary.Binary(sha256.digest()),
        'size': size,
        'release_file': release,
        'release_gpg': release_gpg
        }}, True)

def generate_packages_file(repo, env, arch):
    repo = common.db_repos[repo].find({'environment': env, 'debs.Architecture': arch})
    for pkg in repo:
        for deb in pkg['debs']:
            data = u""
            for k,v in deb.iteritems():

                if k == 'md5':
                    data += u"MD5sum: {0}\n".format(hexlify(v))
                elif k == 'sha1':
                    data += u"SHA1: {0}\n".format(hexlify(v))
                elif k == 'sha256':
                    data += u"SHA256: {0}\n".format(hexlify(v))
                elif k == 'sha512':
                    data += u"SHA512: {0}\n".format(hexlify(v))
                elif k == 'storage_key':
                    data += u"Filename: {0}\n".format(v)
                else:
                    data += u"{0}: {1}\n".format(k.capitalize(), v)
            data += u"\n"
            yield data

def dmove_package(pkg = None,  ver = None, repo = None, src = None, dst = None):
    try:
        with common.RepoLock(common.db_cacus.locks, repo, env):
            result = common.db_repos[repo].update(
                    {'Source': pkg, 'Version': ver, 'environment': src },
                    {'$set': {'environment': dst}}, False, w = 1)
            if result['n'] == 0:
                log.error("Cannot find package '%s_%s' in repo '%s' at env %s", pkg, ver, repo, src)
            elif result['nModified'] == 0:
                log.warning("Package '%s_%s' is already in repo '%s' at env %s", pkg, ver, repo, src)
            else:
                log.info("Package '%s_%s' was dmoved in repo '%s' from %s to %s", pkg, ver, repo, src, dst)

            update_repo_metadata(repo, src)
            update_repo_metadata(repo, dst)
    except common.RepoLockTimeout as e:
        log.error("Dmove failed: %s", e)



