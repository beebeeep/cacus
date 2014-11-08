#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bson import binary
import os
import sys
import stat
from debian import debfile, deb822
from binascii import hexlify
import logging
import pprint

import loader
import common
import gzip

log = logging.getLogger('cacus.repo_manage')

#def upload_package(repo, env, files, pkg_name = None, pkg_ver = None):
def upload_package(repo, env, files, changes):
    # files is array of files of .deb, .dsc, .tar.gz and .changes
    # these files are belongs to single package
    meta = {}
    for file in files:
        filename = os.path.basename(file)
        base_key = "{0}/{1}".format(repo, filename)

        p = common.db[repo].find_one({'Source': changes['source'], 'Version': changes['version']})
        if p:
            log.warning("%s is already uploaded to repo '%s', environment '%s'", base_key, repo, p['environment'])
            continue

        with open(file) as f:
            hashes = common.get_hashes(f)

        log.info("Uploading %s to repo '%s' environment '%s'", base_key, repo, env)
        #storage_key = loader.get_plugin('storage').put(base_key, file)
        storage_key = base_key

        meta['environment'] = env
        meta['Source'] = changes['source']
        meta['Version'] = changes['version']

        key_name = common.sanitize_filename(filename)

        if file.endswith('.deb'):
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
            for k,v in deb.debcontrol().iteritems():
                doc[k] = v
            meta['debs'].append(doc)

        else:
            if not meta.has_key('sources'):
                meta['sources'] = []

            meta['sources'].append({
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

    pprint.pprint(meta)
    common.db[repo].insert(meta)

def update_repo_metadata(repo, env):
    fname = "{0}/{1}/Packages.gz".format(common.config['repos'][repo]['repo_root'], env)
    log.info("Generating %s", fname)
    if not os.path.isdir(os.path.dirname(fname)):
        os.mkdir(os.path.dirname(fname))
    with gzip.GzipFile(fname, 'w') as packages_file:
        generate_packages_file(repo, env, packages_file)

def generate_packages_file(repo, env, file):
    data = ""
    repo = common.db[repo].find({'environment': env})
    for pkg in repo:
        for deb in pkg['debs']:
            for k,v in deb.iteritems():
                if k == 'md5':
                    data += "MD5sum: {0}\n".format(hexlify(v))
                elif k == 'sha1':
                    data += "SHA1: {0}\n".format(hexlify(v))
                elif k == 'sha256':
                    data += "SHA256: {0}\n".format(hexlify(v))
                elif k == 'sha512':
                    data += "SHA512: {0}\n".format(hexlify(v))
                elif k == 'storage_key':
                    data += "Filename: {0}\n".format(v)
                else:
                    data += "{0}: {1}\n".format(k.capitalize(), v)
            data += "\n"
    file.write(data)
