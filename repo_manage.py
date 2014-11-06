#!/usr/bin/env python

from bson import binary
import os
import sys
import stat
from debian import debfile
from binascii import hexlify
import logging

import misc
import loader
import common
import gzip

log = logging.getLogger('cacus.repo_manage')

def upload_packages(repo, env, pkgs):
    for filename in pkgs:
        meta = {}
        repo_filename = "{0}/{1}".format(repo, os.path.basename(filename))

        p = common.db[repo].find_one({'filename': repo_filename})
        if p:
            log.warning("%s is already uploaded to repo '%s', environment '%s'", repo_filename, repo, p['environment'])
            continue

        with open(filename) as file:
            hashes = common.get_hashes(file)

        if filename.endswith('.deb'):
            deb = debfile.DebFile(filename)
            for k,v in deb.debcontrol().iteritems():
                meta[k] = v
            meta['filename'] = repo_filename
            meta['size'] = os.stat(filename)[stat.ST_SIZE]
            meta['sha512'] = binary.Binary(hashes['sha512'])
            meta['sha256'] = binary.Binary(hashes['sha256'])
            meta['sha1'] = binary.Binary(hashes['sha1'])
            meta['md5'] = binary.Binary(hashes['md5'])
            meta['environment'] = env
            common.db[repo].insert(meta)

        log.info("Uploading %s to repo '%s' environment '%s'", repo_filename, repo, env)
        loader.get_plugin('storage').put(repo_filename, filename)

def update_repo_metadata(repo, env):
    fname = "{0}/{1}/Packages.gz".format(common.config['repos'][repo]['repo_root'], env)
    log.info("Generating %s", fname)
    if not os.path.isdir(os.path.dirname(fname)):
        os.mkdir(os.path.dirname(fname))
    with gzip.GzipFile(fname, 'w') as packages_file:
        generate_packages_file(repo, env, packages_file)

def generate_packages_file(repo, env, file):
    for pkg in common.db[repo].find({'environment': env}, {'environment': 0, '_id': 0}):
        for k,v in pkg.iteritems():
            if k == 'md5':
                file.write("MD5sum: {0}\n".format(hexlify(v)))
            elif k == 'sha1':
                file.write("SHA1: {0}\n".format(hexlify(v)))
            elif k == 'sha256':
                file.write("SHA256: {0}\n".format(hexlify(v)))
            elif k == 'sha512':
                file.write("SHA512: {0}\n".format(hexlify(v)))
            else:
                file.write("{0}: {1}\n".format(k.capitalize(), v))
        file.write("\n")
