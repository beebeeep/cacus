#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import yaml
import os
import stat
from debian import debfile
from bson import binary
from pprint import pprint
import hashlib
import pymongo
import logging
import binascii


import storage

config = None
mongo = None
db = None

logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
log = logging.getLogger()
log.setLevel(logging.INFO)


#fileHandler = logging.FileHandler("cacus.log")
#fileHandler.setFormatter(logFormatter)
#log.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)

def connect_mongo(cfg):
    if cfg['type'] == 'single_mongo':
        return pymongo.Connection(host = cfg['host'], port = cfg['port'])

def get_hashes(file):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    fpos = file.tell()
    file.seek(0)

    for chunk in iter(lambda: file.read(4096), b''):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        sha512.update(chunk)

    file.seek(fpos)

    return {'md5': md5.digest(), 'sha1': sha1.digest(), 'sha256': sha256.digest(), 'sha512': sha512.digest()}

def upload_packages(repo, env, pkgs):
    for filename in pkgs:
        meta = {}
        repo_filename = "{0}/{1}".format(repo, os.path.basename(filename))

        p = db[repo].find_one({'filename': repo_filename})
        if p:
            log.warning("{0} is already uploaded to {1}, environment {2}".format(
                repo_filename, repo, p['environment']))
            continue

        with open(filename) as file:
            hashes = get_hashes(file)

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

        log.info("Uploading {0} to {1} environment {2}".format(repo_filename, repo, env))
        db[repo].insert(meta)
        storage.put(repo_filename, filename, config['storage'])

def update_repo_metadata(repo, env):
    print "update", repo, env
    for pkg in db[repo].find({'environment': env}, {'environment': 0, '_id': 0}):
        for k,v in pkg.iteritems():
            if k == 'md5':
                print "MD5sum: {0}".format(binascii.hexlify(v))
            elif k == 'sha1':
                print "SHA1: {0}".format(binascii.hexlify(v))
            elif k == 'sha256':
                print "SHA256: {0}".format(binascii.hexlify(v))
            elif k == 'sha512':
                print "SHA512: {0}".format(binascii.hexlify(v))
            else:
                print "{0}: {1}".format(k.capitalize(), v)
        print



if __name__  == '__main__':
    parser = argparse.ArgumentParser(description='Cacus repo tool')
    parser.add_argument('-l', '--log', type = str, default = '/dev/stderr',
            help = 'Log to file (defaut stderr)')
    parser.add_argument('-c', '--config', type = str, default = '/etc/cacus.yaml',
            help = 'Config file (default /etc/cacus.yaml')
    parser.add_argument('-v', '--verbosity', type = str, default = 'error',
            help = 'Log file verbosity (default is "error")')
    op_type = parser.add_mutually_exclusive_group()
    op_type.add_argument('--upload', action = 'store_true', help = 'Upload package(s)')
    op_type.add_argument('--remove', action = 'store_true', help = 'Remove package(s)')
    op_type.add_argument('--dmove', action = 'store_true', help = 'Dmove package(s)')
    op_type.add_argument('--update-repo', nargs='?', help = 'Update repository metadata')
    parser.add_argument('--from', type = str, help = 'From repo')
    parser.add_argument('--to', type = str, help = 'To repo')
    parser.add_argument('--env', choices = ['unstable', 'testing', 'prestable', 'stable'], help = 'Environment')
    parser.add_argument('pkgs', type = str, nargs = '*')
    args = parser.parse_args()


    with open(args.config if args.config else '/etc/cacus.yaml') as cfg:
        config = yaml.load(cfg)

    mongo = connect_mongo(config['metadb'])
    db = mongo['repos']

    if args.upload:
        upload_packages(args.to, args.env, args.pkgs)
    elif args.update_repo:
        update_repo_metadata(args.update_repo, args.env)

