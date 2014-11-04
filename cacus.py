#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging

import common, repo_manage, duploader

logFormatter = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(name)s: %(message)s")
log = logging.getLogger('cacus')
log.setLevel(logging.INFO)

#fileHandler = logging.FileHandler("cacus.log")
#fileHandler.setFormatter(logFormatter)
#log.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)

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
    op_type.add_argument('--duploader-daemon', action = 'store_true', help = 'Start duploader daemon')
    op_type.add_argument('--update-repo', nargs='?', help = 'Update repository metadata')
    parser.add_argument('--from', type = str, help = 'From repo')
    parser.add_argument('--to', type = str, help = 'To repo')
    parser.add_argument('--env', choices = ['unstable', 'testing', 'prestable', 'stable'], help = 'Environment')
    parser.add_argument('pkgs', type = str, nargs = '*')
    args = parser.parse_args()

    common.config = common.load_config(args.config)
    common.db = common.connect_mongo(common.config['metadb'])['repos']

    if args.upload:
        repo_manage.upload_packages(args.to, args.env, args.pkgs)
    elif args.update_repo:
        repo_manage.update_repo_metadata(args.update_repo, args.env)
    elif args.duploader_daemon:
        duploader.start_duploader()


