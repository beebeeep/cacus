#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
import pprint


logFormatter = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(name)s: %(message)s")
log = logging.getLogger('cacus')
log.setLevel(logging.DEBUG)

#fileHandler = logging.FileHandler("cacus.log")
#fileHandler.setFormatter(logFormatter)
#log.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)

env_choices = ['unstable', 'testing', 'prestable', 'stable']

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
    op_type.add_argument('--dmove', nargs = 2,  help = 'Dmove package(s)')
    op_type.add_argument('--duploader-daemon', action = 'store_true', help = 'Start duploader daemon')
    op_type.add_argument('--repo-daemon', action = 'store_true', help = 'Start repository daemon')
    op_type.add_argument('--update-repo', nargs='?', help = 'Update repository metadata')
    parser.add_argument('--from', choices = env_choices, help = 'From env')
    parser.add_argument('--to', choices = env_choices, help = 'To env')
    parser.add_argument('--repo', type = str, help = 'Repository')
    parser.add_argument('--env', choices = env_choices, help = 'Environment')
    parser.add_argument('pkgs', type = str, nargs = '*')
    args = parser.parse_args()

    import common
    common.config = common.load_config(args.config)
    common.db_repos = common.connect_mongo(common.config['metadb'])['repos']
    common.db_cacus = common.connect_mongo(common.config['metadb'])['cacus']

    import repo_manage, repo_daemon, duploader

    if args.upload:
        #repo_manage.upload_packages(args.to, args.env, args.pkgs)
        print "This option is broken for current moment"
        sys.exit(1)
    elif args.update_repo:
        repo_manage.update_repo_metadata(args.update_repo, args.env)
    elif args.duploader_daemon:
        duploader.start_duploader()
    elif args.repo_daemon:
        repo_daemon.start_daemon()
    elif args.dmove:
        repo_manage.dmove_package(pkg = args.dmove[0], ver = args.dmove[1],
                repo =  args.repo, src = args.__getattribute__('from'), dst = args.to)


