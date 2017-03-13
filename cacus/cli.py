#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
import traceback


# TODO feel free to PR if you know how to log tracebacks in more elegant way
# atm it for some reason doubles traceback string
class MyLogger(logging.getLoggerClass()):
    def error(self, msg, *args, **kwargs):
        if sys.exc_info()[0]:
            msg = str(msg) + "\n{}".format(traceback.format_exc().replace('%', '%%'))
        return super(MyLogger, self).error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        if sys.exc_info()[0]:
            msg = str(msg) + "\n{}".format(traceback.format_exc().replace('%', '%%'))
        return super(MyLogger, self).error(msg, *args, **kwargs)

logging.setLoggerClass(MyLogger)

import repo_manage
import repo_daemon
import duploader
import distro_import

env_choices = ['unstable', 'testing', 'prestable', 'stable']


def main():
    parser = argparse.ArgumentParser(description='Cacus repo tool')
    parser.add_argument('-l', '--log', type=str, default='/dev/stderr',
                        help='Log to file (defaut stderr)')
    parser.add_argument('-c', '--config', type=str,
                        help='Config file (default /etc/cacus.yaml')
    parser.add_argument('-v', '--verbosity', type=str, default='error',
                        help='Log file verbosity (default is "error")')
    op_type = parser.add_mutually_exclusive_group()
    op_type.add_argument('--create-indexes', action='store_true', help='Create MongoDB indexes')
    op_type.add_argument('--duploader-daemon', action='store_true', help='Start duploader daemon')
    op_type.add_argument('--repo-daemon', action='store_true', help='Start repository daemon')
    op_type.add_argument('--update-distro', metavar='DISTRO', nargs='?', help='Update distribution metadata')
    op_type.add_argument('--import-distro', type=str, nargs=2, metavar=('URL', 'NAME'), help='Import distribution')
    """
    op_type.add_argument('--upload', action='store_true', help='Upload package(s)')
    op_type.add_argument('--remove', action='store_true', help='Remove package(s)')
    op_type.add_argument('--dmove', nargs=2, metavar=('PKG', 'VER'), help='Dmove package(s)')
    # op_type.add_argument('--import-repo', type=str, metavar='PATH', help='Import mounted dist.yandex.ru repo')
    parser.add_argument('--from', choices=env_choices, help='From env')
    parser.add_argument('--to', choices=env_choices, help='To env')
    parser.add_argument('--repo', type=str, help='Repository')
    parser.add_argument('--arch', type=str, help='Architecture')
    parser.add_argument('--env', choices=env_choices, help='Environment')
    parser.add_argument('pkgs', type=str, nargs='*')
    """
    args = parser.parse_args()

    if args.duploader_daemon:
        duploader.start_daemon(args.config)
    elif args.repo_daemon:
        repo_daemon.start_daemon(args.config)
    elif args.update_distro:
        manager = repo_manage.RepoManager(args.config)
        manager.update_distro_metadata(args.update_distro, force=True)
    elif args.import_distro:
        importer = distro_import.DistroImporter(args.config)
        importer.import_distro(args.import_distro[0], args.import_distro[1])
    elif args.create_indexes:
        manager = repo_manage.RepoManager(args.config)
        manager.create_cacus_indexes()
        manager.create_packages_indexes()
    else:
        # default action is to start both duploader daemon and repo daemon
        from multiprocessing import Process

        repod = Process(target=repo_daemon.start_daemon, args=(args.config,))
        duploaderd = Process(target=duploader.start_daemon, args=(args.config,))
        repod.start()
        duploaderd.start()
        repod.join()
        duploaderd.join()

if __name__ == '__main__':
    main()
