#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
import traceback


# TODO feel free to PR if you know how to log tracebacks in more elegant way
# atm it for some reason doubles traceback string
class MyLogger(logging.getLoggerClass()):
    user = None

    def makeRecord(self, name, lvl, fn, lno, msg, args, exc_info, func=None, extra=None):
        if not extra:
            extra = {}
        extra['user'] = self.user or 'N/A'
        return super(MyLogger, self).makeRecord(name, lvl, fn, lno, msg, args, exc_info, func, extra)

    def error(self, msg, *args, **kwargs):
        if sys.exc_info()[0]:
            msg = str(msg) + "\n{}".format(traceback.format_exc().replace('%', '%%'))
        return super(MyLogger, self).error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        if sys.exc_info()[0]:
            msg = str(msg) + "\n{}".format(traceback.format_exc().replace('%', '%%'))
        return super(MyLogger, self).error(msg, *args, **kwargs)

logging.setLoggerClass(MyLogger)

import common
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
    op_type.add_argument('--gen-token', type=str, metavar='NAME',
                         help='Generate JWT token for NAME')
    op_type.add_argument('--revoke-token', type=str, metavar='JTI',
                         help='Revoke JWT token with jti=JTI')
    op_type.add_argument('--list-tokens', action='store_true',
                         help='List known JWT tokens')
    op_type.add_argument('--get-token', type=str, metavar='JTI',
                         help='Get token by ID')
    op_type.add_argument('--update-distro', metavar='DISTRO', nargs='?', help='Update distribution metadata')
    op_type.add_argument('--import-distro', type=str, nargs=2, metavar=('URL', 'NAME'), help='Import distribution')

    parser.add_argument('-e', '--expire', type=int, help='Expiration period for JWT token')
    parser.add_argument('-d', '--distro', type=str, nargs='*', help='Distros that will be manageable by this JWT token. If omitted, token will have root access.')
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
        manager = repo_manage.RepoManager(config_file=args.config)
        manager.update_distro_metadata(args.update_distro)
    elif args.import_distro:
        importer = distro_import.DistroImporter(config_file=args.config)
        importer.import_distro(args.import_distro[0], args.import_distro[1])
    elif args.create_indexes:
        manager = repo_manage.RepoManager(config_file=args.config)
        manager.create_cacus_indexes()
        manager.create_packages_indexes()
    elif args.gen_token:
        if not args.expire:
            parser.error("Specify expiration period in days")

        manager = repo_manage.RepoManager(config_file=args.config, quiet=True)
        token = manager.generate_token(args.gen_token, args.expire, args.distro)
        print "Generated token for '{}' with {}; valid for {} days:\n{}".format(
            args.gen_token, 'access to distros: ' + ', '.join(args.distro) if args.distro else 'ROOT access',
            args.expire, token)
    elif args.revoke_token:
        manager = repo_manage.RepoManager(config_file=args.config, quiet=True)
        if manager.revoke_token(args.revoke_token):
            print("Revoked token with jti={}".format(args.revoke_token))
        else:
            print("Cannot find token with jti={}".format(args.revoke_token))
    elif args.list_tokens:
        manager = repo_manage.RepoManager(config_file=args.config, quiet=True)
        manager.print_tokens()
    elif args.get_token:
        manager = repo_manage.RepoManager(config_file=args.config, quiet=True)
        print manager.get_token(args.get_token)
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
