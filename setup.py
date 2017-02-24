#!/usr/bin/env python

from setuptools import setup

setup(
    name="cacus",
    version="0.3",
    author="Danila Migalin",
    author_email="me@miga.me.uk",
    url="https://github.com/beebeeep/cacus",
    description="Distributed, fault-tolerant and fast Debian repository with REST API and pluggable storage modules",
    long_description="",
    license="MIT",
    packages=["cacus"],
    install_requires=['PyYAML',
                      'requests',
                      'pymongo>=3.0',
                      'motor>=1.0',
                      'tornado',
                      'pyinotify',
                      'gnupg',
                      'yapsy',
                      'futures',
                      'python-debian',
#                      'azure-common>=1.1.4',
#                      'azure-storage>=0.32'
                      ],
    entry_points={
        'console_scripts': [
            'cacus = cacus.cli:main'
        ]
    },
#    package_data={
#        'cacus': ['plugins/*']
#    },
    data_files=[
        ('/etc', ['contrib/cacus-default.yml'])
    ]
)
