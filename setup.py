#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="cacus",
    version="0.2",
    author="Danila Migalin",
    author_email="me@miga.me.uk",
    url="https://github.com/beebeeep/cacus",
    description="Distributed, fault-tolerant and fast Debian repository with REST API and pluggable storage modules",
    long_description="",
    license="MIT",
    packages=find_packages(),
    install_requires=['PyYAML', 'requests', 'pymongo', 'motor', 'tornado', 'pyinotify', 'gnupg', 'yapsy', 'futures', 'python-debian'],
    entry_points={
        'console_scripts': [
            'cacus = cacus.cli:main'
        ]
    },
    package_data={
        'cacus': ['plugins/*.yapsy-plugin']
    },
    data_files=[
        ('/etc', ['cacus-default.yml'])
    ]
)
