Κάκος 
=====

Distributed, fault-tolerant and fast Debian repository with REST API and pluggable storage modules.

Idea:
-----
Managing the huge and highloaded (for read and write) debian repo can be a tricky job - existing solutions like reprepro could be slow in refreshing repo indices and barely suitable for horizontal scaling. 

Cacus is designed as scalable, high-load and high-availability debian repo fully compatible with official Debian repository layout, relying on MongoDB and various pluggable cloud storage engines and can be easily installed and used on multiple instances behind any kind of load balancing. 

Moreover, Cacus features REST API that can be used to integrate it with CI/CD systems

Installation:
-----------
Get the code, install the dependencies:
Python libs (via pip or apt):
- pymongo
- motor
- tornado
- pyinotify
- requests
- pyme
- yapsy
- concurrent.futures
- python-debian (>= 0.1.21+nmu3 for .xz compression support in .deb)

Debian packages:
- mini-dinstall (it's not actually used as repo manager, just one python lib)

Also you will need MongoDB running somewhere, and storage:
- Dummy local file storage - ready to use
- Azure Blob Storage - ready to use
- Elliptics (http://reverbrain.com/elliptics/) - planned
- Amazon S3 (https://aws.amazon.com/s3/) - planned
- Ceph (http://ceph.com) - planned
- Any other - feel free to contribute your storage plugin

Human-friendly ways (debian package, docker image etc) pending.

Usage:
------
Just run ```python cacus.py --help```

To start incoming dirs watcher, run
```shell
python cacus.py --config /path/to/cacus.yaml --duploader-daemon
```

Start repository HTTP daemon:
```shell
python cacus.py --config /path/to/cacus.yaml --repo-daemon
```
Import repository:
```shell
python cacus.py --config /path/to/cacus.yaml  --import-repo /path/to/repo/ --repo REPO --env ENV
```
