Κάκος 
=====

Tool for creating and maintaining Debian repos with pluggable storage modules

INSTALLING:
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

Human-friendly ways (debian package, docker image etc) pending.

USAGE:
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


