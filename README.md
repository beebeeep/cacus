Κάκος 
=====

Proof of concept tool for Debian repos creating and maintaining


USAGE:

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
