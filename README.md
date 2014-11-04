cacus
=====

Proof of concept tool for Debian repos creating and maintaining


USAGE:

Just run ```python cacus.py --help```

To start incoming dirs watcher, run
```shell
python cacus.py --config /path/to/cacus.yaml --duploader-daemon
```

Manual package upload:
```shell
python cacus.py --config /path/to/cacus.yaml --upload --to yandex-precise --env unstable ~/path/where/all/*deb
```
