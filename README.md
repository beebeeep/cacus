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
Get the code, run ```python setup.py install```
Dependencies:
- pymongo
- motor
- tornado
- pyinotify
- requests
- gnupg
- yapsy
- concurrent.futures
- python-debian (>= 0.1.22 for .xz compression support in .deb)

Also mini-dinstall package needed (cacus uses it's python library to parse some Debian files) - this dependency will be removed later.

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
Just run ```cacus --help```

To start incoming dirs watcher, run
```shell
cacus --config /path/to/cacus.yaml --duploader-daemon
```

Start repository HTTP daemon (APT and REST APIs):
```shell
cacus --config /path/to/cacus.yaml --repo-daemon
```

REST API documentation pending, some examples:
```shell
# Create distribution "test-repo", duploader daemon will start listening for incoming files at /src/cacus/incoming/test-repo
curl -X POST  -vks 'localhost/debian/api/v1/distro/create/test-repo' \
  -d '{"gpg_check": false, "description": "Test distro", "incoming_timeout": 5, "strict": false}' -H 'Content-Type: application/json'

# Create snapshot "snap1" of distro "test-repo"
curl -X POST  -vks 'localhost/debian/api/v1/distro/snapshot/test-repo/snap1'

# List snapshots of "test-repo"
curl -vks 'localhost/debian/api/v1/distro/snapshot/test-repo'

# Copy package hello-world=0.1 from "unstable" to "stable" components
curl -X POST  -vks 'localhost/debian/api/v1/package/copy/apt-test' \
  -d '{"pkg": "hello-world", "ver": "0.1", "from": "unstable", "to": "stable"}' -H 'Content-Type: application/json'
```
