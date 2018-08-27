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
Get the code, then either run ```python setup.py install``` to install it locally or use ```docker build``` to create Docker image. 
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

NOTE: on some crippled platforms, like Debian Jessie, you probably will need to manually install azure libs in order to use AzureStorage plugin: ```sudo pip install --upgrade azure-common azure-storage``` (this is probably due to Azure/azure-storage-python#51)

Also you will need MongoDB running somewhere, and storage:
- Dummy local file storage - ready to use
- Azure Blob Storage - ready to use
- Elliptics (http://reverbrain.com/elliptics/) - planned
- Amazon S3 (https://aws.amazon.com/s3/) - planned
- Ceph (http://ceph.com) - planned
- Any other - feel free to contribute your storage plugin

Also you can just build docker image using supplied Dockerfile, note that it has build argument `STORAGE` for selecting storage plugin (currently, only `azure` and `file` are supported). For example, to build and start container (with mounted /var/lib/cacus, where you should put config file `config.yml`, gpg homedir and where will be the duploader incoming dirs):
```sh
docker build -t cacus:0.7.5 --build-arg STORAGE=azure .
docker run -v /var/lib/cacus:/cacus -d --name cacus-repo -p 8088:1488 --restart always cacus:0.7.5
```

Also, there are packages for Debian Jessie:
```sh
curl https://cacus.miga.me.uk/cacus.asc | sudo apt-key add -
sudo sh -c 'echo "deb http://cacus.miga.me.uk/debian cacus-jessie unstable" > /etc/apt/sources.list.d/cacus.list'
sudo apt-get update
sudo apt-get install python3-cacus python3-cacus-{azure,file}-storage
```

Configuration & environment
---------------------------
You can use [sample config file](contrib/cacus-default.yml) to make your own config (its default location is ```/etc/cacus.yml```). For docker you can map some external folder with config file, incoming dir and GPG homedir to some location inside, i.e. ```docker run --name cacus -P -v /srv/cacus:/cacus cacus-image```, just make sure that paths in config are correct. 

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

For day to day repo management, there is a convenient CLI tool [caca](https://github.com/beebeeep/caca), you really should try it unless you are eager to fiddle with curl and raw REST API. Also there is a [web-interface](https://github.com/beebeeep/web-caca) supporting some basic functions like package search, copying and uploading ([see here](https://cacus.miga.me.uk/web/#/app/distro/)).

REST API documentation can be found [here](https://cacus.miga.me.uk/docs/), here are some examples:
```shell
# Create distribution "test-repo", duploader daemon will start listening for incoming files at /src/cacus/incoming/test-repo/[unstable, testing, main]
curl -X POST -H 'Content-Type: application/json' -vks \
  'localhost/debian/api/v1/distro/create/test-repo' \
  -d '{"gpg_check": false, "description": "Test distro", "incoming_timeout": 5, "strict": false,
       "simple": false, "components": ["unstable", "testing", "main"] }'

# Create "simple" distribution "test-repo", only for single .deb binary packages
curl -X POST -H 'Content-Type: application/json' -vks \
  'localhost/debian/api/v1/distro/create/test-repo' \
  -d '{"description": "Test distro", "simple": true, "components": ["unstable", "testing", "main"] }'

# Remove distribution "test-repo", including all snapshots and files uploaded to storage
curl -X POST -vks 'localhost/debian/api/v1/distro/remove/test-repo'

# Create snapshot "snap1" of distro "test-repo"
curl -X POST  -vks 'localhost/debian/api/v1/distro/snapshot/test-repo/snap1'

# List snapshots of "test-repo"
curl -vks 'localhost/debian/api/v1/distro/snapshot/test-repo'

# Upload package to distribution "common", component "unstable"
curl -vks -T hello-world_0.1-1ubuntu1_amd64.deb localhost/debian/api/v1/package/upload/common/unstable

# Copy package hello-world=0.1 from "unstable" to "stable" components
curl -X POST  -vks 'localhost/debian/api/v1/package/copy/apt-test' \
  -d '{"pkg": "hello-world", "ver": "0.1", "from": "unstable", "to": "stable"}' -H 'Content-Type: application/json'
```
