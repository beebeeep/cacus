## [Version 0.7.21](https://github.com/beebeeep/cacus/tree/v0.7.21) (2017-09-22)
  * Added "noindex" parameter to api/v1/package/upload for batch uploads

## [Version 0.7.20](https://github.com/beebeeep/cacus/tree/v0.7.20) (2017-09-18)
  * Decrement used quota upon package purging

## [Version 0.7.19](https://github.com/beebeeep/cacus/tree/v0.7.19) (2017-09-14)
  * Added compatibility with Azure CosmosDB (mongodb API)
  * Added support of locks in Consul

## [Version 0.7.18](https://github.com/beebeeep/cacus/tree/v0.7.18) (2017-09-04)
  * Added optional file name for api/v1/package/upload
  * Fixed uploading to non-existent components

## [Version 0.7.17](https://github.com/beebeeep/cacus/tree/v0.7.17) (2017-09-04)
  * Added package purging
  * Purge old packages

## [Version 0.7.16](https://github.com/beebeeep/cacus/tree/v0.7.16) (2017-08-15)
  * fixed error handling in /api/v1/package/remove

## [Version 0.7.15](https://github.com/beebeeep/cacus/tree/v0.7.15) (2017-08-03)
  * api/v1/distro/show now shows all distros available for authenticated user

## [Version 0.7.14](https://github.com/beebeeep/cacus/tree/v0.7.14) (2017-08-02)
  * Fixed distro import
  * Added CORS stuff

## [Version 0.7.13](https://github.com/beebeeep/cacus/tree/v0.7.13) (2017-07-17)
  * Reject old tokens by default

## [Version 0.7.12](https://github.com/beebeeep/cacus/tree/v0.7.12) (2017-07-14)
  * Added token storing & revocation
  * Create DB indexes for new distro's collections

## [Version 0.7.11](https://github.com/beebeeep/cacus/tree/v0.7.11) (2017-06-27)
  * Fixed missing token check at /package/search endpoint
  * Added list of components to /distro/show
  * Removed old API endpoint

## [Version 0.7.10](https://github.com/beebeeep/cacus/tree/v0.7.10) (2017-06-08)
  * JWT token handling improved

## [Version 0.7.9](https://github.com/beebeeep/cacus/tree/v0.7.9) (2017-05-30)
  * Distro is now optional in api/v1/package/search/

## [Version 0.7.8](https://github.com/beebeeep/cacus/tree/v0.7.8) (2017-05-29)
  * Fixed bug with root token processing
  * Added `restrict_dangerous_operations` option to repo daemon settings

## [Version 0.7.7](https://github.com/beebeeep/cacus/tree/v0.7.7) (2017-05-16)
  * Fixed #13 - update all indices while dealing with "all" architecture

## [Version 0.7.6](https://github.com/beebeeep/cacus/tree/v0.7.6) (2017-05-05)
  * Added API authentication and authorization

## [Version 0.7.5](https://github.com/beebeeep/cacus/tree/v0.7.5) (2017-04-19)
  * Added `max_body_size` setting to `repo_daemon` config

## [Version 0.7.4](https://github.com/beebeeep/cacus/tree/v0.7.4) (2017-04-11)
  * Snapshotting from another snapshot
  * Defaults for some new distro parameters

## [Version 0.7.3](https://github.com/beebeeep/cacus/tree/v0.7.3) (2017-04-12)
  * Update metadata of all affected components while reuploading the package

## [Version 0.7.2](https://github.com/beebeeep/cacus/tree/v0.7.2) (2017-04-11)
  * Added separate access log
  * Fixed GPG key availability check

## [Version 0.7](https://github.com/beebeeep/cacus/tree/v0.7) (2017-04-10)
  * Added retention policy to distributions
  * Updated /api/v1/package/search according latest changes in DB structure
  * Individual signing keys for distros
  * New handle /api/v1/distro/show[/distroname] to get information about
    distro(s)
  * Tests!

## [Version 0.6](https://github.com/beebeeep/cacus/tree/v0.6) (2017-03-13)
  * Refactored code
  * Added "simple" duploader - for binary-only repos
  * Added distro removal

## [Version 0.5](https://github.com/beebeeep/cacus/tree/v0.5) (2017-03-08)
  * Added incoming dirs for each component of each Distro
  * Distro components list is now fixed during repo creation and can be only
    changed by updating distro settings via API
