## [Version 0.7.5](https://github.com/beebeeep/cacus/tree/v0.7.5) (2017-04-19)
  * Added `max_body_size` setting to `repo_daemon``` config

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
