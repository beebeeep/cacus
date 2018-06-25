#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import time
import uuid
import motor
import base64
import logging
import email.utils

from jose import jwt
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, Finish, stream_request_body
from tornado import gen, httputil, httpserver, escape
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address

from . import common
from . import repo_manage


access_log = logging.getLogger('tornado.access')
app_log = logging.getLogger('tornado.application')
gen_log = logging.getLogger('tornado.general')


class CacusRequestHandler(RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with, authorization, content-type, accept")
        self.set_header('Access-Control-Allow-Methods', 'POST, PUT, GET, OPTIONS')

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.finish()


class CachedRequestHandler(CacusRequestHandler):

    def prepare(self):
        pass

    @gen.coroutine
    def _cache_expired(self, item, selector):
        """ Checks whether item in DB was updated since client's latest version
        TODO: i don't like this double-quering of DB, first for expiry check, than
        for actual data. Should be redesigned.
        """
        db = self.settings['db']
        latest_dt = None
        result = db.cacus[item].find(selector, {'lastupdated': 1})
        while (yield result.fetch_next):
            dt = result.next_object()['lastupdated']
            if not latest_dt or dt > latest_dt:
                latest_dt = dt

        if not latest_dt:
            raise gen.Return((True, None))

        if_modified = self.request.headers.get('If-Modified-Since')
        if not if_modified:
            raise gen.Return((True, latest_dt))

        cached_dt = email.utils.parsedate(if_modified)
        cached_ts = time.mktime(cached_dt)
        latest_ts = time.mktime(latest_dt.timetuple())
        if latest_ts <= cached_ts:
            raise gen.Return((False, latest_dt))
        else:
            raise gen.Return((True, latest_dt))


# TODO JSON schema?
class ApiRequestHandler(CacusRequestHandler):
    """ Provides JSON body processing and authentication/authorization using JWT """

    def _get_json_request(self):
        if 'application/json' not in self.request.headers.get('Content-type', '').lower():
            self.set_status(400)
            self.write({'success': False, 'msg': 'application/json Content-type expected'})
            raise Finish()
        try:
            app_log.debug("body '%s'",  self.request.body)
            req = json.loads(escape.to_unicode(self.request.body))
        except Exception as e:
            self.set_status(400)
            self.write({'success': False, 'msg': 'invalid JSON: {}'.format(e)})
            raise Finish()

        class JsonRequestData(dict):

            def __init__(self, request, *args, **kwargs):
                self._request = request
                super(JsonRequestData, self).__init__(*args, **kwargs)

            def __getitem__(self, key):
                try:
                    return dict.__getitem__(self, key)
                except KeyError:
                    app_log.error("Missing required argument %s", key)
                    self._request.set_status(400)
                    self._request.write({'success': False, 'msg': "Missing required argument '{}'".format(key)})
                    raise Finish()

        return JsonRequestData(self, req)

    @gen.coroutine
    def _check_token(self, aud):
        config = self.settings['manager'].config

        ip = ip_address(self.request.remote_ip)
        for net in config['repo_daemon']['privileged_nets']:
            if ip in net:
                # no auth required
                raise gen.Return({'privileged': True})

        try:
            secret = base64.b64decode(config['repo_daemon']['auth_secret'])
            if 'Authorization' not in self.request.headers:
                raise Exception("Authorization required")
            scheme, token = self.request.headers['Authorization'].split(' ')
            if scheme != 'Bearer':
                raise Exception("Use Bearer authorization scheme")
            try:
                if aud is not None:
                    claim = jwt.decode(token, secret, audience=aud, algorithms='HS256')
                else:
                    claim = jwt.decode(token, secret, algorithms='HS256', options={'verify_aud': False})
            except jwt.JWTClaimsError as e:
                if 'Invalid audience' in e:
                    claim = jwt.decode(token, secret, audience=common.Cacus.admin_access, algorithms='HS256')
            if 'jti' in claim:
                # check for revoked tokens
                doc = yield self.settings['db'].cacus.access_tokens.find_one({'jti': claim['jti']})
                if doc and doc['revoked']:
                    raise Exception("Token blacklisted")
            else:
                if self.settings['manager'].config['repo_daemon'].get('reject_old_tokens', True):
                    raise Exception("Old token format, please renew")
        except Exception as e:
            self.set_status(401)
            self.write({'success': False, 'msg': str(e)})
            raise Finish()

        app_log.user = claim['sub']
        access_log.user = claim['sub']
        self.settings['manager'].log.user = claim['sub']
        raise gen.Return(claim)

    def on_finish(self):
        app_log.user = None
        access_log.user = None
        self.settings['manager'].log.user = None


class StorageHandler(CacusRequestHandler):

    def on_connection_close(self):
        self.dead = True

    @gen.coroutine
    def stream_from_storage(self, key=None, headers=[]):
        self.dead = False
        stream = common.ProxyStream(self, headers=headers, ioloop=IOLoop.current())
        self.set_header('Content-Type', 'application/octet-stream')
        # TODO last-modified, content-length and other metadata _should_ be provided!
        try:
            yield self.settings['workers'].submit(self.settings['manager'].storage.get, key, stream)
        except common.NotFound:
            self.set_status(404)
            app_log.error("Key %s was not found at storage", key)
        except common.FatalError as e:
            # self.set_status(500)
            app_log.error("Got error from storage plugin: %s", e)
        self.finish()

    @gen.coroutine
    def get(self, key):
        yield self.stream_from_storage(key)


class ExtStorageHandler(CacusRequestHandler):
    """ Redirects to external location.
    APT should support redirects since version 0.7.21 (see https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=79002)
    """

    @gen.coroutine
    def get(self, url):
        # unescaping being performed here automagical?
        # url = escape.url_unescape(url)
        self.set_header('Location', url)
        self.set_status(302)


class PackagesHandler(CachedRequestHandler, StorageHandler):

    @gen.coroutine
    def get(self, distro=None, comp=None, arch=None):

        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('repos', {'distro': distro, 'component': comp, 'architecture': arch})
        if not expired:
            self.set_status(304)
            return
        if not dt:
            self.set_status(404)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.repos.find_one({'distro': distro, 'component': comp, 'architecture': arch})
        if doc:
            s = self.settings['config']['repo_daemon']
            if s['proxy_storage']:
                headers = [('Content-Length', doc['size']), ('Last-Modified', httputil.format_timestamp(dt))]
                yield self.stream_from_storage(doc['packages_file'], headers=headers)
            else:
                # we use x-accel-redirect instead of direct proxying via storage plugin to allow
                # user to offload cacus' StorageHandler if current storage allows it
                url = os.path.join(s['repo_base'], s['storage_subdir'], doc['packages_file'])
                app_log.info("Redirecting %s/%s/%s/Packages to %s", distro, comp, arch, url)
                self.add_header("X-Accel-Redirect", url)
                self.set_status(200)
        else:
            self.set_status(404)


class SourcesHandler(CachedRequestHandler, StorageHandler):
    """ Returns Sources repo indice
    Generating on the fly as it's rarely used so no point to slow down
    metadata update by pre-generating and storing this file
    """

    @gen.coroutine
    def get(self, distro=None, comp=None):

        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('components', {'distro': distro, 'component': comp})
        if not expired:
            self.set_status(304)
            return
        if not dt:
            self.set_status(404)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.components.find_one({'distro': distro, 'component': comp})
        if doc:
            s = self.settings['config']['repo_daemon']
            if s['proxy_storage']:
                headers = [('Content-Length', doc['size']), ('Last-Modified', httputil.format_timestamp(dt))]
                yield self.stream_from_storage(doc['sources_file'], headers=headers)
            else:
                # we use x-accel-redirect instead of direct proxying via storage plugin to allow
                # user to offload cacus' StorageHandler if current storage allows it
                url = os.path.join(s['repo_base'], s['storage_subdir'], doc['sources_file'])
                app_log.info("Redirecting %s/%s/source/Sources to %s", distro, comp, url)
                self.add_header("X-Accel-Redirect", url)
                self.set_status(200)
        else:
            self.set_status(404)


class SourcesFilesHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, distro=None, comp=None, file=None):
        db = self.settings['db']
        doc = yield db.cacus.repos[distro].find_one({'component': comp, 'sources.name': file},
                                                    {'sources.storage_key': 1, 'sources.name': 1})
        for f in doc['sources']:
            if f['name'] == file:
                s = self.settings['config']['repo_daemon']
                url = os.path.join(s['repo_base'], f['storage_key'])
                app_log.info("Redirecting %s to %s", file, url)
                self.add_header("X-Accel-Redirect", url)
                break
        self.set_status(200)


class ReleaseHandler(CachedRequestHandler):

    @gen.coroutine
    def get(self, distro=None, gpg=None):
        db = self.settings['db']
        (expired, dt) = yield self._cache_expired('distros', {'distro': distro})
        if not expired:
            self.set_status(304)
            return
        if not dt:
            self.set_status(404)
            return
        self.add_header('Last-Modified', httputil.format_timestamp(dt))
        self.set_header('Content-Type', 'application/octet-stream')

        doc = yield db.cacus.distros.find_one({'distro': distro})
        if gpg:
            self.write(doc['release_gpg'])
        else:
            self.write(doc['release_file'])


class ApiDistroRecalculateQuotasHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro):
        yield self._check_token(distro)
        try:
            used = yield self.settings['workers'].submit(self.settings['manager'].recalculate_distro_quotas, distro=distro)
        except common.NotFound as e:
            self.set_status(404)
            self.write({'success': False, 'msg': str(e)})
            return
        self.write({'success': True, 'msg': 'Recalculate complete, used quota is {}'.format(used)})


class ApiDistroReindexHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro):
        yield self._check_token(distro)
        try:
            yield self.settings['workers'].submit(self.settings['manager'].update_distro_metadata, distro=distro)
        except common.NotFound as e:
            self.set_status(404)
            self.write({'success': False, 'msg': str(e)})
            return
        self.write({'success': True, 'msg': 'Reindex complete'})


class ApiDistroShowHandler(ApiRequestHandler):

    @gen.coroutine
    def get(self, distro):
        # a bit tricky auth check here. If distro is not specified, return all distros token has access to
        # (i.e all distros in case of privileged net or admin token)
        claim = yield self._check_token(distro)
        if distro:
            if ('privileged' in claim or claim['aud'] == common.Cacus.admin_access or distro in claim['aud']):
                selector = {'distro': distro}
            else:
                self.set_status(401)
                self.write({'success': False, 'msg': 'Access denied'})
                return
        else:
            if 'privileged' in claim or claim['aud'] == common.Cacus.admin_access:
                selector = {}
            else:
                selector = {'distro': {'$in': claim['aud']}}

        result = []
        cursor = self.settings['db'].cacus.distros.find(selector, {'release_file': 0, 'release_gpg': 0})
        while (yield cursor.fetch_next):
            d = cursor.next_object()
            c = self.settings['db'].cacus.components.find({'distro': d['distro']}, {'component': 1}).to_list(None)
            components = [x['component'] for x in (yield c)]
            pkg_count = yield self.settings['db'].packages[d['distro']].count({})
            if 'imported' in d:
                result.append({
                    'distro': d['distro'],
                    'description': d['description'],
                    'lastupdated': d['lastupdated'].isoformat(),
                    'packages': pkg_count,
                    'type': 'mirror',
                    'source': d['imported']['from'],
                    'components': components
                })
            elif 'snapshot' in d:
                result.append({
                    'distro': d['distro'],
                    'description': d['description'],
                    'lastupdated': d['lastupdated'].isoformat(),
                    'packages': pkg_count,
                    'type': 'snapshot',
                    'origin': d['snapshot']['origin'],
                    'components': components
                })
            else:
                result.append({
                    'distro': d['distro'],
                    'description': d['description'],
                    'lastupdated': d['lastupdated'].isoformat(),
                    'packages': pkg_count,
                    'quota': d['quota'] if d.get('quota', None) is not None else -1,
                    'quota_used': d.get('quota_used', -1),
                    'retention': d.get('retention', 0),
                    'type': 'general',
                    'simple': d.get('simple', True),
                    'strict': d.get('strict', True),
                    'gpg_key': d.get('gpg_key', None) or self.settings['config']['gpg']['sign_key'],
                    'components': components
                })

        self.write({'success': True, 'result': result})


class ApiDistroSnapshotHandler(ApiRequestHandler):

    @gen.coroutine
    def get(self, distro):
        yield self._check_token(distro)
        ret = {'distro': distro, 'snapshots': []}
        snapshots = self.settings['db'].cacus.distros.find({'snapshot.origin': distro}, {'snapshot': 1, 'lastupdated': 1})
        for snapshot in (yield snapshots.to_list(None)):
            ret['snapshots'].append({
                'snapshot': snapshot['snapshot']['name'],
                'created': snapshot['lastupdated'].isoformat()
            })

        self.write({'success': True, 'result': ret})

    @gen.coroutine
    def delete(self, distro):
        yield self._check_token(distro)
        snapshot = self._get_json_request()['snapshot']
        try:
            msg = yield self.settings['workers'].submit(self.settings['manager'].delete_snapshot, distro=distro, name=snapshot)
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})
            return
        self.write({'success': True, 'msg': msg})

    @gen.coroutine
    def post(self, distro):
        yield self._check_token(distro)
        req = self._get_json_request()
        snapshot_name = req['snapshot']
        from_snapshot = req.get('from', None)
        try:
            msg = yield self.settings['workers'].submit(self.settings['manager'].create_snapshot,
                                                        distro=distro, name=snapshot_name, from_snapshot=from_snapshot)
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})
            return
        self.write({'success': True, 'msg': msg})


class ApiDistroCreateHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro):
        yield self._check_token(distro)

        req = self._get_json_request()
        comps = req['components']
        description = req['description']
        simple = req['simple']
        retention = req.get('retention', 0)
        gpg_key = req.get('gpg_key', None)
        quota = req.get('quota', None)

        if quota is not None:
            # quota management is available only for admins
            yield self._check_token(common.Cacus.admin_access)

        if not simple:
            gpg_check = req['gpg_check']
            strict = req['strict']
            incoming_wait_timeout = req['incoming_timeout']
        else:
            gpg_check = strict = incoming_wait_timeout = None

        try:
            old = yield self.settings['workers'].submit(self.settings['manager'].create_distro, distro=distro, description=description,
                                                        components=comps, gpg_check=gpg_check, strict=strict, simple=simple, quota=quota,
                                                        retention=retention, incoming_wait_timeout=incoming_wait_timeout, gpg_key=gpg_key)
            if not old:
                self.set_status(201)
                self.write({'success': True, 'msg': 'repo created'})
            else:
                self.set_status(200)
                self.write({'success': True, 'msg': 'repo settings updated'})
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})


class ApiDistroUpdateHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro):
        yield self._check_token(distro)

        req = self._get_json_request()
        comps = req.get('components', None)
        description = req.get('description', None)
        simple = req.get('simple', None)
        retention = req.get('retention', None)
        gpg_key = req.get('gpg_key', None)
        quota = req.get('quota', None)

        if quota is not None:
            # quota management is available only for admins
            yield self._check_token(common.Cacus.admin_access)

        if simple is not None and not simple:
            gpg_check = req['gpg_check']
            strict = req['strict']
            incoming_wait_timeout = req['incoming_timeout']
        else:
            gpg_check = strict = incoming_wait_timeout = None

        try:
            yield self.settings['workers'].submit(self.settings['manager'].create_distro, update_only=True, distro=distro, description=description,
                                                  components=comps, gpg_check=gpg_check, strict=strict, simple=simple, quota=quota,
                                                  retention=retention, incoming_wait_timeout=incoming_wait_timeout, gpg_key=gpg_key)
            self.set_status(200)
            self.write({'success': True, 'msg': 'repo settings updated'})
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})


class ApiDistroRemoveHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro):
        if self.settings['config']['repo_daemon']['restrict_dangerous_operations']:
            aud = common.Cacus.admin_access
        else:
            aud = distro
        yield self._check_token(aud)
        try:
            msg = yield self.settings['workers'].submit(self.settings['manager'].remove_distro, distro)
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})
            return
        self.write({'success': True, 'msg': msg})


@stream_request_body
class ApiPkgUploadHandler(ApiRequestHandler):
    """Upload single package to non-strict repo.

    Possible implementations: nginx upload_pass (RFC 1867 multipart/form-data only)? tornado.iostream? common.ProxyStream?
    TODO: implement for strict repos? Uploading multiple files can be tricky for REST API, also this is covered by duploader.
    XXX: note that file is uploaded under some random name (we assume that storage can neither preserve file name,
         nor update stored files). So multiple uploads of same package may leave orhpaned files in storage -
         though that could be a problem only for really huge repos. Storage cleanup is possible but a bit tricky.
    """
    _filename = None
    _file = None

    def prepare(self):
        app_log.debug("Got some file: Content-Type %s, Content-Length %s",
                      self.request.headers.get('Content-Type', 'N/A'), self.request.headers.get('Content-Length', 'N/A'))
        self._filename = os.path.join(self.settings['config']['duploader_daemon']['incoming_root'], str(uuid.uuid1()) + ".deb")
        try:
            self._file = open(self._filename, 'w')
        except Exception as e:
            app_log.error("Cannot open temporary file: %s", str(e))
            self.set_status(500)
            self.write({'success': False, 'msg': str(e)})
            self.finish()

    def on_finish(self):
        try:
            if self._file and not self._file.closed:
                self._file.close()
            if os.path.isfile(self._filename):
                os.unlink(self._filename)
        except Exception as e:
            app_log.error("Cannot delete %s: %s", self._filename, e)

    @gen.coroutine
    def data_received(self, data):
        yield self.settings['workers'].submit(self._write_data, data)

    def _write_data(self, data):
        self._file.write(data)
        self._file.flush()

    @gen.coroutine
    def put(self, distro, comp, name=None):
        """ Handle file upload.
        NB name parameter is not used and added for compatibility
        """
        yield self._check_token(distro)

        skip_update_meta = (self.get_argument('noindex', None) is not None)

        try:
            distro_settings = yield self.settings['db'].cacus.distros.find_one({'distro': distro}, {'strict': 1})
            if not distro_settings:
                raise common.NotFound("Distribution '{}' was not found".format(distro))
            if distro_settings['strict'] and not distro_settings['simple']:
                raise common.FatalError("Strict mode enabled for '{}', will not upload package without signed .changes file".format(distro))

            r = yield self.settings['workers'].submit(self.settings['manager'].upload_package, distro, comp,
                                                      [self._filename], changes=None, skipUpdateMeta=skip_update_meta)
            self.set_status(201)
            self.write({'success': True, 'msg': "Package {0[Package]}_{0[Version]} was uploaded to {1}/{2}".format(r[0], distro, comp)})

        except common.NotFound as e:
            self.set_status(404)
            self.write({'success': False, 'msg': str(e)})
        except common.TemporaryError as e:
            # TODO retries
            # timeout on dmove can only if we cannot lock the distro,
            # i.e. there is some other operation processing current distro
            self.set_status(409)
            self.write({'success': False, 'msg': str(e)})
        except (common.FatalError, Exception) as e:
            app_log.error("Erorr processing incoming package: %s", str(e))
            self.set_status(400)
            self.write({'success': False, 'msg': str(e)})


class ApiPkgCopyHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro=None):
        yield self._check_token(distro)
        req = self._get_json_request()
        pkg = req['pkg']
        ver = req['ver']
        arch = req.get('arch', None)
        dst = req['to']
        source_pkg = req.get('source_pkg', False)

        try:
            r = yield self.settings['workers'].submit(self.settings['manager'].copy_package,
                                                      distro=distro, pkg=pkg, ver=ver, arch=arch, dst=dst, source_pkg=source_pkg)
            self.write({'success': True, 'msg': r})
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})


class ApiPkgRemoveHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro=None, comp=None):
        yield self._check_token(distro)
        req = self._get_json_request()
        pkg = req['pkg']
        ver = req['ver']
        arch = req.get('arch', None)
        source_pkg = req.get('source_pkg', False)

        try:
            r = yield self.settings['workers'].submit(self.settings['manager'].remove_package, distro=distro,
                                                      pkg=pkg, ver=ver, arch=arch, comp=comp, source_pkg=source_pkg)
            self.write({'success': True, 'msg': r})
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})


class ApiPkgPurgeHandler(ApiRequestHandler):

    @gen.coroutine
    def post(self, distro=None, comp=None):
        yield self._check_token(distro)
        req = self._get_json_request()
        pkg = req['pkg']
        ver = req['ver']
        arch = req.get('arch', None)

        try:
            r = yield self.settings['workers'].submit(self.settings['manager'].purge_package, distro=distro,
                                                      pkg=pkg, ver=ver, arch=arch)
            self.write({'success': True, 'msg': r})
        except common.CacusError as e:
            self.set_status(e.http_code)
            self.write({'success': False, 'msg': str(e)})


class ApiPkgSearchHandler(ApiRequestHandler):

    @gen.coroutine
    def get(self, distro=None):
        yield self._check_token(distro)
        pkg = self.get_argument('pkg', None)
        ver = self.get_argument('ver', None)
        comp = self.get_argument('comp', None)
        descr = self.get_argument('descr', None)
        lang = self.get_argument('lang', None)
        yield self._search(distro, pkg, ver, comp, descr, lang)

    @gen.coroutine
    def post(self, distro=None):
        yield self._check_token(distro)
        req = self._get_json_request()
        pkg = req.get('pkg', None)
        ver = req.get('ver', None)
        comp = req.get('comp', None)
        descr = req.get('descr', None)
        lang = req.get('lang', None)
        yield self._search(distro, pkg, ver, comp, descr, lang)

    @gen.coroutine
    def _search(self, distro=None, pkg=None, ver=None, comp=None, descr=None, lang=None):
        db = self.settings['db']
        config = self.settings['config']
        selector = {}

        if not pkg and not descr:
            self.write({'success': False, 'msg': "Specify either 'pkg' or 'descr' search term"})
            return
        if pkg:
            selector['Package'] = {'$regex': pkg}
        if ver:
            selector['Version'] = {'$regex': ver}
        if comp:
            selector['components'] = comp
        if descr:
            if lang:
                selector['$text'] = {'$search': descr, '$language': lang}
            else:
                selector['$text'] = {'$search': descr}
        projection = {
            '_id': 0,
            'Package': 1,
            'Version': 1,
            'Architecture': 1,
            'storage_key': 1,
            'meta.Maintainer': 1,
            'meta.Description': 1,
            'components': 1
        }

        result = {}
        pkgs = {}

        if distro:
            distros = [distro]
        else:
            cursor = db.cacus.distros.find({}, {'distro': 1}).to_list(None)
            distros = (x['distro'] for x in (yield cursor))
        for d in distros:
            pkgs[d] = []
            cursor = db.packages[d].find(selector, projection)
            while (yield cursor.fetch_next):
                pkg = cursor.next_object()
                if pkg:
                    p = dict((k.lower(), v) for k, v in pkg.items())
                    p['url'] = os.path.join(config['repo_daemon']['storage_subdir'], p['storage_key'])
                    for k, v in pkg['meta'].items():
                        p[k.lower()] = v
                    del p['meta']
                    del p['storage_key']
                    pkgs[d].append(p)

        result = {'success': True, 'result': pkgs}
        self.write(result)


def _make_app(config):
    s = config['repo_daemon']

    # APT interface. Using full debian repository layout (see https://wiki.debian.org/RepositoryFormat)
    release_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9@/]+)/Release(?P<gpg>\.gpg)?$"
    packages_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9@/]+)/(?P<comp>[-_a-z0-9]+)/binary-(?P<arch>\w+)/Packages$"
    sources_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9@/]+)/(?P<comp>[-_a-z0-9]+)/source/Sources$"
    sources_files_re = s['repo_base'] + r"/dists/(?P<distro>[-_.A-Za-z0-9@/]+)/(?P<comp>[-_a-z0-9]+)/source/(?P<file>.*)$"
    storage_re = os.path.join(s['repo_base'], s['storage_subdir']) + r"/(?P<key>.*)$"
    extstorage_re = s['repo_base'] + r"/extstorage/(?P<url>.*)$"

    # REST API
    # Package operations
    api_pkg_upload_re = s['repo_base'] + r"/api/v1/package/upload/(?P<distro>[-_.A-Za-z0-9]+)/(?P<comp>[-_a-z0-9]+)(?:/(?P<name>.+))?$"
    api_pkg_copy_re = s['repo_base'] + r"/api/v1/package/copy/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_pkg_remove_re = s['repo_base'] + r"/api/v1/package/remove/(?P<distro>[-_.A-Za-z0-9]+)/(?P<comp>[-_a-z0-9]+)$"
    api_pkg_purge_re = s['repo_base'] + r"/api/v1/package/purge/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_pkg_search_re = s['repo_base'] + r"/api/v1/package/search(?:/(?P<distro>[-_.A-Za-z0-9]+))?$"
    # Distribution operations
    api_distro_create_re = s['repo_base'] + r"/api/v1/distro/create/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_distro_update_re = s['repo_base'] + r"/api/v1/distro/update/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_distro_remove_re = s['repo_base'] + r"/api/v1/distro/remove/(?P<distro>[-_.A-Za-z0-9]+)$"
    api_distro_reindex_re = s['repo_base'] + r"/api/v1/distro/reindex/(?P<distro>[-_.A-Za-z0-9/]+)$"
    api_distro_recalculate_quotas_re = s['repo_base'] + r"/api/v1/distro/recalculate_quotas/(?P<distro>[-_.A-Za-z0-9/]+)$"
    api_distro_snapshot_re = s['repo_base'] + r"/api/v1/distro/snapshot/(?P<distro>[-_.A-Za-z0-9/]+)$"
    api_distro_show_re = s['repo_base'] + r"/api/v1/distro/show(?:/(?P<distro>[-_.A-Za-z0-9/]+))?$"

    return Application([
        url(packages_re, PackagesHandler),
        url(release_re, ReleaseHandler),
        url(sources_re, SourcesHandler),
        url(sources_files_re, SourcesFilesHandler),
        url(storage_re, StorageHandler),
        url(extstorage_re, ExtStorageHandler),
        url(api_pkg_upload_re, ApiPkgUploadHandler),
        url(api_pkg_copy_re, ApiPkgCopyHandler),
        url(api_pkg_remove_re, ApiPkgRemoveHandler),
        url(api_pkg_purge_re, ApiPkgPurgeHandler),
        url(api_pkg_search_re, ApiPkgSearchHandler),
        url(api_distro_create_re, ApiDistroCreateHandler),
        url(api_distro_update_re, ApiDistroUpdateHandler),
        url(api_distro_remove_re, ApiDistroRemoveHandler),
        url(api_distro_reindex_re, ApiDistroReindexHandler),
        url(api_distro_recalculate_quotas_re, ApiDistroRecalculateQuotasHandler),
        url(api_distro_snapshot_re, ApiDistroSnapshotHandler),
        url(api_distro_show_re, ApiDistroShowHandler),
        ])


def start_daemon(config):

    manager = repo_manage.RepoManager(config_file=config)

    for handler in common._setup_log_handlers(manager.config['logging']['access']):
        access_log.addHandler(handler)

    app = _make_app(manager.config)
    server = httpserver.HTTPServer(app, max_body_size=manager.config['repo_daemon'].get('max_body_size', 200*1024*1024))
    server.bind(manager.config['repo_daemon']['port'])
    server.start(0)
    db = motor.MotorClient(**(manager.config['db']))
    thread_pool = ThreadPoolExecutor(100)
    app.settings['config'] = manager.config
    app.settings['manager'] = manager
    app.settings['db'] = db
    app.settings['workers'] = thread_pool
    IOLoop.instance().start()
