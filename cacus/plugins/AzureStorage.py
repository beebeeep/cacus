#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Azure blob storage plugin
    see https://azure.microsoft.com/en-us/documentation/articles/storage-python-how-to-use-blob-storage/
"""

import re
import logging

import requests
from azure.common import AzureMissingResourceHttpError, AzureHttpError, AzureException
from azure.storage.blob import BlockBlobService, PublicAccess, ContentSettings


from cacus import common
from cacus.plugin import IStoragePlugin, PluginInitException

log = logging.getLogger('cacus.azure_storage')


class AzureStorage(IStoragePlugin):

    def configure(self, config):
        self._session = requests.Session()
        self._adapter = requests.adapters.HTTPAdapter(max_retries=config['retries'])
        self._session.mount('https://', self._adapter)
        self.storage = BlockBlobService(account_name=config['account_name'], account_key=config['account_key'], request_session=self._session)
        self.container = config['container']
        self.timeout = config['timeout']
        try:
            container = self.storage.get_container_properties(self.container, timeout=self.timeout)
            log.info("Configuring Azure blob storage %s/%s", self.storage.account_name, self.container)
        except AzureMissingResourceHttpError as e:
            log.warning("Container '%s' is missing in account '%s', trying to create new", self.container, self.storage.account_name)
            try:
                self.storage.create_container(self.container, timeout=self.timeout)
                self.storage.set_container_acl(self.container, public_access=PublicAccess.Container, timeout=self.timeout)
            except Exception as e:
                log.critical("Cannot create new container: %s", e)
                raise PluginInitException("Cannot create new container")
        except AzureHttpError as e:
            log.critical("Cannot access container '%s' in account '%s': %s", self.container, self.storage.account_name, e)
            raise PluginInitException("Cannot access container")
        except Exception as e:
            log.critical("Cannot access container '%s' in account '%s': %s", self.container, self.storage.account_name, e)
            raise PluginInitException("Cannot access container")

    def delete(self, key):
        log.info("Deleting file '%s' from %s/%s", key, self.storage.account_name, self.container)
        try:
            self.storage.delete_blob(self.container, key, timeout=self.timeout)
        except AzureMissingResourceHttpError:
            log.error("File '%s' was not found in %s/%s", key, self.storage.account_name, self.container)
            raise common.NotFound('File not found')
        except Exception as e:
            log.error("Cannot delete '%s' from %s/%s: %s", key, self.storage.account_name, self.container, e)
            raise common.FatalError(e)

    def put(self, key, filename=None, file=None):
        storage_key = key
        try:
            if filename:
                log.debug("Uploading %s to %s", filename, self.storage.make_blob_url(self.container, storage_key))
                self.storage.create_blob_from_path(self.container, storage_key, filename,
                                                   content_settings=ContentSettings(content_type='application/octet-stream'), timeout=self.timeout)
            elif file:
                old_pos = file.tell()
                file.seek(0)
                log.debug("Uploading from stream to %s", self.storage.make_blob_url(self.container, storage_key))
                self.storage.create_blob_from_stream(self.container, storage_key, file,
                                                     content_settings=ContentSettings(content_type='application/octet-stream'), timeout=self.timeout)
                file.seek(old_pos)
        except Exception as e:
            # TODO: more detailed error inspection
            log.critical("Error uploading to %s/%s: %s", self.storage.account_name, self.container, e)
            raise common.FatalError(e)
        return storage_key

    def get(self, key, stream):
        # current azure python sdk barely can work with non-seekable streams,
        # so we have to implement chunking by our own
        # TODO: proper ranging? RFC says server SHOULD return 406 once range is unsatisfiable,
        # but Azure is OK with end pos > blob length unless blob is not empty
        chunk_size = 4*1024*1024
        chunk_start = 0
        chunk_end = chunk_size - 1
        while True:
            try:
                chunk = self.storage._get_blob(self.container, key, start_range=chunk_start, end_range=chunk_end, timeout=self.timeout)
                log.debug("Writing %s bytes from %s", len(chunk.content), chunk_start)
                stream.write(chunk.content)
            except IOError:
                # remote side closed connection
                return
            except AzureMissingResourceHttpError as e:
                raise common.NotFound(e)
            except (AzureHttpError, AzureException) as e:
                raise common.TemporaryError('Error while downloading {}: {}'.format(key, e))

            blob_length = int(chunk.properties.content_range.split('/')[1])
            chunk_start, chunk_end, blob_size = map(int, re.match(r'^bytes\s+(\d+)-(\d+)/(\d+)$', chunk.properties.content_range).groups())
            if chunk_end == blob_size - 1:
                # no more data to stream
                break
            else:
                chunk_start = chunk_end + 1
                chunk_end += chunk_size
        return 0
