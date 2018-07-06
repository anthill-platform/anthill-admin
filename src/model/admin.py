
from tornado.gen import Return, coroutine, Task

import common.discover

from common.model import Model
from common.internal import Internal, InternalError
from common.login import LoginClient, LoginClientError
from common import cached

import logging
import collections


class AdminModel(Model):
    def __init__(self, application, cache):
        self.application = application
        self.internal = Internal()
        self.cache = cache

    @coroutine
    def list_services(self):
        @cached(kv=self.cache,
                h="services",
                ttl=60,
                json=True)
        @coroutine
        def get_services():
            discovery = common.discover.cache.location()

            response = yield self.internal.get(
                discovery,
                "@services/internal",
                {},
                discover_service=False)

            raise Return(response)

        services = yield get_services()

        raise Return(services)

    @coroutine
    def get_service(self, service_id):
        result = yield common.discover.cache.get_service(service_id)
        raise Return(result)

    @coroutine
    def get_metadata(self, service_id, access_token):

        @cached(kv=self.cache,
                h=lambda: "metadata:" + service_id,
                ttl=300,
                json=True)
        @coroutine
        def get_metadata(token):
            try:
                logging.info("Looking for metadata from {0}".format(service_id))

                response = yield self.internal.get(
                    service_id,
                    "@metadata", {
                        "access_token": token
                    })

            except InternalError as e:
                raise Return(None)
            else:
                raise Return(response)

        metadata = yield get_metadata(access_token)

        raise Return(metadata)

    @coroutine
    def clear_cache(self):
        db = self.cache.acquire()

        services = yield self.list_services()

        keys = ["metadata:" + service_id for service_id in services]
        keys.extend(["services_metadata", "services"])

        try:
            yield Task(db.delete, *keys)
        finally:
            yield db.release()

    @coroutine
    def list_services_with_metadata(self, access_token):

        @cached(kv=self.cache,
                h="services_metadata",
                ttl=60,
                json=True)
        @coroutine
        def get_services(token):
            services = yield self.list_services()
            result = {}

            metadatas = yield {service_id: self.get_metadata(service_id, token) for service_id in services}

            for service_id, metadata in metadatas.iteritems():
                if metadata:
                    service = {
                        "location": services[service_id],
                        "metadata": metadata
                    }
                    result[service_id] = service

            raise Return(result)

        services = yield get_services(access_token)

        raise Return(collections.OrderedDict(sorted(services.items())))

    @coroutine
    def get_gamespace_info(self, gamespace_name):
        login_client = LoginClient(self.cache)
        try:
            gamespace_info = yield login_client.find_gamespace(gamespace_name)
        except LoginClientError:
            gamespace_info = None
        raise Return(gamespace_info)
