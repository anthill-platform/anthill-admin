
from tornado.gen import multi

from anthill.common import discover, cached

from anthill.common.model import Model
from anthill.common.internal import Internal, InternalError
from anthill.common.login import LoginClient, LoginClientError

import logging
import collections


class AdminModel(Model):
    def __init__(self, application, cache):
        self.application = application
        self.internal = Internal()
        self.cache = cache

    async def list_services(self):
        @cached(kv=self.cache,
                h="services",
                ttl=60,
                json=True)
        async def get_services():
            discovery = discover.cache.location()

            response = await self.internal.get(
                discovery,
                "@services/internal",
                {},
                discover_service=False)

            return response

        services = await get_services()

        return services

    # noinspection PyMethodMayBeStatic
    async def get_service(self, service_id):
        result = await discover.cache.get_service(service_id)
        return result

    async def get_metadata(self, service_id, access_token):

        @cached(kv=self.cache,
                h=lambda: "metadata:" + service_id,
                ttl=300,
                json=True)
        async def get_metadata(token):
            try:
                logging.info("Looking for metadata from {0}".format(service_id))

                response = await self.internal.get(
                    service_id,
                    "@metadata", {
                        "access_token": token
                    })

            except InternalError:
                return None
            else:
                return response

        metadata = await get_metadata(access_token)

        return metadata

    async def clear_cache(self):
        async with self.cache.acquire() as db:
            services = await self.list_services()
            keys = ["metadata:" + service_id for service_id in services]
            keys.extend(["services_metadata", "services"])
            await db.delete(*keys)

    async def list_services_with_metadata(self, access_token):

        @cached(kv=self.cache,
                h="services_metadata",
                ttl=60,
                json=True)
        async def get_services(token):
            services_list = await self.list_services()
            result = {}

            meta_list = await multi({
                service_id: self.get_metadata(service_id, token)
                for service_id in services_list
            })

            for service_id, metadata in meta_list.items():
                if metadata:
                    service = {
                        "location": services_list[service_id],
                        "metadata": metadata
                    }
                    result[service_id] = service

            return result

        services = await get_services(access_token)

        return collections.OrderedDict(sorted(services.items()))

    async def get_gamespace_info(self, gamespace_name):
        login_client = LoginClient(self.cache)
        try:
            gamespace_info = await login_client.find_gamespace(gamespace_name)
        except LoginClientError:
            gamespace_info = None
        return gamespace_info
