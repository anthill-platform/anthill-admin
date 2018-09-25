
from anthill.common.options import options
from anthill.common import server, database, access, keyvalue, handler, retry

from . import handler as h
from . import options as _opts

from . model.audit import AuditLogModel
from . model.admin import AdminModel

import logging


class AdminServer(server.Server):
    # noinspection PyShadowingNames
    def __init__(self, db=None):
        super(AdminServer, self).__init__()

        self.cache = keyvalue.KeyValueStorage(
            host=options.cache_host,
            port=options.cache_port,
            db=options.cache_db,
            max_connections=options.cache_max_connections)

        self.db = db or database.Database(
            host=options.db_host,
            database=options.db_name,
            user=options.db_username,
            password=options.db_password)

        self.audit = AuditLogModel(self.db)
        self.admin = AdminModel(self, self.cache)
        self.external_auth_location = None

    def get_auth_callback(self):
        return h.AdminAuthCallbackHandler

    def get_handlers(self):
        return [
            (r"/gamespace", h.SelectGamespaceHandler),

            (r"/ws/service", h.ServiceWSHandler),
            (r"/service/upload", h.ServiceUploadAdminHandler),
            (r"/service/([\w-]+)/([\w-]*)", h.ServiceAdminHandler),
            (r"/proxy/([\w-]+)/?(.*)", h.ServiceProxyHandler),
            (r"/api", h.ServiceAPIHandler),

            (r"/debug", h.DebugConsoleHandler),
            (r"/logout", handler.LogoutHandler)
        ]

    def get_admin(self):
        return {
            "audit": h.AuditLogHandler
        }

    def get_root_handler(self):
        return h.IndexHandler

    async def started(self):
        await super(AdminServer, self).started()

        @retry(operation="locate auth external", max=5, delay=5)
        async def locate():
            return await self.get_auth_location("external")

        self.external_auth_location = await locate()

        if self.external_auth_location is None:
            logging.error("Failed to locate auth 'external'.")
        else:
            logging.info("Located auth service: {0}".format(self.external_auth_location))


if __name__ == "__main__":
    stt = server.init()
    access.AccessToken.init([access.public()])
    server.start(AdminServer)
