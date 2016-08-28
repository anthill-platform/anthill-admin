
import logging

from tornado.gen import coroutine
from common.options import options

import common.server
import common.database
import common.access
import common.sign
import common.keyvalue
import common.handler

import handler
import options as _opts

from model.admin import AdminModel
from common import retry


class AdminServer(common.server.Server):
    # noinspection PyShadowingNames
    def __init__(self):
        super(AdminServer, self).__init__()

        self.db = common.database.Database(
            host=options.db_host,
            database=options.db_name,
            user=options.db_username,
            password=options.db_password)

        self.cache = common.keyvalue.KeyValueStorage(
            host=options.cache_host,
            port=options.cache_port,
            db=options.cache_db,
            max_connections=options.cache_max_connections)

        self.admin = AdminModel(self, self.cache)
        self.external_auth_location = None

    def get_auth_callback(self):
        return handler.AdminAuthCallbackHandler

    def get_handlers(self):
        return [
            (r"/gamespace", handler.SelectGamespaceHandler),

            (r"/ws/service", handler.ServiceWSHandler),
            (r"/service/([\w-]+)/([\w-]*)", handler.ServiceAdminHandler),
            (r"/api", handler.ServiceAPIHandler),

            (r"/debug", handler.DebugConsoleHandler),
            (r"/logout", common.handler.LogoutHandler),
            (r"/", handler.IndexHandler),
        ]

    @coroutine
    def started(self):
        yield super(AdminServer, self).started()

        @retry(operation="locate auth external", max=5, delay=5)
        def locate():
            return self.get_auth_location("external")

        self.external_auth_location = yield locate()

        if self.external_auth_location is None:
            logging.error("Failed to locate auth 'external'.")
        else:
            logging.info("Located auth service: " + self.external_auth_location)


if __name__ == "__main__":

    stt = common.server.init()
    common.access.AccessToken.init([common.access.public()])
    common.server.start(AdminServer)
