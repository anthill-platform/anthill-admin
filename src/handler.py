
import urllib
import ujson
import traceback
import base64
import logging

import tornado.websocket
import tornado.httpclient
import tornado.ioloop

from tornado.gen import coroutine, Return
from tornado.web import HTTPError

from common.handler import AuthCallbackHandler, AuthenticatedHandler
from common.handler import CookieAuthenticatedHandler, CookieAuthenticatedWSHandler

import common.access
import common.discover
import common.admin

from common import cached
from common.access import scoped, AccessToken, parse_scopes
from common.internal import InternalError
from common.discover import DiscoveryError


class AdminAuthCallbackHandler(AuthCallbackHandler):

    def __init__(self, application, request, **kwargs):
        super(AdminAuthCallbackHandler, self).__init__(application, request, **kwargs)
        self.gamespace = ""

    def access_required(self):
        return ["admin"]

    def authorize_error(self, error):
        code = error["result_id"]

        description = {
            "scope_restricted": "This user has no access to the system (not enough rights).",
            "authorize_forbidden": "This user has no access to the system (access forbidden)."
        }

        if code in description:
            code = description[code]

        if "credential" in error:
            code += "<br><br>Credential: {0}".format(error["credential"])

        self.render("template/error.html", title="", description=code)


class AdminHandler(CookieAuthenticatedHandler):
    def __init__(self, application, request, **kwargs):

        super(AdminHandler, self).__init__(
            application,
            request,
            **kwargs)

        self.profile = None
        self.gamespace = None
        self.gamespace_info = {}

    def authorize_as(self):
        return "admin"

    def write_error(self, status_code, **kwargs):
        self.set_status(status_code)

        self.render(
            "template/error.html",
            title=status_code,
            description=traceback.format_exc())

    def external_auth_location(self):
        return self.application.external_auth_location

    def access_restricted(self, scopes=None, ask_also=None):

        if self.gamespace is None:
            self.redirect("/gamespace")
            return

        super(AdminHandler, self).access_restricted(scopes=scopes, ask_also=ask_also)

    def get_gamespace(self):
        if self.gamespace is not None:
            return self.gamespace

        return super(AdminHandler, self).get_gamespace()

    def get_current_user(self):
        current_user = super(AdminHandler, self).get_current_user()
        if current_user is not None:
            current_user.profile = self.profile
        return current_user

    @coroutine
    def prepare(self):

        yield super(AdminHandler, self).prepare()

        self.gamespace = self.get_cookie("gamespace", None)

        if self.gamespace:
            # look up some info
            self.gamespace_info = yield self.application.admin.get_gamespace_info(self.gamespace)

        if self.token is not None:

            try:
                # noinspection PyUnusedLocal
                @cached(kv=self.application.cache,
                        h=lambda: "profile_" + str(self.token.account),
                        ttl=300,
                        json=True)
                @coroutine
                def get_profile():
                    profile_content = yield self.application.internal.get(
                        "profile",
                        "profile/me",
                        {
                            "access_token": self.token.key
                        })

                    raise Return(profile_content)

                profile = yield get_profile()

            except InternalError:
                self.profile = {"name": "Unknown"}
            else:
                self.profile = profile


class DebugConsoleHandler(AdminHandler):
    @coroutine
    @scoped(scopes=["admin"],
            method="access_restricted",
            ask_also=["profile", "profile_write"])
    def get(self):

        # ask discovery where it located externally
        # so console can access it
        discovery = yield common.discover.cache.get_service("discovery", "external")

        self.render(
            "template/console.html",
            discovery_service=discovery,
            gamespace=self.gamespace)


class IndexHandler(AdminHandler):
    @coroutine
    @scoped(scopes=["admin"],
            method="access_restricted",
            ask_also=["profile", "profile_write"])
    def get(self):
        services = self.application.admin
        services_list = yield services.list_services_with_metadata(self.token.key)

        self.render(
            "template/index.html",
            services=services_list)


class SelectGamespaceHandler(AdminHandler):
    @coroutine
    def get(self):
        gamespaces = yield self.application.get_gamespace_list()

        self.render(
            "template/gamespace.html",
            gamespaces=gamespaces,
            selected=self.gamespace)

    @coroutine
    def post(self):
        gamespace = self.get_argument("gamespace")

        self.set_cookie("gamespace", gamespace)

        if self.current_user is not None:
            token = self.current_user.token

            current_gamespace = yield self.application.get_gamespace(gamespace)

            new_gamespace = token.get(AccessToken.GAMESPACE)

            if current_gamespace != new_gamespace:
                self.logout()

        self.redirect("/")


class ServiceAPIHandler(AuthenticatedHandler):
    @coroutine
    @scoped(scopes=["admin"])
    def get(self):

        context = self.get_argument("context", "{}")
        service_id = self.get_argument("service")
        action = self.get_argument("action")

        try:
            context_data = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad 'context' field.")

        try:
            data = yield self.application.internal.get(
                service_id,
                "@admin", {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "access_token": self.current_user.token.key
                })

        except InternalError as e:

            if e.code == 401:
                response = e.response
                scopes = response.headers.get("Need-Scopes", None)

                if scopes is None:
                    raise HTTPError(403, "Forbidden")

                raise HTTPError(403, "Forbidden. Need access: '{0}'.".format(scopes))

            if e.code == 404:
                raise HTTPError(404, "No administration context was found.")

            if e.code == 599:
                raise HTTPError(599, "Service is down.")

            raise HTTPError(e.code, e.body)

        self.dumps(data)

    @coroutine
    @scoped(scopes=["admin"])
    def post(self):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        for field_name, data in self.request.files.iteritems():
            arguments[field_name] = base64.b64encode(data[0]["body"])

        try:
            context = arguments.pop("context")
            method = arguments.pop("method")
            service_id = arguments.pop("service")
            action = arguments.pop("action")
        except KeyError:
            raise HTTPError(400, "Missing fields")

        if "access_token" in arguments:
            del arguments["access_token"]

        try:
            context_data = ujson.loads(context)
        except KeyError:
            raise HTTPError(400, "Corrupted context")
        except ValueError:
            raise HTTPError(400, "Corrupted context")

        output = ujson.dumps(arguments)

        try:
            data = yield self.application.internal.post(
                service_id,
                "@admin", {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "method": method,
                    "data": output,
                    "access_token": self.current_user.token.key
                })

        except InternalError as e:

            if e.code == common.admin.REDIRECT:
                response = e.response
                data = ujson.loads(response.body)

                redirect_to = data["redirect-to"]
                context_data = data["context"]

                redirect_data = {
                    "service": service_id,
                    "action": redirect_to,
                    "access_token": self.current_user.token.key,
                    "context": ujson.dumps(context_data)
                }

                self.redirect("/api?" + urllib.urlencode(redirect_data))
                return

            if e.code == 401:
                response = e.response
                scopes = response.headers.get("Need-Scopes", None)

                if scopes is None:
                    raise HTTPError(403, "Forbidden")

                raise HTTPError(403, "Forbidden. Such access required: '{0}'.".format(scopes))

            raise HTTPError(e.code, e.body)

        self.dumps(data)


class ServiceAdminHandler(AdminHandler):

    def __store_notice__(self, message, kind):
        notice = base64.b64encode(ujson.dumps({
            "kind": kind,
            "message": message
        }))

        self.set_cookie("notice", notice)

    @coroutine
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    def get(self, service_id, action):

        context = self.get_argument("context", "{}")

        try:
            context_data = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad context field.")

        try:
            data = yield self.application.internal.get(
                service_id,
                "@admin",
                {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "access_token": self.current_user.token.key
                })
        except InternalError as e:

            if e.code == 401:

                response = e.response
                scopes = response.headers.get("Need-Scopes", None)

                if scopes is None:
                    raise HTTPError(403, "Forbidden")

                parsed = parse_scopes(scopes)
                self.access_restricted(scopes=parsed)

                return

            if e.code == 404:
                self.render(
                    "template/error.html",
                    title="Cannot administrate this page.",
                    description="Service <span class=\"badge\">{0}</span> has no api "
                                "<span class=\"badge\">{1}</span> to administrate.".format(service_id, action))

                return

            if e.code == common.admin.REDIRECT:
                response = e.response
                data = ujson.loads(response.body)

                redirect_to = data["redirect-to"]
                context_data = data["context"]

                redirect_data = {
                    "context": ujson.dumps(context_data)
                }

                if "notice" in data:
                    self.__store_notice__(data["notice"], "info")

                url = "/service/" + service_id + "/" + redirect_to
                self.redirect(url + "?" + urllib.urlencode(redirect_data))
                return

            if e.code == 599:
                self.render(
                    "template/error.html",
                    title="Service is down.",
                    description="""
                        Service <span class=\"badge\">{0}</span> appears to be down.<br>
                        Please try again later.
                    """.format(service_id))
                return

            if e.code == common.admin.ACTION_ERROR:
                response = e.response
                data = ujson.loads(response.body)
            else:
                raise HTTPError(e.code, e.body)

        services = self.application.admin
        metadata = yield services.get_metadata(service_id, self.token.key) or {}

        notice = self.get_cookie("notice")
        if notice:
            try:
                notice = ujson.loads(base64.b64decode(notice))
            except:
                notice = None

            self.clear_cookie("notice")

        self.render(
            "template/service.html",
            data=data,
            service_id=service_id,
            action=action,
            context=context_data,
            metadata=metadata,
            notice=notice)

    @coroutine
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    def post(self, service_id, action):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        for field_name, data in self.request.files.iteritems():
            arguments[field_name] = base64.b64encode(data[0]["body"])

        try:
            context = arguments.pop("context")
            method = arguments.pop("method")
        except KeyError:
            raise HTTPError(400, "Missing fields")

        try:
            context_data = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad context field.")

        arguments_data = ujson.dumps(arguments)

        try:
            data = yield self.application.internal.post(
                service_id,
                "@admin", {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "method": method,
                    "data": arguments_data,
                    "access_token": self.current_user.token.key
                })
        except InternalError as e:
            do_raise = True
            data = {}

            if e.code == common.admin.REDIRECT:
                response = e.response
                data = ujson.loads(response.body)

                redirect_to = data["redirect-to"]
                context_data = data["context"]

                redirect_data = {
                    "context": ujson.dumps(context_data)
                }

                if "notice" in data:
                    self.__store_notice__(data["notice"], "info")

                url = "/service/" + service_id + "/" + redirect_to
                self.redirect(url + "?" + urllib.urlencode(redirect_data))
                return

            if e.code == common.admin.ACTION_ERROR:
                do_raise = False

                response = e.response
                data = ujson.loads(response.body)

                if not isinstance(data, list):
                    raise HTTPError(500, "Failed to render error")

                try:
                    error = data[0]["title"]
                except IndexError:
                    raise HTTPError(500, "Failed to render error")

                links = data[1] if len(data) > 1 else None

                if not links:
                    referrer = self.request.headers.get("Referer")

                    if referrer:
                        self.__store_notice__(error, "error")
                        self.redirect(referrer)
                        return

            if e.code == 401:
                response = e.response
                scopes = response.headers.get("Need-Scopes", None)

                if scopes is None:
                    raise HTTPError(403, "Forbidden")

                parsed = parse_scopes(scopes)
                self.access_restricted(scopes=parsed)
                return

            if do_raise:
                raise HTTPError(e.code, e.body)

        services = self.application.admin
        metadata = yield services.get_metadata(service_id, self.token.key) or {}

        self.render(
            "template/service.html",
            data=data,
            service_id=service_id,
            action=action,
            context=context_data,
            metadata=metadata,
            notice=None)


class ServiceWSHandler(CookieAuthenticatedWSHandler):
    def __init__(self, application, request, **kwargs):
        super(ServiceWSHandler, self).__init__(application, request, **kwargs)
        self.conn = None
        self.buffer = []

    def check_origin(self, origin):
        return True

    def required_scopes(self):
        return ["admin"]

    def close(self, code=None, reason=None):
        super(ServiceWSHandler, self).close(code, reason)

        logging.error(reason)

    @coroutine
    def prepared(self):
        yield super(ServiceWSHandler, self).prepared()

        service_id = self.get_argument("service")
        context = self.get_argument("context")
        action = self.get_argument("action")

        try:
            context = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted context")

        logging.info("New ws connection to service '{0}'".format(service_id))

        try:
            service_location = yield common.discover.cache.get_service(service_id)
        except DiscoveryError:
            raise HTTPError(500, "Failed to discover service: " + service_id)

        scheme, sep, rest = service_location.partition(':')

        schemes = {
            "http": "ws",
            "https": "wss"
        }

        if scheme not in schemes:
            raise HTTPError(500, "Not supported scheme on child service: " + scheme)

        service_location = schemes[scheme] + ":" + rest

        destination = service_location + "/@stream_admin?" + urllib.urlencode(
            {
                "context": ujson.dumps(context),
                "action": action,
                "access_token": self.token.key
            })

        while True:
            try:
                self.conn = yield tornado.websocket.websocket_connect(
                    destination)
            except tornado.httpclient.HTTPError as e:

                if e.code == common.admin.REDIRECT:
                    response = e.response
                    data = ujson.loads(response.body)

                    action = data["action"]
                    host = data["host"]
                    context = data["context"]

                    destination = "ws://" + host + "/@stream_admin?" + urllib.urlencode({
                        "context": context,
                        "action": action,
                        "access_token": self.token.key
                    })

                    logging.info("Redirecting admin stream to " + destination)

                else:
                    raise HTTPError(e.code, "Failed to connect to service {0} ({1}): {2} {3}.".format(
                         service_id, destination, e.message, e.response.body if e.response else ""))
            else:
                break

    def open(self, *args, **kwargs):
        tornado.ioloop.IOLoop.current().spawn_callback(self.connected)

    @coroutine
    def connected(self):

        for msg in self.buffer:
            self.conn.write_message(msg)

        while True:
            msg = yield self.conn.read_message()
            if msg is None:
                break
            try:
                yield self.write_message(msg)
            except tornado.websocket.WebSocketClosedError:
                break

        self.close(1000, "Service closed connection.")

    def on_message(self, message):

        # messages can be received before connection to the child service is
        # established, so buffer them
        if self.conn is not None:
            tornado.ioloop.IOLoop.current().spawn_callback(self.conn.write_message, message)
        else:
            self.buffer.append(message)

    def on_close(self):
        if self.conn is not None:
            self.conn.close()


