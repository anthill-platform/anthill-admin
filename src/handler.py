import urllib
import ujson
import traceback
import base64
import logging
from urlparse import urlsplit

import tornado.websocket
import tornado.httpclient
import tornado.ioloop

from tornado.gen import coroutine, Return, Future, sleep
from tornado.web import HTTPError, stream_request_body, RequestHandler
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.ioloop import IOLoop
from tornado.queues import Queue

from common.handler import AuthCallbackHandler, AuthenticatedHandler
from common.handler import CookieAuthenticatedHandler, CookieAuthenticatedWSHandler

import common.access
import common.discover
import common.admin
import common.discover

from common import cached
from common.access import scoped, AccessToken, parse_scopes
from common.internal import InternalError
from common.discover import DiscoveryError
from common.options import options


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

        self.render("template/error.html", error_title="", error_description=code)


class AdminHandler(CookieAuthenticatedHandler):
    def __init__(self, application, request, **kwargs):

        super(AdminHandler, self).__init__(
            application,
            request,
            **kwargs)

        self.profile = None
        self.gamespace = None
        self.gamespace_info = {}
        self.services_list = None
        self.current_service = None

    def authorize_as(self):
        return "admin"

    def write_error(self, status_code, **kwargs):
        self.set_status(status_code)

        self.render(
            "template/error.html",
            error_title=status_code,
            error_description=traceback.format_exc() if options.debug else traceback.format_exc(0))

    def external_auth_location(self):
        return self.application.external_auth_location

    def need_profile(self):
        return True

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
        admin = self.application.admin

        if self.gamespace:
            # look up some info
            self.gamespace_info = yield admin.get_gamespace_info(self.gamespace)

        if self.token:

            services = self.application.admin

            if self.get_argument("refresh", "0") == "1":
                yield services.clear_cache()
                self.redirect("/")
                return

            gamespace_id = self.token.get(AccessToken.GAMESPACE)

            if self.need_profile():
                try:

                    # noinspection PyUnusedLocal
                    @cached(kv=self.application.cache,
                            h=lambda: "profile_" + str(self.token.account),
                            ttl=300,
                            json=True)
                    @coroutine
                    def get_profile():
                        try:
                            profile_content = yield self.application.internal.request(
                                "profile",
                                "get_my_profile",
                                gamespace_id=gamespace_id,
                                account_id=self.token.account)
                        except InternalError:
                            raise Return({"name": "Unknown"})

                        raise Return(profile_content)

                    profile = yield get_profile()

                except InternalError:
                    self.profile = {"name": "Unknown"}
                else:
                    self.profile = profile

            self.services_list = yield admin.list_services_with_metadata(self.token.key)


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

        self.set_header("X-Api-Context", ujson.dumps(context_data))
        self.set_header("X-Api-Action", ujson.dumps(action))

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

            raise HTTPError(e.code, e.body, reason="Action Error")

        self.dumps(data)

    @coroutine
    @scoped(scopes=["admin"])
    def post(self):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

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
                redirect_service = data.get("redirect-service", service_id)
                context_data = data["context"]

                redirect_data = {
                    "service": redirect_service,
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

            raise HTTPError(e.code, e.body, reason="Action Error")

        self.dumps(data)


@stream_request_body
class ServiceUploadAdminHandler(AdminHandler):
    def __init__(self, application, request, **kwargs):
        super(ServiceUploadAdminHandler, self).__init__(application, request, **kwargs)

        self.chunks = Queue(10)
        self.client = None
        self.send_complete = Future()
        self.content_length = None
        self.filename = ""
        self.bytes_received = 0
        self.context = {}
        self.args = {}

    @coroutine
    def __producer__(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    def need_profile(self):
        return False

    @coroutine
    def data_received(self, chunk):
        self.bytes_received += len(chunk)
        yield self.chunks.put(chunk)

    def write_error(self, status_code, **kwargs):
        RequestHandler.write_error(self, status_code, **kwargs)

    @coroutine
    def upload(self, service_location, action):
        self.client = AsyncHTTPClient()

        request = HTTPRequest(
            url=service_location + "/@admin_upload?" + urllib.urlencode({
                "action": action,
                "access_token": self.token.key,
                "context": ujson.dumps(self.context),
                "args": ujson.dumps(self.args),
            }),
            method="PUT",
            body_producer=self.__producer__,
            headers={
                "Content-Length": self.content_length,
                "X-File-Name": self.filename
            },
            request_timeout=2400)

        try:
            response = yield self.client.fetch(request)
        except Exception as e:
            logging.exception("Failed to upload file to service {0}".format(
                service_location
            ))
            self.send_complete.set_exception(e)
        else:
            self.send_complete.set_result(response)

    @coroutine
    def prepared(self, *args, **kwargs):

        service_id = self.get_argument("service")
        action = self.get_argument("action")
        context = self.get_argument("context", "{}")
        args = self.get_argument("args", "{}")

        try:
            self.args = ujson.loads(args)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad args field.")

        try:
            self.context = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad context field.")

        self.filename = self.request.headers.get("X-File-Name", "")
        self.content_length = self.request.headers.get("Content-Length")

        if not self.content_length:
            raise HTTPError(400, "No content-length")

        try:
            service_location = yield common.discover.cache.get_service(service_id)
        except common.discover.DiscoveryError as e:
            raise HTTPError(e.code, "Failed to discover '{0}': ".format(service_id) + e.message)

        IOLoop.current().add_callback(self.upload, service_location, action)

    @coroutine
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    def put(self):

        if str(self.bytes_received) != str(self.content_length):
            raise HTTPError(400, "Did not receive data as expected")

        yield self.chunks.put(None)

        try:
            response = yield self.send_complete
        except tornado.httpclient.HTTPError as e:
            self.set_status(e.code, e.message)
            self.finish(e.response.body if e.response else None)
        else:
            self.dumps(response)

    @coroutine
    def prepare(self):
        self.request.connection.set_max_body_size(1073741824)
        yield super(ServiceUploadAdminHandler, self).prepare()


class ServiceAdminHandler(AdminHandler):
    def __store_notice__(self, message, kind):
        notice = base64.b64encode(ujson.dumps({
            "kind": kind,
            "message": message
        }))

        self.set_cookie("notice", notice)

    @coroutine
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    def get(self, current_service, action):

        context = self.get_argument("context", "{}")

        try:
            context_data = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad context field.")

        self.current_service = current_service

        try:
            data = yield self.application.internal.get(
                current_service,
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
                    error_title="Cannot administrate this page.",
                    error_description="Service <span class=\"badge\">{0}</span> has no api "
                                      "<span class=\"badge\">{1}</span> to administrate.".format(
                        current_service, action))

                return

            if e.code == common.admin.BINARY_FILE:
                filename = e.response.headers["File-Name"]
                self.set_header("Content-Disposition", "attachment; filename=" + str(filename))
                self.write(e.response.body)
                return

            if e.code == common.admin.REDIRECT:
                response = e.response
                data = ujson.loads(response.body)

                redirect_to = data["redirect-to"]
                redirect_service = data.get("redirect-service", current_service)
                context_data = data["context"]

                redirect_data = {
                    "context": ujson.dumps(context_data)
                }

                if "notice" in data:
                    self.__store_notice__(data["notice"], "info")

                url = "/service/" + redirect_service + "/" + redirect_to
                self.redirect(url + "?" + urllib.urlencode(redirect_data))
                return

            if e.code == 599:
                self.render(
                    "template/error.html",
                    error_title="Service is down.",
                    error_description="""
                        Service <span class=\"badge\">{0}</span> appears to be down.<br>
                        Please try again later.
                    """.format(current_service))
                return

            if e.code == common.admin.ACTION_ERROR:
                response = e.response
                data = ujson.loads(response.body)
            else:
                raise HTTPError(e.code, e.body)

        services = self.application.admin

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
            action=action,
            context=context_data,
            notice=notice)

    def access_restricted(self, scopes=None, ask_also=None):
        ajax = self.get_argument("ajax", "false") == "true"

        if ajax:
            self.set_status(401)
            self.write("Authorization required")
            return

        super(ServiceAdminHandler, self).access_restricted(scopes, ask_also)

    def write_error(self, status_code, **kwargs):
        ajax = self.get_argument("ajax", "false") == "true"

        if ajax:
            self.set_status(status_code)
            self.write(traceback.format_exc() if options.debug else traceback.format_exc(0))
            return

        super(ServiceAdminHandler, self).write_error(status_code, **kwargs)

    @coroutine
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    def post(self, service_id, action):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        try:
            context = arguments.pop("context")
            method = arguments.pop("method")
            ajax = arguments.pop("ajax", "false") == "true"
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
            data = {}

            if ajax:
                self.set_status(e.code, "Error")
                response = e.response
                self.write(response.body)
                return
            else:
                do_raise = True

                if e.code == common.admin.BINARY_FILE:
                    filename = e.response.headers["File-Name"]
                    self.set_header("Content-Disposition: attachment; filename=" + str(filename))
                    self.write(e.response.body)
                    return

                if e.code == common.admin.REDIRECT:
                    response = e.response
                    data = ujson.loads(response.body)

                    redirect_to = data["redirect-to"]
                    redirect_service = data.get("redirect-service", service_id)
                    context_data = data["context"]

                    redirect_data = {
                        "context": ujson.dumps(context_data)
                    }

                    if "notice" in data:
                        self.__store_notice__(data["notice"], "info")

                    url = "/service/" + redirect_service + "/" + redirect_to
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

        if ajax:
            self.dumps(data)
            return

        self.render(
            "template/service.html",
            data=data,
            current_service=service_id,
            action=action,
            context=context_data,
            notice=None)


class ServiceWSHandler(CookieAuthenticatedWSHandler):
    def __init__(self, application, request, **kwargs):
        super(ServiceWSHandler, self).__init__(application, request, **kwargs)
        self.conn = None
        self.chunks = Queue(255)

    def check_origin(self, origin):
        return True

    def required_scopes(self):
        return ["admin"]

    def close(self, code=None, reason=None):
        super(ServiceWSHandler, self).close(code, reason)

        logging.error(reason)

    @coroutine
    def on_opened(self, *args, **kwargs):

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
        except DiscoveryError as e:
            raise HTTPError(e.code, "Failed to discover service: " + service_id)

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
                self.conn = yield tornado.websocket.websocket_connect(destination)
            except tornado.httpclient.HTTPError as e:

                if e.code == common.admin.REDIRECT:
                    response = e.response
                    data = ujson.loads(response.body)

                    action = data["action"]
                    host = data["host"]
                    context = data["context"]

                    parsed = urlsplit(host)
                    protocol = "wss" if parsed.scheme == "https" else "ws"

                    destination = protocol + "://" + parsed.netloc + parsed.path + "/@stream_admin?" + urllib.urlencode(
                        {
                            "context": context,
                            "action": action,
                            "access_token": self.token.key
                        })

                    logging.info("Redirecting admin stream to " + destination)

                else:
                    reason = e.message, e.response.body if e.response else e.message
                    self.close(e.code, str(reason))
                    return
            else:
                yield self.read_messages(service_id, action)
                break

    @coroutine
    def read_messages(self, service_id, action):
        while True:
            message = yield self.conn.read_message()

            if message is None:
                if self.conn.close_code:
                    self.close(self.conn.close_code, self.conn.close_reason)
                else:
                    self.close(500, "Internal Server Error WS on {0}: {1}".format(service_id, action))
                return

            self.write_message(message)

    def on_message(self, message):
        if self.conn is not None:
            self.conn.write_message(message)

    @coroutine
    def on_closed(self):
        logging.info("Service WS connection closed")
        if self.conn is not None:
            self.conn.close(self.close_code, self.close_reason)


class ServiceProxyHandler(AuthenticatedHandler):
    @coroutine
    @scoped(scopes=["admin"])
    def get(self, service_id, path):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        arguments["access_token"] = self.token.key

        try:
            data = yield self.application.internal.get(service_id, path, arguments, network="external")
        except InternalError as e:
            raise HTTPError(e.code, e.body)

        self.dumps(data)

    @coroutine
    @scoped(scopes=["admin"])
    def post(self, service_id, path):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        arguments["access_token"] = self.token.key

        try:
            data = yield self.application.internal.post(service_id, path, arguments, network="external")
        except InternalError as e:
            raise HTTPError(e.code, e.body)

        self.dumps(data)


class IndexHandler(AdminHandler):
    @coroutine
    @scoped(scopes=["admin"],
            method="access_restricted",
            ask_also=["profile", "profile_write"])
    def get(self):
        self.render("template/index.html")
