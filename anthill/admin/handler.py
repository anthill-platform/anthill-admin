from urllib import parse

import tornado.websocket
import tornado.httpclient
import tornado.ioloop

from tornado.gen import Future
from tornado.web import HTTPError, stream_request_body, RequestHandler
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.ioloop import IOLoop
from tornado.queues import Queue

from anthill.common.handler import AuthCallbackHandler, AuthenticatedHandler
from anthill.common.handler import CookieAuthenticatedHandler, CookieAuthenticatedWSHandler
from anthill.common.login import LoginClient, LoginClientError

from anthill.common import admin, discover, cached
from anthill.common.access import scoped, AccessToken, parse_scopes
from anthill.common.internal import InternalError, Internal
from anthill.common.discover import DiscoveryError
from anthill.common.options import options

from .model.audit import AuditLogError

import anthill.common.admin as a

import ujson
import traceback
import base64
import logging
import math


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

    async def prepare(self):
        await super(AdminHandler, self).prepare()

        self.gamespace = self.get_cookie("gamespace", None)
        admin_model = self.application.admin

        if self.gamespace:
            # look up some info
            self.gamespace_info = await admin_model.get_gamespace_info(self.gamespace)

        if self.token:

            services = self.application.admin

            if self.get_argument("refresh", "0") == "1":
                await services.clear_cache()
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
                    async def get_profile():
                        try:
                            profile_content = await Internal().request(
                                "profile",
                                "get_my_profile",
                                gamespace_id=gamespace_id,
                                account_id=self.token.account)
                        except InternalError:
                            return {"name": "Unknown"}

                        return profile_content

                    profile = await get_profile()

                except InternalError:
                    self.profile = {"name": "Unknown"}
                else:
                    self.profile = profile

            self.services_list = await admin_model.list_services_with_metadata(self.token.key)


class DebugConsoleHandler(AdminHandler):
    @scoped(scopes=["admin"],
            method="access_restricted",
            ask_also=["profile", "profile_write"])
    async def get(self):
        # ask discovery where it located externally
        # so console can access it
        discovery = await discover.cache.get_service("discovery", "external")

        self.render(
            "template/console.html",
            discovery_service=discovery,
            gamespace=self.gamespace)


class SelectGamespaceHandler(AdminHandler):
    async def get(self):

        login_client = LoginClient(self.application.cache)

        try:
            gamespaces = await login_client.get_gamespaces()
        except LoginClientError as e:
            raise a.ActionError(e.message)

        self.render(
            "template/gamespace.html",
            gamespaces=gamespaces,
            selected=self.gamespace)

    async def post(self):
        gamespace = self.get_argument("gamespace")

        self.set_cookie("gamespace", gamespace)

        if self.current_user is not None:
            token = self.current_user.token

            login_client = LoginClient(self.application.cache)

            try:
                current_gamespace = await login_client.find_gamespace(gamespace)
            except LoginClientError as e:
                raise HTTPError(e.code, e.message)

            current_gamespace_id = current_gamespace.gamespace_id

            new_gamespace = token.get(AccessToken.GAMESPACE)

            if current_gamespace_id != new_gamespace:
                self.logout()

        self.redirect("/")


class ServiceAPIHandler(AuthenticatedHandler):
    @scoped(scopes=["admin"])
    async def get(self):

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
            data = await Internal().get(
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

    @scoped(scopes=["admin"])
    async def post(self):

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
            data = await Internal().post(
                service_id,
                "@admin", {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "method": method,
                    "data": output,
                    "access_token": self.current_user.token.key
                })

        except InternalError as e:
            if e.code == admin.REDIRECT:
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

                self.redirect("/api?" + parse.urlencode(redirect_data))
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

    async def __producer__(self, write):
        while True:
            chunk = await self.chunks.get()
            if chunk is None:
                return
            await write(chunk)

    def need_profile(self):
        return False

    async def data_received(self, chunk):
        self.bytes_received += len(chunk)
        await self.chunks.put(chunk)

    def write_error(self, status_code, **kwargs):
        RequestHandler.write_error(self, status_code, **kwargs)

    async def upload(self, service_location, action):
        self.client = AsyncHTTPClient()

        request = HTTPRequest(
            url=service_location + "/@admin_upload?" + parse.urlencode({
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
            response = await self.client.fetch(request)
        except Exception as e:
            logging.exception("Failed to upload file to service {0}".format(
                service_location
            ))
            self.send_complete.set_exception(e)
        else:
            self.send_complete.set_result(response)

    async def prepared(self, *args, **kwargs):

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
            service_location = await discover.cache.get_service(service_id)
        except discover.DiscoveryError as e:
            raise HTTPError(e.code, "Failed to discover '{0}': ".format(service_id) + e.message)

        IOLoop.current().add_callback(self.upload, service_location, action)

    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    async def put(self):

        if str(self.bytes_received) != str(self.content_length):
            raise HTTPError(400, "Did not receive data as expected")

        await self.chunks.put(None)

        try:
            response = await self.send_complete
        except tornado.httpclient.HTTPError as e:
            self.set_status(e.code, e.message)
            self.finish(e.response.body if e.response else None)
        else:
            self.dumps(response)

    async def prepare(self):
        self.request.connection.set_max_body_size(1073741824)
        await super(ServiceUploadAdminHandler, self).prepare()


class ServiceAdminHandler(AdminHandler):
    def __store_notice__(self, message, kind):
        notice = base64.b64encode(ujson.dumps({
            "kind": kind,
            "message": message
        }).encode())

        self.set_cookie("notice", notice)

    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write", "admin_audit_log"])
    async def get(self, current_service, action):

        context = self.get_argument("context", "{}")

        try:
            context_data = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Bad context field.")

        self.current_service = current_service

        try:
            data = await Internal().get(
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
                error_description = "Service <span class=\"badge\">{0}</span> has no api " \
                                    "<span class=\"badge\">{1}</span> to administrate.".format(current_service, action)

                self.render("template/error.html",
                            error_title="Cannot administrate this page.",
                            error_description=error_description)
                return

            if e.code == admin.BINARY_FILE:
                filename = e.response.headers["File-Name"]
                self.set_header("Content-Disposition", "attachment; filename=" + str(filename))
                self.write(e.response.body)
                return

            if e.code == admin.REDIRECT:
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
                self.redirect(url + "?" + parse.urlencode(redirect_data))
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

            if e.code == admin.ACTION_ERROR:
                response = e.response
                data = ujson.loads(response.body)
            else:
                raise HTTPError(e.code, e.body.decode("utf-8"))

        notice = self.get_cookie("notice")
        if notice:
            # noinspection PyBroadException
            try:
                notice = ujson.loads(base64.b64decode(notice))
            except Exception:
                notice = None

            self.clear_cookie("notice")

        self.render(
            "template/service.html",
            data=data,
            action=action,
            context=context_data,
            notice=notice)

    async def __parse_audit__(self, headers, service_name, service_action):
        log = headers.get("Audit-Log", None)
        if not log:
            return

        gamespace_id = self.token.get(AccessToken.GAMESPACE)
        account_id = self.token.account
        audit = self.application.audit

        try:
            unpacked = ujson.loads(log)
        except (KeyError, ValueError):
            logging.exception("Failed to parse audit log")
        else:
            if not isinstance(unpacked, dict):
                return

            action_icon = unpacked.get("icon")
            action_message = unpacked.get("message")
            action_payload = unpacked.get("payload")

            if not action_icon or action_payload is None or not action_message:
                return

            await audit.audit_log(gamespace_id, service_name, service_action, action_icon,
                                  action_message, action_payload, account_id)

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

    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write"])
    async def post(self, service_id, action):

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
            data, headers = await Internal().post(
                service_id,
                "@admin", {
                    "context": ujson.dumps(context_data),
                    "action": action,
                    "method": method,
                    "data": arguments_data,
                    "access_token": self.current_user.token.key
                }, return_headers=True)
        except InternalError as e:
            data = {}

            if e.response is not None:
                await self.__parse_audit__(e.response.headers, service_id, action)

            if ajax:
                self.set_status(e.code, "Error")
                response = e.response
                self.write(response.body)
                return
            else:
                do_raise = True

                if e.code == admin.BINARY_FILE:
                    filename = e.response.headers["File-Name"]
                    self.set_header("Content-Disposition", "attachment; filename=" + str(filename))
                    self.write(e.response.body)
                    return

                if e.code == admin.REDIRECT:
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
                    self.redirect(url + "?" + parse.urlencode(redirect_data))
                    return

                if e.code == admin.ACTION_ERROR:
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
        else:
            await self.__parse_audit__(headers, service_id, action)

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

    async def on_opened(self, *args, **kwargs):

        service_id = self.get_argument("service")
        context = self.get_argument("context")
        action = self.get_argument("action")

        try:
            context = ujson.loads(context)
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted context")

        logging.info("New ws connection to service '{0}'".format(service_id))

        try:
            service_location = await discover.cache.get_service(service_id)
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

        destination = service_location + "/@stream_admin?" + parse.urlencode(
            {
                "context": ujson.dumps(context),
                "action": action,
                "access_token": self.token.key
            })

        while True:
            try:
                self.conn = await tornado.websocket.websocket_connect(destination)
            except tornado.httpclient.HTTPError as e:

                if e.code == admin.REDIRECT:
                    response = e.response
                    data = ujson.loads(response.body)

                    action = data["action"]
                    host = data["host"]
                    context = data["context"]

                    parsed = parse.urlsplit(host)
                    protocol = "wss" if parsed.scheme == "https" else "ws"

                    destination = protocol + "://" + parsed.netloc + parsed.path + "/@stream_admin?" + parse.urlencode(
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
                await self.read_messages(service_id, action)
                break

    async def read_messages(self, service_id, action):
        while True:
            message = await self.conn.read_message()

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

    async def on_closed(self):
        logging.info("Service WS connection closed")
        if self.conn is not None:
            self.conn.close(self.close_code, self.close_reason)


class ServiceProxyHandler(AuthenticatedHandler):
    @scoped(scopes=["admin"])
    async def get(self, service_id, path):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        arguments["access_token"] = self.token.key

        try:
            data = await Internal().get(service_id, path, arguments, network="external")
        except InternalError as e:
            raise HTTPError(e.code, e.body)

        self.dumps(data)

    @scoped(scopes=["admin"])
    async def post(self, service_id, path):

        arguments = {
            k: self.get_argument(k)
            for k in self.request.arguments
        }

        arguments["access_token"] = self.token.key

        try:
            data = await Internal().post(service_id, path, arguments, network="external")
        except InternalError as e:
            raise HTTPError(e.code, e.body)

        self.dumps(data)


class IndexHandler(AdminHandler):
    @scoped(scopes=["admin"], method="access_restricted", ask_also=["profile", "profile_write", "admin_audit_log"])
    async def get(self):
        self.render("template/index.html")


class AuditLogHandler(a.AdminController):
    ENTRIES_PER_PAGE = 50

    async def get(self, page=1):
        audit = self.application.audit

        offset = (int(page) - 1) * AuditLogHandler.ENTRIES_PER_PAGE
        limit = AuditLogHandler.ENTRIES_PER_PAGE

        try:
            entries, total_count = await audit.list_paged_count(self.gamespace, offset=offset, limit=limit)
        except AuditLogError as e:
            raise a.ActionError(e.message)

        pages = int(math.ceil(float(total_count) / float(AuditLogHandler.ENTRIES_PER_PAGE)))

        services_list = await self.application.admin.list_services_with_metadata(self.token.key)

        author_ids = set()
        for entry in entries:
            entry.author_name = str(entry.author)

            metadata = services_list.get(entry.service_name, {}).get("metadata", {})

            entry.service_icon = metadata.get("icon", None)
            entry.service_title = metadata.get("title", entry.service_name)

            author_ids.add(entry.author)

        internal = Internal()

        try:
            profiles = await internal.send_request(
                "profile", "mass_profiles",
                accounts=author_ids,
                gamespace=self.gamespace,
                action="get_public",
                profile_fields=["name"])
        except InternalError:
            pass  # well
        else:
            for entry in entries:
                profile = profiles.get(str(entry.author))
                if profile:
                    entry.author_name = profile.get("name")

        return {
            "entries": entries,
            "pages": pages
        }

    def access_scopes(self):
        return ["admin_audit_log"]

    @staticmethod
    def __generate_diff__(entry):
        changes = entry.payload.get("changes")

        return {
            key.replace("_", " ").title(): value
            for key, value in changes.items()
        }

    def render(self, data):
        return [
            a.breadcrumbs([], "Audit Log"),
            a.content(title="Log Entries", headers=[
                {
                    "id": "time",
                    "title": "Time"
                },
                {
                    "id": "service_name",
                    "title": "Service Name"
                },
                {
                    "id": "service_action",
                    "title": "Action"
                },
                {
                    "id": "author",
                    "title": "Author"
                },
                {
                    "id": "info",
                    "title": "Info"
                }
            ], items=[
                {
                    "author": [
                        a.link("/profile/profile", entry.author_name, icon="user", badge="", account=entry.author)
                    ],
                    "service_name": [
                        a.link("/{0}/index".format(entry.service_name), entry.service_title,
                               icon=entry.service_icon, badge="")
                    ],
                    "time": str(entry.date),
                    "service_action": [
                        a.link("/{0}/{1}".format(entry.service_name,
                                                 entry.service_action),
                               entry.message, icon=entry.icon, badge="", **entry.payload.get("context", {}))
                    ],
                    "info": [
                        a.json_view(AuditLogHandler.__generate_diff__(entry))
                    ]
                }
                for entry in data["entries"]
            ], style="default"),
            a.pages(data["pages"])
        ]
