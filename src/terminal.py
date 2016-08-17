#!/usr/bin/env python

import ujson
import sys
import readline
import tornado.ioloop
import tornado.options
import threading
import termcolor
import shlex
import re

import common.discover

from common.internal import Internal, InternalError

from tornado.gen import coroutine, Return, Task

import common.options.default as _opts
from common.options import options, define


KV_FORMAT = re.compile("^(\w+)=(.*)$")

define("run",
       default=None,
       help="Runs a single command and exits the terminal.",
       type=str)

define("file",
       default=None,
       help="Runs commands from the file and exits the terminal.",
       type=str)


def thread_input(callback):
    def __run__(cb):
        result = raw_input(">>> ")
        cb(result)

    thread = threading.Thread(target=__run__, args=(callback,))
    thread.start()
    thread.join()


class Exit(Exception):
    pass


# noinspection PyMethodMayBeStatic
class Terminal(object):
    def __init__(self):
        self.internal = None
        self.terminal = None
        self.ioloop = None

        common.options.parse_env()
        common.options.parse_command_line()

    def input(self):
        return Task(thread_input)

    @coroutine
    def input_notice(self, notice, color=None, default=None):

        if default:
            notice += ": [" + default + "]"

        yield self.log(notice, color=color)
        text = yield self.input()

        if not text:
            raise Return(default)

        raise Return(text)

    @coroutine
    def command(self, command_args):
        args = shlex.split(command_args)

        if not args:
            return

        command = args[0]

        a = []
        kv = {}
        for arg in args[1:]:
            try:
                key, value = arg.split("=")
            except ValueError:
                raise Exception("Arguments should be key=value pairs")

            if key and value:
                kv[key] = value

        if hasattr(self, "cmd_" + command):
            yield getattr(self, "cmd_" + command)(*a, **kv)

    @coroutine
    def loop(self):
        command_args = yield self.input_notice("Enter a command:", color="blue")
        yield self.command(command_args)

    @coroutine
    def cmd_post(self, service=None, url=None, **kwargs):

        if not service or not url:
            yield self.log(" * Error: arguments 'service', 'url' required")
            return

        yield self.log("...")

        try:
            result = yield self.internal.post(service, url, kwargs)
        except InternalError as e:
            yield self.log(" * Error: " + str(e.code) + " " + e.body, color="red")
        else:
            yield self.log("Response:", color="green")
            yield self.log("", color="green")
            yield self.log(ujson.dumps(result, indent=4, escape_forward_slashes=False), color="green")
            yield self.log("", color="green")

    @coroutine
    def cmd_get(self, service=None, url=None, **kwargs):

        if not service or not url:
            yield self.log(" * Error: arguments 'service', 'url' required")
            return

        yield self.log("...")

        try:
            result = yield self.internal.get(service, url, kwargs)
        except InternalError as e:
            yield self.log(" * Error: " + str(e.code) + " " + e.body, color="red")
        else:
            yield self.log("Response:", color="green")
            yield self.log("", color="green")
            yield self.log(ujson.dumps(result, indent=4, escape_forward_slashes=False), color="green")
            yield self.log("", color="green")

    @coroutine
    def cmd_request(self, service=None, method=None, **kwargs):

        if not service or not method:
            yield self.log(" * Error: arguments 'service', 'method' required")
            return

        yield self.log("...")

        try:
            result = yield self.internal.request(service, method, **kwargs)
        except InternalError as e:
            yield self.log(" * Error: " + str(e.code) + " " + e.body, color="red")
        else:
            yield self.log("Response:", color="green")
            yield self.log("", color="green")
            yield self.log(ujson.dumps(result, indent=4, escape_forward_slashes=False), color="green")
            yield self.log("", color="green")

    @coroutine
    def cmd_exit(self, **kwargs):
        raise Exit()

    @coroutine
    def cmd_help(self, **kwargs):
        yield self.log([
            " * This terminal tool is intended to make core configuration to anthill services.",
            "",
            "The format goes as follows: [command] [command arguments]",
            ""
        ])

    @coroutine
    def setup(self):
        discovery_internal = common.discover.cache.discovery_service
        default_external = "http://discovery-dev.anthill.local"
        default_broker = options.internal_broker

        yield self.log("* Discovery internal location: " + discovery_internal)
        external_location = yield self.input_notice(
            "Enter discovery external location (as it goes to the users)", color="blue", default=default_external)
        broker_location = yield self.input_notice(
            "Enter rabbitmq location for the discovery service", color="blue", default=default_broker)

        try:
            self.internal.post(discovery_internal, "@service/discovery/external", {
                "location": external_location
            }, use_json=False, discover_service=False)
            self.internal.post(discovery_internal, "@service/discovery/broker", {
                "location": broker_location
            }, use_json=False, discover_service=False)
        except InternalError as e:
            yield self.log("* Error configuring discovery: " + e.message, color="red")
        else:
            yield self.log("* Discovery configured! Try discover it.", color="yellow")

    @coroutine
    def log(self, data, color=None):
        if isinstance(data, list):
            for item in data:
                yield self.log(item, color=color)
            return

        print termcolor.colored(data, color=color)

    @coroutine
    def main(self):
        yield self.log([
            "*",
            "*    Welcome to the anthill terminal!",
            "*"
        ], color="yellow")

        yield self.log("Type 'exit' to exit.")
        yield self.log("Type 'help' to get help.")

        while True:
            try:
                yield self.loop()
            except Exit:
                break
            except Exception as e:
                yield self.log(" * Error: " + e.message, color="red")

        yield self.stop()

    @coroutine
    def stop(self):
        self.ioloop.stop()

    @coroutine
    def started(self):
        self.internal = Internal()
        common.discover.init()

        if options.run:
            yield self.command(options.run)
            yield self.stop()
            return

        if options.file:
            with (open(options.file)) as f:
                for line in f.readlines():
                    yield self.command(line)

                yield self.stop()
                return

        yield self.main()

    def run(self):
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ioloop.add_callback(self.started)
        self.ioloop.start()

    @coroutine
    def helper_discovery_get_service(self):
        service_id = yield self.input_notice("Enter service ID", default="login")

        raise Return({
            "service_id": service_id
        })

    @coroutine
    def helper_discovery_set_service(self):
        default_service = "login"
        default_network = "internal"
        default_broker = options.internal_broker

        service_id = yield self.input_notice("Enter service ID", default=default_service)
        network = yield self.input_notice("Enter network kind", default=default_network)

        if network == "internal":
            default_location = "http://" + service_id + "-dev.anthill.internal"
        elif network == "external":
            default_location = "http://" + service_id + "-dev.anthill.local"
        elif network == "broker":
            default_location = default_broker
        else:
            default_location = None

        location = yield self.input_notice("Enter network location", default=default_location)

        raise Return({
            "service_id": service_id,
            "network": network,
            "location": location
        })

Terminal().run()
