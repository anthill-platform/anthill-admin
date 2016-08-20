
SERVICES = {};
CURRENT_SERVICE = null;
DISCOVERY_SERVICE = null;
CURRENT_GAMESPACE = null;

function console_init(discovery_service, gamespace)
{
    CURRENT_GAMESPACE = gamespace;
    DISCOVERY_SERVICE = discovery_service;
    SERVICES["discovery"] = discovery_service;
}

function def()
{
    return $.Deferred();
}

function ask(f, defaultValue, ifEmpty)
{
    var d = def();

    if (defaultValue == null)
    {
        var consoleInput = $('#console-input');

        var placeholder = consoleInput.attr("placeholder");

        consoleInput.attr("placeholder", f);
        sandbox.setValue("");

        sandbox.model.input(function(command)
        {
            if (command != "")
            {
                sandbox.model.addHistory({
                    "command": command,
                    "result": f,
                    "_hidden": true
                });
            }
            if (ifEmpty != null && command == "")
            {
                command = ifEmpty;
            }
            consoleInput.attr("placeholder", placeholder)
            d.resolve(command);
        });
    }
    else
    {
        d.resolve(defaultValue);
    }


    return d.promise();
}

function extend_fields(fields)
{
    fields["access_token"] = Cookies.get("console_access_token");

    return fields;
}

function http_get(url, fields)
{
    var d = def();

    $.get(url, fields, function(data)
    {
        d.resolve(data);
    }).fail(function(req, textStatus, error) {
        d.reject(textStatus + ": " + error + ":\n" + req.responseText);
    });

    return d.promise();
}

function http_post(url, fields)
{
    var d = def();

    $.post(url, fields, function(data)
    {
        d.resolve(data);
    }).fail(function(req, textStatus, error) {
        d.reject(textStatus + ": " + error + ":\n" + req.responseText);
    });

    return d.promise();
}

function http_delete(url, fields)
{
    var d = def();

    $.ajax({
        url: url,
        type: 'DELETE',
        data: fields,
        success: function (data)
        {
            d.resolve(data);
        },
        error: function (req, textStatus, error)
        {
            d.reject(textStatus + ": " + error + ":\n" + req.responseText);
        }
    });

    return d.promise();
}

function render_object(response)
{
    if (typeof response == "object")
    {
        return "JSON:\n" + JSON.stringify(response, null, "    ");
    }

    return response;
}

function discover(service_name)
{
    var d = def();

    http_get(DISCOVERY_SERVICE + "/service/" + service_name, {}).done( function(data) {
        d.resolve(data);
    }).fail(function(e) {
        d.reject(e);
    });

    return d.promise();
}

function parse_fields(fields)
{
    var fs = fields.split("\n");
    var result = {};

    for (var i in fs)
    {
        var field = fs[i];

        var m = field.match(/(\w+)=(.*)/i);

        if (m != null)
        {
            result[m[1]] = m[2];
        }
    }

    return result;
}

commands = {
    service: {
        "usage": "<service_id>",
        "help": "Switch service",
        "f": function (service_name) {
            if (service_name == null) {
                return "Current service: " + CURRENT_SERVICE;
            }

            var d = def();

            discover(service_name).done(function (service_location) {
                SERVICES[service_name] = service_location;
                CURRENT_SERVICE = service_name;

                d.resolve("Switched to '" + CURRENT_SERVICE + "' (" + service_location + ")");
            }).fail(function (e) {
                d.reject("Failed to discover service: " + e);
            });

            return d.promise();
        }
    },
    auth: {
        "service": "login",
        "usage": "<credential> <username> <key> <scopes> <gamespace>",
        "help": "Authorize",
        "f": function (credential, username, key, scopes, gamespace) {

            var d = def();

            ask("Credential ('anonymous', 'dev', 'google', etc)", credential).done(function(credential)
            {
                ask("Username", username).done(function(username)
                {
                    ask("Key (a password)", key).done(function(key)
                    {
                        ask("Scopes of access (comma-separated):", scopes).done(function(scopes)
                        {
                            ask("Gamespace (leave empty for current)", gamespace, CURRENT_GAMESPACE).done(function (gamespace)
                            {
                                discover("login").done(function (auth_location)
                                {
                                    http_post(auth_location + '/auth',
                                    {
                                        "credential": credential,
                                        "username": username,
                                        "key": key,
                                        "scopes": scopes,
                                        "gamespace": gamespace
                                    }).done(function (access_token)
                                    {
                                        Cookies.set("console_access_token", access_token);
                                        d.resolve("Authorized! Access token: " + access_token)
                                    }).fail(function (e)
                                    {
                                        d.reject("Failed: " + e);
                                    });
                                });
                            });
                        });
                    });
                });
            });

            return d.promise();
        }
    },

    merge:
    {
        "usage": "<scopes> <gamespace> <should_have>",
        "help": "Launches attach window, using current access token",
        "f": function (scopes, gamespace, should_have)
        {
            var d = def();

            ask("Scopes of access (comma-separated):", scopes, "admin,profile,profile_write").done(function(scopes)
            {
                ask("Gamespace (leave empty for current)", gamespace, CURRENT_GAMESPACE).done(
                function (gamespace)
                {
                    ask("What scopes should be definitely acquired (default admin,profile)?", should_have, 'admin,profile').done(
                    function (should_have)
                    {
                        var token = Cookies.get("console_access_token");

                        if (token == null)
                        {
                            d.reject("Not authorized");
                        }
                        else
                        {
                            discover("login").done(function (service_location)
                            {
                                window.location.href = service_location + '/authform?scopes=' +
                                    encodeURIComponent(scopes) + '&gamespace=' + encodeURIComponent(gamespace) +
                                    '&attach_to=' + encodeURIComponent(token) + '&redirect=' +
                                    encodeURIComponent(window.location.origin + "/callback?after=" +
                                        encodeURIComponent(window.location.pathname)) +
                                    '&should_have=' + encodeURIComponent(should_have);

                                d.resolve("Done");

                            }).fail(function (e) {
                                d.reject("Failed to discover auth service: " + e);
                            });
                        }
                    });
                });
            });

            return d.promise();
        }
    },

    get: {
        "usage": "<path> <http_fields>",
        "help": "HTTP GET request",
        "f": function (path, fields) {
            if (CURRENT_SERVICE == null) {
                throw new Error("Please select service first (service <service_name>)")
            }

            var service_location = SERVICES[CURRENT_SERVICE];

            var d = def();

            ask("Fields, use ctrl+enter to enter few fields", fields, "{}").done(function(fields) {

                try
                {
                    var fields_data = parse_fields(fields);

                    http_get(service_location + "/" + path, extend_fields(fields_data)).done(function (response) {
                        d.resolve(response == "" ? "OK" : render_object(response));
                    }).fail(function (e) {
                        d.reject("Failed: " + e);
                    });
                }
                catch (e)
                {
                    d.reject("Error: " + e)
                }
            });

            return d.promise();
        }
    },

    post: {
        "usage": "<path> <http_fields>",
        "help": "HTTP POST request",
        "f": function (path, fields) {
            if (CURRENT_SERVICE == null) {
                throw new Error("Please select service first (service <service_name>)")
            }

            var service_location = SERVICES[CURRENT_SERVICE];

            var d = def();

            ask("Fields, use ctrl+enter to enter few fields", fields, "{}").done(function(fields) {

                try
                {
                    var fields_data = parse_fields(fields);

                    http_post(service_location + "/" + path, extend_fields(fields_data)).done(function (response) {
                        d.resolve(response == "" ? "OK" : render_object(response));
                    }).fail(function (e) {
                        d.reject("Failed: " + e);
                    });
                }
                catch (e)
                {
                    d.reject("Error: " + e)
                }
            });

            return d.promise();
        }
    },

    delete: {
        "usage": "<path> <http_fields>",
        "help": "HTTP DELETE request",
        "f": function (path, fields) {
            if (CURRENT_SERVICE == null) {
                throw new Error("Please select service first (service <service_name>)")
            }

            var service_location = SERVICES[CURRENT_SERVICE];

            var d = def();

            ask("Fields, use ctrl+enter to enter few fields", fields, "{}").done(function(fields) {

                try
                {
                    var fields_data = parse_fields(fields);

                    http_delete(service_location + "/" + path, extend_fields(fields_data)).done(function (response) {
                        d.resolve(response == "" ? "OK" : response);
                    }).fail(function (e) {
                        d.reject("Failed: " + e);
                    });
                }
                catch (e)
                {
                    d.reject("Error: " + e)
                }
            });

            return d.promise();
        }
    },

    token: {
        "usage": "<optional access token>",
        "help": "Returns access token (Or sets if passed)",
        "f": function(set) {
            if (set == null)
            {
                return Cookies.get("console_access_token");
            }
            else
            {
                Cookies.set("console_access_token", set);
                return "New token: " + set;
            }
        }
    },

    help: {
        "usage": null,
        "help": "This command",
        "f": function() {
            var result = "Possible commands are:";

            for (var id in commands)
            {
                var cmd = commands[id];

                if (cmd["service"] != null)
                {
                    if (cmd["service"] != CURRENT_SERVICE)
                    {
                        continue;
                    }
                }


                result = result + "\n    * " + id + (cmd["usage"] != null ? " " + cmd["usage"] : "")
                    + " - " + cmd["help"];
            }

            return result;
        }
    }
};

$(function()
{
    for (var id in commands)
    {
        window[id] = commands[id]["f"];
    }
});