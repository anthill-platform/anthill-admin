
function WebSocketJsonRPC(url)
{
    /*
        WebSocket JSON-RPC protocol implementation. See http://www.jsonrpc.org/specification
     */
    this.ws = new WebSocket(url);

    this.nextId = 0;
    this.requestHandlers = {};
    this.responseHandlers = {};

    var zis = this;

    this.onclose = function(code, reason){};

    this.onerror = function(){};
    this.onopen = function(){};

    this.write = function(obj)
    {
        this.ws.send(JSON.stringify(obj));
    };

    this.parse_params = function(params)
    {
        if (params == null)
        {
            return [];
        }

        if (params instanceof Array)
        {
            return params;
        }
    
        if (params instanceof Object)
        {
            return [params];
        }

        return params;
    };

    this.serialize_params = function(params)
    {
        if (params.length > 0)
        {
            var first = params[0];

            if (typeof first === 'object')
            {
                return first;
            }

            return params;
        }
        else
        {
            return null;
        }
    };

    this.serialize_error = function(code, message, data)
    {
        var res = {
            "code": code,
            "message": message
        };

        if (data != null)
        {
            res["data"] = data;
        }

        return res;
    };

    this.rpc = function (method)
    {
        var params = this.serialize_params(Array.prototype.slice.call(arguments, 1));
        var to_send = {
            "jsonrpc": "2.0",
            "method": method
        };

        if (params != null)
        {
            to_send["params"] = params
        }

        this.write(to_send);
    };

    this.write_error = function(code, message, data, id)
    {
        var to_write = {
            "jsonrpc": "2.0",
            "error": this.serialize_error(code, message, data)
        };
        if (id != null)
        {
            to_write["id"] = id;
        }
        
        this.write(to_write);

        console.error("Error " + code + ". " + message + (data != null ? ": " + data : ""));
    };
    
    this.write_result = function(result, id)
    {
        this.write({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        });
    };

    this.handle = function (method, callback)
    {
        this.requestHandlers[method] = callback
    };

    this.request = function (method)
    {
        var d = $.Deferred();

        var params = this.serialize_params(Array.prototype.slice.call(arguments, 1));
        var to_send = {
            "jsonrpc": "2.0",
            "id": this.nextId,
            "method": method
        };

        if (params != null)
        {
            to_send["params"] = params
        }

        this.write(to_send);

        this.responseHandlers[this.nextId] = d;
        this.nextId++;

        return d.promise();
    };

    this.ws.onclose = function(evt)
    {
        zis.onclose(evt.code, evt.reason);
    };

    this.ws.onerror = function(evt)
    {

    };

    this.ws.onmessage = function(evt)
    {
        try
        {
            var msg = JSON.parse(evt.data);
        }
        catch (e)
        {
            zis.write_error(-32700, "Parse error");
            return;
        }

        if (!msg.hasOwnProperty("jsonrpc"))
        {
            zis.write_error(-32600, "Invalid Request", "No 'jsonrpc' field.");
            return;
        }

        if (msg["jsonrpc"] != "2.0")
        {
            zis.write_error(-32600, "Bad version of 'jsonrpc': " + msg["jsonrpc"] + ".");
            return;
        }

        var hasId = msg.hasOwnProperty("id") && msg["id"] != null;
        var hasMethod = msg.hasOwnProperty("method") && msg["method"] != null;
        var hasParams = msg.hasOwnProperty("params");
        var hasResult = msg.hasOwnProperty("result");
        var hasError = msg.hasOwnProperty("error");

        var params = hasParams ? zis.parse_params(msg["params"]) : null;
        var method = hasMethod ? msg["method"] : null;
        var id = hasId ? msg["id"] : null;
        var error = hasError ? msg["error"] : null;
        var result = hasResult ? msg["result"] : null;

        if (hasId && hasMethod)
        {
            // a request
            if (zis.requestHandlers.hasOwnProperty(method))
            {
                // call a request
                try
                {
                    var response = zis.requestHandlers[method].apply(zis, params);
                }
                catch (e)
                {
                    zis.write_error(e.code, e.message, e.data, id);
                    return;
                }

                if (response != null)
                {
                    // if a result of callback is a deffered object, then handle it asynchronously
                    if (response.promise)
                    {
                        response.done(function(result)
                        {
                            zis.write_result(result, id);
                        }).fail(function(code, message, data)
                        {
                            zis.write_error(code, message, data, id);
                        });
                    }
                    else
                    {
                        zis.write_result(response, id);
                    }
                }
                else
                {
                    zis.write_error(-32603, "Internal error", "Response cannot be null", id);
                }
            }
            else
            {
                zis.write_error(-32601, "Method not found");
            }
        }
        else if (hasId)
        {
            if (hasError == hasResult)
            {
                zis.write_error(-32600, "Invalid Request", "Should be (only) one 'result' or 'error' field.");
                return;
            }

            // a response

            if (zis.responseHandlers.hasOwnProperty(id))
            {
                var handler = zis.responseHandlers[id];
                delete zis.responseHandlers[id];

                if (hasResult)
                {
                    handler.resolve(result);
                }
                else
                {
                    if (error.hasOwnProperty("code") &&
                        error.hasOwnProperty("message"))
                    {
                        var responseCode = error["code"];
                        var responseMessage = error["message"];
                        var responseData = error.hasOwnProperty("data") ? error["data"] : null;

                        // hasError
                        handler.reject(responseCode, responseMessage, responseData);
                    }
                    else
                    {
                        zis.write_error(-32600, "Invalid Request", "Bad 'error' field.");
                    }
                }
            }
            else
            {
                zis.write_error(-32600, "Invalid Request", "No such handler.", id);
            }
        }
        else if (hasMethod)
        {
            // an rpc
            if (zis.requestHandlers.hasOwnProperty(method))
            {
                zis.requestHandlers[method].apply(zis, params);
            }
        }
        else if (hasError)
        {
            if (error.hasOwnProperty("code") &&
                error.hasOwnProperty("message"))
            {
                var code = error["code"];
                var message = error["message"];
                var data = error.hasOwnProperty("data") ? error["data"] : null;

                // hasError
                console.error("Error received: " + code + " " + message + (data != null ? ". " + data : ""));
            }
            else
            {
                zis.write_error(-32600, "Invalid Request", "Bad 'error' field.");
            }
        }
        else
        {
            zis.write_error(-32600, "Invalid Request", "No 'method' nor 'id' field.");
        }
    };

    this.ws.onopen = function(evt)
    {
        zis.onopen()
    };
}

function ServiceJsonRPC(service, action, context)
{
    var proto = location.protocol == "https:" ? "wss:" : "ws:";

    return new WebSocketJsonRPC(proto + "//" +
        location.host + "/ws/service?service=" + SERVICE +
        "&action=" + action +
        "&context=" + encodeURIComponent(JSON.stringify(context)));
}