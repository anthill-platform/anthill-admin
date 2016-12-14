
SERVICE = null;
EDITOR = null;
TITLE = null;

RENDERERS = {
    error: {
        render: function(data)
        {
            return $('<div class="panel panel-danger">' +
                '<div class="panel-heading">' +
                '<h3 class="panel-title">Error</h3>' +
                '</div>' +
                '<div class="panel-body">' + data.title + '</div></div>');
        }
    },
    notice: {
        render: function(data)
        {
            return $('<div class="panel panel-info">' +
                '<div class="panel-heading">' +
                '<h3 class="panel-title">' + data.title + '</h3>' +
                '</div>' +
                '<div class="panel-body">' + data.text + '</div></div>');
        }
    },
    pages: {
        render: function(data)
        {
            var parent = $('<div align="center"></div>');
            var nav = $('<nav></nav>').appendTo(parent);
            var pag = $('<ul class="pagination"></ul>').appendTo(nav);

            var count = data.count;
            var key = data.key;
            var current_page = CONTEXT[key] || 1;

            var prev_page = Math.max(1, current_page - 1);
            var next_page = Math.min(count, current_page + 1);

            function link(page)
            {
                var ctx = jQuery.extend({}, CONTEXT);
                ctx[key] = page;

                return '/service/' + SERVICE + '/' + ACTION + '?context=' + encodeURIComponent(JSON.stringify(ctx));
            }

            $('<li><a href="' + link(prev_page) + '" aria-label="Previous">' +
                '<span aria-hidden="true">&laquo;</span></a></li>').appendTo(pag);

            for (var i = 1; i <= count; i++)
            {
                $('<li' + (current_page == i ? ' class="active"' : '') +
                    '><a href="' + link(i) + '">' + i + '</a></li>').appendTo(pag);
            }

            $('<li><a href="' + link(next_page) + '" aria-label="Next">' +
                '<span aria-hidden="true">&raquo;</span></a></li>').appendTo(pag);

            return parent;
        }
    },
    script: {
        render: function(data)
        {
            var script = eval(data.script);
            var context = data.context;
            var div = $('<div></div>');

            script(div, context);
            
            return div;
        }
    },
    json_view: {
        render: function(data)
        {
            var contents = eval(data.contents);
            var div = $('<div></div>');

            div.append(new JSONFormatter(contents, 0).render());

            return div;
        }
    },


    file_upload: {
        render: function(data)
        {
            var panel = $('<div class="panel panel-default"><div class="panel-heading">' + data.title + '</div></div>');
            var body = $('<div class="panel-body"></div>').appendTo(panel);

            var div = $('<div><a class="btn btn-default btn-double-space">' +
                '<i class="fa fa-upload" aria-hidden="true"></i> Upload file</a></div>').appendTo(body);

            var status = $('<span></span>').appendTo(div);

            var action = data.action.length > 0 ? data.action : ACTION;

            var btn = div.find("a")[0];

            $(function()
            {
                 var uploader = new ss.SimpleUpload({
                    button: btn,
                    url: '/service/upload?context=' +
                        encodeURIComponent(JSON.stringify(CONTEXT)) + '&service=' + SERVICE +
                        '&action=' + action,
                    method: 'put', responseType: 'json', multipart: false,

                    onSubmit: function()
                    {
                        status.html('<i class="fa fa-refresh fa-spin" aria-hidden="true"></i> Uploading <span></span>...');
                    },
                    onProgress: function(pct)
                    {
                        status.find('span').html(pct + '%');
                    },
                    onComplete: function( filename, response )
                    {
                        status.html('<span class="text-success">' +
                            '<i class="fa fa-check" aria-hidden="true"></i> Uploaded</span>');
                    },
                    onError: function(filename, response, code, error, body)
                    {
                        switch (code)
                        {
                            case 445:
                            {
                                notify_error("Error uploading file: " + body);
                                status.html('<span class="text-danger">' +
                                    '<i class="fa fa-warning" aria-hidden="true"></i> ' + body + '</span>');

                                break;
                            }
                            case 444:
                            {
                                var body = JSON.parse(body);

                                if (body.notice != null)
                                {
                                    Cookies.set("notice", btoa(JSON.stringify({
                                        "kind": "info",
                                        "message": body.notice
                                    })));
                                }

                                var to = body["redirect-to"];
                                var ctx = body["context"];

                                document.location.href = '/service/' + SERVICE + '/' + to +
                                    '?context=' + encodeURIComponent(JSON.stringify(ctx));

                                break;
                            }
                            default:
                            {
                                notify_error("Error uploading file: " + error);
                                status.html('<span class="text-danger">' +
                                    '<i class="fa fa-warning" aria-hidden="true"></i> ' + error + '</span>');
                            }
                        }

                    }
                 });
            });

            return panel;
        }
    },

    link: {
        render: function(data)
        {
            var div = $('<ul class="nav nav-pills"></ul>');
            div.append(render_link(data));
            return div;
        }
    },
    status: {
        render: function(data)
        {
            var div = $('<div></div>');

            var icon = data.icon;
            var style = data.style || "primary";

            $('<span class="label label-' + style + '">' +
                (icon != null ? ('<i class="fa fa-' + icon + '" aria-hidden="true"></i> ') : '') +
                data.title + '</span>').appendTo(div);

            return div;
        }
    },

    button: {
        render: function(data)
        {
            var url = '/service/' + SERVICE + '/' + data.url;
            var context = JSON.stringify(data.context);
            var query = '?context=' + encodeURIComponent(context);

            var form = $('<form enctype="multipart/form-data" method="GET" style="float: left;"></form>');

            var button = $('<button type="submit" href="#" ' +
                'class="btn btn-' + data.style + ' btn-space">' + data.title + '</button>').appendTo(form);

            if (data.method == "get")
            {
                form.attr('action', url);
                button.attr({
                    name: 'context',
                    value: context
                });
            }
            else
            {
                form.attr({
                    method: 'POST',
                    action: url + query
                });
                button.attr({
                    name: 'method',
                    value: data.method
                })
            }

            if (data.style == "danger")
            {
                button.click(function ()
                {
                   return confirm("Are you sure? This cannot be undone!");
                });
            }

            return form;
        }
    },
    content: {
        render: function(data)
        {
            var panel = $('<div class="panel panel-default"><div class="panel-heading">' + data.title + '</div></div>');
            var body = $('<div class="panel-body"></div>').appendTo(panel);

            var table = $('<table class="table table-striped"></table>').appendTo(body);

            var headers = data["headers"];
            var items = data["items"];
            var context = data["context"];

            var process_item = function(d)
            {
                if (typeof d == "object")
                {
                    var parent = $('<div style="float: left;"></div>');

                    render(parent, d);

                    return parent;
                }

                return $('<span>' + d + '</span>');
            };

            var thead = $('<thead></thead>').appendTo(table);
            var tbody = $('<tbody></tbody>').appendTo(table);

            var tr = $('<tr></tr>').appendTo(thead);
            for (var i in headers)
            {
                var header = headers[i];

                var td = $('<th class="th-notop"></th>').appendTo(tr);

                if (header.width)
                {
                    td.attr("width", header.width);
                }

                td.append(process_item(header["title"]));
            }

            if (items.length > 0)
            {
                for (var it in items)
                {
                    var item = items[it];

                    tr = $('<tr></tr>').appendTo(tbody);
                    for (i in headers)
                    {
                        var h = headers[i];
                        var id = h["id"];

                        td = $('<td nowrap="nowrap" style="vertical-align: middle;"></td>').appendTo(tr);
                        td.append(process_item(item[id]));
                    }
                }
            }
            else
            {
                tbody.append('<tr><td colspan="100">' +
                    '<h4 align="center">' + (context["empty"] || "No items to display") + '</h4></td></tr>');
            }


            //var items = data["items"];
            //render(bodyContent, items);

            return panel;
        }
    },
    form: {
        types: {
            text: function(name, value, data)
            {
                if (data.multiline)
                {
                    return $('<textarea class="form-control" rows="' + data.multiline + '" id="' + name + '" name="' +
                        name + '">' + value + '</textarea>');
                }

                return $('<input type="text" class="form-control" id="' + name + '" name="' + name + '" value="' + value +
                    '">');
            },
            status: function(name, value, data)
            {
                return RENDERERS["status"].render({
                    title: value,
                    icon: data.icon,
                    style: data.style
                });
            },
            switch: function(name, value, data)
            {
                var row  = $('<div class="form-group"></div>');
                var checked = value == 'true';
                var readonly = data["readonly"];
                $('<input type="checkbox" class="switch" id="' + name + '" name="' + name + '" ' +
                    'value="true"' + (checked ? ' checked' : '') + (readonly ? ' readonly' : '') + '>').appendTo(row);
                return row;
            },
            date: function(name, value, data)
            {
                var row  = $('<div class="row"></div>');
                var parent = $('<div class="col-sm-6"></div>').appendTo(row);
                var root = $('<div class="form-group"></div>').appendTo(parent);
                var ig = $('<div class="input-group date"></div>').appendTo(root);

                var d = $('<input type="text" class="form-control" id="' + name + '" name="' + name + '" value="' + value +
                    '">').appendTo(ig);

                $('<span class="input-group-addon"><i class="fa fa-calendar" aria-hidden="true"></i></span>').
                    appendTo(ig);

                ig.datetimepicker({
                    sideBySide: true,
                    format: 'YYYY-MM-DD HH:mm:ss'
                });

                return row;
            },
            kv: function(name, value, data)
            {
                var row  = $('<div class="row"></div>');
                var parent = $('<div class="col-sm-6"></div>').appendTo(row);
                var root = $('<div class="form-group"></div>').appendTo(parent);
                var hidden = $('<input type="hidden" name="' + name + '" value="' + value + '">').appendTo(root);
                var values = data.values;

                var items = value;

                var updated = function()
                {
                    var data = {};

                    root.find('.input-group').each(function()
                    {
                        var key = $(this).find('.selectpicker').val();
                        var value = $(this).find('.the-value').val();

                        data[key] = value;
                    });

                    hidden.attr('value', JSON.stringify(data));
                };

                var add_item = function(key, value)
                {
                    var group = $('<div class="input-group input-space"></div>').appendTo(root);
                    var key_input = $('<select class="selectpicker input-kv" data-none-selected-text="Select" ' +
                    'data-live-search="true"></select>').appendTo(group);

                    for (var val_key in values)
                    {
                        var val_title = values[val_key];
                        var option = $('<option value="' + val_key + '">' + val_title + '</option>').appendTo(key_input);
                        if (key == val_key)
                        {
                            option.attr('selected', 'selected');
                        }
                    }

                    var value_input = $('<input type="text" class="form-control the-value" value="' + value + '">').appendTo(group);
                    var delete_button = $('<span class="input-group-btn"><a href="#" class="btn btn-default">' +
                        '<i class="fa fa-remove" aria-hidden="true"></i></a></span>').appendTo(group);

                    key_input.selectpicker();

                    key_input.on('change', updated);
                    value_input.on('change', updated);

                    delete_button.click(function()
                    {
                        group.remove();
                        updated();

                        return false;
                    });

                    updated();
                };

                var btn_add = $('<div style="clear: both;" class="input-space"><a href="#" class="btn btn-default">' +
                    '<i class="fa fa-plus" aria-hidden="true"></i></a></div>').appendTo(root);

                btn_add.find('a').click(function()
                {
                    add_item('', '1');

                    return false;
                });

                for (var key in items)
                {
                    var value = items[key];

                    add_item(key, value);
                }

                return row;
            },
            notice: function(name, value, data)
            {
                return $('<span class="text-' + data["style"] + '">' + value + '</span>');
            },
            readonly: function(name, value, data)
            {
                return $('<input type="text" class="form-control" value="' + value + '" readonly>');
            },
            file: function(name, value, data)
            {
                return $('<input type="file" class="form-control" id="' + name + '" name="' + name + '">');
            },
            code: function(name, value, data)
            {
                var parent = $('<div></div>');

                var fullscreen = $('<ul class="nav nav-pills" style="position: absolute; ' +
                    ' margin-left: -72px;"><li role="presentation"><a href="#">' +
                    '<i class="fa fa-arrows-alt" aria-hidden="true"></i></a></li></ul>').appendTo(parent);

                var height = data.height || 500;

                var e = $('<div class="well full-screen-ready" style="background: none; height: ' + height + 'px;"></div>').appendTo(parent);
                var d = $('<input type="hidden" name="' + name + '" value=""/>').appendTo(parent);

                var buttons = $('<div></div>').appendTo(parent);

                var target = e[0];
                var flask = new CodeFlask;
                flask.scaffold(target, false, { language: 'javascript' });

                fullscreen.click(function()
                {
                    var element = target;

                    if (element.requestFullscreen) {
                      element.requestFullscreen();
                    } else if (element.mozRequestFullScreen) {
                      element.mozRequestFullScreen();
                    } else if (element.webkitRequestFullscreen) {
                      element.webkitRequestFullscreen(Element.ALLOW_KEYBOARD_INPUT);
                    } else if (element.msRequestFullscreen) {
                      element.msRequestFullscreen();
                    }

                    return false;
                });


                flask.update(value);

                flask.onUpdate(function(code)
                {
                   d.val(code);
                });

                d.val(value);

                return parent;
            },
            json: function(name, value, data)
            {
                var parent = $('<div></div>');

                var height = data.height || 500;

                var e = $('<div style="height: ' + height + 'px;"></div>').appendTo(parent);
                var d = $('<input type="hidden" name="' + name + '" value=""/>').appendTo(parent);

                // create the editor
                var container = e[0];
                var editor = new JsonEditor(container, {
                    "name": "contents",
                    "modes": ["tree", "text", "view", "form", "code"],
                    "mode": "code",
                    "indentation": 4,
                    "onChange": function()
                    {
                       d.val(editor.getText());
                    }
                });

                d.val(JSON.stringify(value));

                try
                {
                    editor.set(value);
                }
                catch (e)
                {
                    //
                }

                return parent;
            },
            dorn: function(name, value, data)
            {
                var parent = $('<div class="well well-sm"></div>');

                var e = $('<div></div>').appendTo(parent);
                var d = $('<input type="hidden" name="' + name + '" value=""/>').appendTo(parent);

                // create the editor
                var container = e[0];

                var dorn_editor = new DornEditor(
                    container,
                    {
                        schema: data.schema,
                        disable_collapse: true,
                        no_additional_properties: true,
                        required_by_default: true,
                        theme: 'bootstrap3',
                        iconlib: 'bootstrap3',
                        startval: value
                    }
                );
                dorn_editor.on('change', function() {
                    d.val(JSON.stringify(dorn_editor.getValue()));
                });

                return parent;
            },
            select: function(name, value, data)
            {
                var parent = $('<div></div>');
                var values = data.values;

                var select = $('<select class="selectpicker" data-none-selected-text="Select" ' +
                    'data-live-search="true" id="' + name + '" name="' +
                    name + '">').appendTo(parent);

                for (var i in values)
                {
                    select.append('<option value="' + i + '" ' +
                        (i == value ? ' selected="selected"' : '') + '>' + values[i] + '</option>');
                }

                return parent;
            },
            hidden: function(name, value, data)
            {
                return $('<input type="hidden" class="form-control" id="' + name + '" name="' + name + '" value="' + value +
                    '">');
            },
            tags: function(name, value, data)
            {
                return $('<br><input type="text" data-role="tagsinput" tag-class="label label-danger" ' +
                    'class="tags form-control" id="' + name + '" name="' +
                    name + '" value="' + value + '"' +
                        (data.placeholder != null ? ' placeholder="' + data.placeholder + '"': '') + '>');
            }
        },
        validators:
        {
            "non-empty": function(node)
            {
                node.attr("required", "required");
            },
            "number": function(node)
            {
                node.attr("type", "number");
                node.attr("required", "required");
            }
        },
        render: function(data)
        {
            var context = data["context"];
            var icon = data["icon"];
            $.extend(context, CONTEXT);

            var form_class = '';

            if (context.inline)
            {
                form_class += "form-inline"
            }

            var panel = $('<div class="panel panel-default"><div class="panel-heading">' +
                (icon != null ? ('<i class="fa fa-' + icon + '" aria-hidden="true"></i> ') : '') + data.title + '</div></div>');
            var form = $('<form enctype="multipart/form-data" role="form" method="POST" data-toggle="validator" action="?context=' +
                encodeURIComponent(JSON.stringify(context)) + '" class="' + form_class + '"></form>').appendTo(panel);

            if (data["callback"])
            {
                var callback = data["callback"];
                form.submit(function(e)
                {
                    var values = {};
                    $.each($(form).serializeArray(), function(i, field) {
                        values[field.name] = field.value;
                    });

                    return callback(values);
                });
            }

            var fields = data["fields"];
            var methods = data["methods"];
            var has_body = Object.getOwnPropertyNames(fields).length > 0;

            var fields_array = [];
            var methods_array = [];

            for (var name in fields)
            {
                var field = fields[name];
                fields_array.push({
                    "name": name,
                    "field": field
                })
            }

            for (var name in methods)
            {
                var method = methods[name];
                methods_array.push({
                    "name": name,
                    "method": method
                })
            }

            fields_array.sort(function(ao, bo)
            {
                var a = ao["field"];
                var b = bo["field"];

                var orderA = a.hasOwnProperty("order") ? a.order : ao["name"];
                var orderB = b.hasOwnProperty("order") ? b.order : bo["name"];

                return orderA > orderB ? 1 : -1;
            });

            methods_array.sort(function(ao, bo)
            {
                var a = ao["method"];
                var b = bo["method"];

                var orderA = a.hasOwnProperty("order") ? a.order : ao["name"];
                var orderB = b.hasOwnProperty("order") ? b.order : bo["name"];

                return orderA > orderB ? 1 : -1;
            });

            if (has_body)
            {
                var body = $('<div class="panel-body"></div>').appendTo(form);

                for (var i in fields_array)
                {
                    var fo = fields_array[i];
                    var name = fo["name"];
                    var field = fo["field"];
                    var title = field.title;
                    var value = field.value != undefined ? field.value : "";
                    var validation = field["validation"];
                    var type = field["type"];

                    var f = this.types[type](name, value, field);

                    if (validation != null) {
                        this.validators[validation](f);
                    }

                    var node = $('<div class="form-group"></div>');

                    if (title.length > 0)
                    {
                        $('<label for="' + name + '">' + title + '</label>').appendTo(node);
                    }

                    node.append(f);
                    body.append(node).append(" ");
                }
            }

            if (Object.getOwnPropertyNames(methods).length > 0)
            {
                var footer = $('<div class="panel-' + (has_body ? 'footer' : 'body') + '"></div>').appendTo(form);
                var buttons = $('<div></div>').appendTo(footer);

                for (var i in methods_array)
                {
                    var mo = methods_array[i];
                    var name = mo["name"];
                    var method = mo["method"];

                    var button = $('<button type="submit" name="method" value="' + name +
                        '" class="btn btn-space btn-' + method.style + '"' +
                        (method.danger ? ' data-danger="' + method.danger + '"': "") +
                        (method.doublecheck ? ' data-doublecheck="' + method.doublecheck + '"' : "") + '>' +
                        method.title + '</button>');

                    if (method.style == "danger")
                    {
                        button.click(function ()
                        {
                            var danger = $(this).data("danger") || "Are you sure? This cannot be undone!";
                            if (!confirm(danger))
                            {
                                return false;
                            }

                            var doublecheck = $(this).data("doublecheck");

                            if (doublecheck)
                            {
                                function check(well)
                                {
                                    if (well == undefined)
                                        return "";

                                    return well.replace(" ", "").toLowerCase();
                                }

                                if (check(prompt("Please type in '" + doublecheck + "' to confirm.")) !=
                                        check(doublecheck))
                                {
                                    return false;
                                }
                            }

                            return true;
                        });
                    }

                    buttons.append(button);
                }
            }

            return panel;
        }
    },
    split: {
        render: function(data)
        {
            var node = $('<div class="row"></div>');

            var items = data.items;

            for (var i in items)
            {
                var item = items[i];

                render_node(item, $('<div class="col-xs-6"></div>').appendTo(node))
            }

            return node;
        }
    },
    breadcrumbs: {
        render: function(data)
        {
            var breadcrumbs = $('#service-breadcrumbs');

            var links = data.links;

            if (links.length > 0)
            {
                for (var i in links)
                {
                    var link = links[i];
                    var url;
                    var context = link.context;
                    var icon = link.icon;
                    var additional = '';

                    if (link.url) {
                        var m = link.url.match(/\/(\w+)\/(.+)/i);
                        if (m != null) {
                            url = '/service/' + m[1] + '/' + m[2] +
                                (link.context != null ? '?context=' +
                                encodeURIComponent(JSON.stringify(link.context)) : '');

                            additional = ' <span class="badge">' + m[1] + '</span>';
                        }
                        else if (link.url == '@back') {
                            url = 'javascript:history.back()';
                        }
                        else {
                            url = '/service/' + SERVICE + '/' + link.url +
                                (link.context != null ? '?context=' +
                                encodeURIComponent(JSON.stringify(link.context)) : '');
                        }

                        $('<li><a href="' + url + '">' +
                            (icon != null ? ('<i class="fa fa-' + icon + '" aria-hidden="true"></i> ') : '') +
                            link.title + additional + '</a></li>').appendTo(breadcrumbs);
                    }
                    else
                    {
                        $('<li>' + link.title + '</li>').appendTo(breadcrumbs);
                    }
                }
            }

            TITLE = data.title;

            breadcrumbs.append('<li class="active">' + data.title + '</li>');

            return null;
        }
    },
    links: {
        render: function(data)
        {
            var panel = $('<div class="panel panel-default"><div class="panel-heading">' +
                (data.icon != null ? '<i class="fa fa-' + data.icon + '" aria-hidden="true"></i> ' : '') +
                data.title + '</div></div>');
            var body = $('<div class="panel-body"></div>').appendTo(panel);
            var pills = $('<ul class="nav nav-pills"></ul>').appendTo(body);
            var links = data.links;

            if (links.length > 0)
            {
                for (var i in links)
                {
                    var link = render_link(links[i]);
                    link.appendTo(pills);
                }
            }
            else
            {
                $('<span>Empty</span>').appendTo(pills);
            }

            return panel;
        }
    }
};


function render_node(node, appendTo)
{
    if (typeof node == "string")
    {
        appendTo.append(node);
        return;
    }

    var clazz = node.class;

    var renderer = RENDERERS[clazz];

    if (renderer != null)
    {
        appendTo.append(renderer.render(node));
    }
}

function render_link(link)
{
    var url;
    var context = link.context;
    var icon = link.icon;
    var additional = '';
    var badge = link.badge;

    if (link.url.startsWith("http"))
    {
        url = link.url;

        additional = ' <span class="badge">external</span>';
    }
    else
    {
        var m = link.url.match(/\/(\w+)\/(.+)/i);
        if (m != null)
        {
            url = '/service/' + m[1] + '/' + m[2] +
                (link.context != null ? '?context=' +
                encodeURIComponent(JSON.stringify(link.context)) : '');

            additional = ' <span class="badge">' + m[1] + '</span>';
        }
        else if (link.url == '@back')
        {
            url = 'javascript:history.back()';
        }
        else
        {
            url = '/service/' + SERVICE + '/' + link.url +
                (link.context != null ? '?context=' +
                encodeURIComponent(JSON.stringify(link.context)) : '');
        }
    }

    if (additional == '')
    {
        if (badge != undefined)
        {
            additional = ' <span class="badge">' + badge + '</span>';
        }
    }

    return $('<li role="presentation"><a href="' + url + '">' +
        (icon != null ? ('<i class="fa fa-' + icon + '" aria-hidden="true"></i> ') : '') +
        link.title + additional + '</a></li>');
}

function render(root, data)
{
    root.html('');

    for (var i in data)
    {
        var node = data[i];

        render_node(node, root);
    }
}


function init_service(service_id, action, data, context)
{
    SERVICE = service_id;
    ACTION = action;
    CONTEXT = context;

    render($('#root'), data);

    $(".switch").bootstrapSwitch();

    $('.tags').tagsinput({
        tagClass: function(item)
        {
            if (item.endsWith("admin"))
            {
                return 'label label-danger';
            }

            return 'label label-default';
        }
    });

    $('#service-breadcrumbs').popover({
        trigger: "manual",
        placement: "right",
        content: function()
        {
            var url = "/service/" + SERVICE + "/" + ACTION;

            if (context != {})
            {
                url = url + "?context=" + encodeURIComponent(JSON.stringify(context, null, ""))
            }

            var node = $('<a href="#" class="like" data-fade="false" data-like="' + url +
                '" data-title="' + TITLE +
                '"><span></span></a>');

            processLike(node);

            return node;
        },
        html: true, animation:false
    }).on("mouseenter", function () {
        var _this = this;
        $(this).popover("show");
        $(".popover").on("mouseleave", function () {
            $(_this).popover('hide');
        });
    }).on("mouseleave", function () {
        var _this = this;
        setTimeout(function () {
            if (!$(".popover:hover").length) {
                $(_this).popover("hide");
            }
        }, 300);
    });
}