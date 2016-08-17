
function updateLike(item, like_id)
{
    var heart = $(item).find('span');
    var fadeOut = $(item).data("fade");

    heart.removeClass("glyphicon-star").
          removeClass("glyphicon-star-empty").
          removeClass("glyphicon").
          removeClass("grayed-out");

    heart.addClass(getLike(like_id) ? "glyphicon glyphicon-star":
        ((fadeOut ? ("grayed-out " ) : ("")) + "glyphicon glyphicon-star-empty"));
}

function getLikes()
{
    return Cookies.getJSON("likes") || {};
}

function getLike(like_id)
{
    var likes = getLikes();
    if (likes.hasOwnProperty(like_id))
    {
        return likes[like_id];
    }

    return null;
}

function setLike(like_id, value)
{
    var likes = getLikes();
    likes[like_id] = value;
    Cookies.set("likes", likes);
}

function processLike(item)
{
    var like_id = $(item).data("like");
    updateLike(item, like_id);

    $(item).click(function()
    {
        var like_id = $(item).data("like");
        var title = $(item).data("title");

        if (getLike(like_id))
        {
            setLike(like_id, null);
            updateLike(item, like_id);
        }
        else
        {
            bootbox.prompt({
                title: "Like as",
                value: title,
                callback: function(result)
                {
                    if (result === null)
                        return;

                    setLike(like_id,
                    {
                        "title": result || title
                    });
                    updateLike(item, like_id);
                }
            });
        }

        return false;
    });
}

$(function()
{
    $('.like').each(function()
    {
        processLike(this);
    });

    $('.likes-list').popover({
        trigger: "manual",
        placement: "bottom",
        content: function()
        {
            var likes = getLikes();
            var valid = false;
            var node = $("<div class='like-heading list-group like-group'></div>");

            for (var url in likes)
            {
                if (likes[url])
                {
                    var like = likes[url];
                    var title = like["title"];
                    valid = true;
                    var item = $("<a class='list-group-item' href='" + url + "'></a>").appendTo(node);
                    var likeItem = $('<a href="#" id="service-like" class="like" ' +
                        'data-like="' + url + '"data-title="' + title + '"> <span></span></a>').appendTo(item);
                    processLike(likeItem);
                    item.append(" " + title);
                }
            }

            if (!valid)
            {
                return null;
            }

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
});