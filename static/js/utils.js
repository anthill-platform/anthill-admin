

function notify_progress(message)
{
    return $.notify({
        message: "<i class='fa fa-refresh fa-spin' aria-hidden='true'></i> " + message
    },{
        type: "info",
        placement: {
            from: "bottom",
            align: "center"
        },
        animate: {
            enter: 'animated fadeInUp',
            exit: 'animated fadeOutDown'
        },
        allow_dismiss: false
    });
}

function notify_success(message)
{
    return $.notify({
        message: "<i class='fa fa-check' aria-hidden='true'></i> " + message
    },{
        type: "info",
        placement: {
            from: "bottom",
            align: "center"
        },
        animate: {
            enter: 'animated fadeInUp',
            exit: 'animated fadeOutDown'
        },
        delay: 1500
    });
}

function notify_error(message)
{
    return $.notify({
        message: "<i class='fa fa-times' aria-hidden='true'></i> " + message
    },{
        type: "danger",
        placement: {
            from: "top",
            align: "center"
        },
        animate: {
            enter: 'animated fadeInDown',
            exit: 'animated fadeOutUp'
        },
        delay: 2500
    });
}