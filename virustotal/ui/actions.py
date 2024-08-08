from traceback import format_exc


def pre_render(**kwargs):
    pass


def virustotal(app, *args, **kwargs):
    ping = {"ping_status": "unknown"}

    args = kwargs.get("args", False)
    if not args:
        return {**ping}

    is_ping = args.get("ping", False)
    if not is_ping:
        return {**ping}

    # Check ping
    try:
        if "INSTANCES" in app.config:
            ping_data = app.config["INSTANCES"].get_ping("virustotal")
        else:
            ping_data = app.bw_instances_utils.get_ping("virustotal")

        ping = {"ping_status": ping_data["status"]}
    except BaseException:
        error = f"Error while trying to ping virustotal : {format_exc()}"
        print(error, flush=True)
        ping = {"ping_status": "error", "error": error}

    return {**ping}
