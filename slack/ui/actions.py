def slack(**kwargs):
    ping = {"ping_status": "unknown"}

    args = kwargs.get("args", False)
    if not args:
        return {**ping}

    is_ping = args.get("ping", False)
    if not is_ping:
        return {**ping}

    # Check ping
    try:
        ping_data = kwargs["app"].config["INSTANCES"].get_ping("slack")
        ping = {"ping_status": ping_data["status"]}
    except:
        ping = {"ping_status": "error"}

    return {**ping}
