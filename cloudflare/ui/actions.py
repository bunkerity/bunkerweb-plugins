from logging import getLogger
from traceback import format_exc


def pre_render(**kwargs):
    """Build the Cloudflare plugin status card shown on the BunkerWeb web UI.

    Reflects the result of the Lua `api()` ping (`POST /cloudflare/ping`), which reports
    that the plugin is up and how many Cloudflare trusted ranges are loaded.
    """
    logger = getLogger("UI")
    ret = {
        "ping_status": {
            "title": "CLOUDFLARE STATUS",
            "value": "error",
            "col-size": "col-12 col-md-6",
            "card-classes": "h-100",
        },
    }
    try:
        ping_data = kwargs["bw_instances_utils"].get_ping("cloudflare")
        ret["ping_status"]["value"] = ping_data["status"]
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get cloudflare ping: {e}")
        # Never surface the raw exception (it may contain internal URLs / details).
        ret["error"] = "Could not retrieve the plugin status"

    return ret


def cloudflare(**kwargs):
    pass
