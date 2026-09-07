from json import loads
from logging import getLogger
from traceback import format_exc


def _peers(db):
    """Peers from the telemetry the poll job cached, or an empty list."""
    raw = db.get_job_cache_file("syswarden-telemetry-poll", "telemetry.json")
    if not raw:
        return []
    payload = loads(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
    peers = payload.get("peers") if isinstance(payload, dict) else None
    return [peer for peer in peers or [] if isinstance(peer, dict)]


def _total(peers, key):
    """Sum one telemetry counter over the peers, ignoring what isn't a number."""
    return sum(peer[key] for peer in peers if isinstance(peer.get(key), (int, float)))


def pre_render(**kwargs):
    """Build the SysWarden status cards shown on the BunkerWeb web UI.

    The ping card reflects the Lua `api()` ping (`POST /syswarden/ping`); the counters come
    from the telemetry `syswarden-telemetry-poll` cached, so rendering never calls a peer.
    """
    logger = getLogger("UI")
    ret: dict = {
        "ping_status": {
            "title": "SYSWARDEN STATUS",
            "value": "error",
            "col-size": "col-12 col-md-6",
            "card-classes": "h-100",
        },
    }
    try:
        ping_data = kwargs["bw_instances_utils"].get_ping("syswarden")
        ret["ping_status"]["value"] = ping_data["status"]
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get syswarden ping: {e}")
        # Never surface the raw exception (it may contain internal URLs / details).
        ret["error"] = "Could not retrieve the plugin status"

    db = kwargs.get("db")
    if not db:
        # No database handle (the caller only asked for the ping): nothing else to show.
        return ret

    try:
        peers = _peers(db)
        # The key prefix is what makes a card render at all: plugin_page.html only draws
        # keys starting with ping_, info_, date_, count_, counter_, top_ or list_, and
        # silently drops everything else. A counter_ card is passed through
        # human_readable_number(), which calls int() on the value, so the "reachable out of
        # total" ratio has to be an info_ card instead.
        counters = (
            ("info_peers_reachable", "PEERS REACHABLE", f"{sum(1 for peer in peers if peer.get('reachable'))}/{len(peers)}"),
            ("counter_kernel_blocked", "BLOCKED (LAYER 3)", _total(peers, "global_blocked")),
            ("counter_geoip_blocked", "GEOIP BLOCKED", _total(peers, "geoip_blocked")),
            ("counter_asn_blocked", "ASN BLOCKED", _total(peers, "asn_blocked")),
            ("counter_waf_banned", "SYSWARDEN WAAP BANS", _total(peers, "waf_total_banned")),
            ("counter_whitelisted", "WHITELISTED IPS", _total(peers, "whitelist_active_ips")),
        )
        for key, title, value in counters:
            ret[key] = {"title": title, "value": value, "col-size": "col-12 col-md-4", "card-classes": "h-100"}
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get syswarden telemetry: {e}")
        ret["error"] = "Could not retrieve the SysWarden telemetry"

    return ret


def syswarden(**kwargs):
    pass
