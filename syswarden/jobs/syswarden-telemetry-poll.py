#!/usr/bin/env python3

from json import dumps
from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for syswarden_helpers / syswarden_client).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from logger import setup_logger  # type: ignore
from common_utils import bytes_hash  # type: ignore
from jobs import Job  # type: ignore

from syswarden_helpers import parse_telemetry  # type: ignore
from syswarden_client import call, get_peers, get_timeout, make_session  # type: ignore

LOGGER = setup_logger("SYSWARDEN.TELEMETRY-POLL", getenv("LOG_LEVEL", "INFO"))
status = 0

try:
    if getenv("USE_SYSWARDEN", "no") != "yes":
        LOGGER.info("SysWarden is not activated, skipping telemetry poll...")
        sys_exit(0)

    peers = get_peers(LOGGER)
    timeout = get_timeout()
    session = make_session(LOGGER)
    JOB = Job(LOGGER, __file__)

    entries = []
    for peer in peers:
        got_status, peer_status = call(session, peer, "GET", "/ha/status", timeout=timeout)
        got_telemetry, telemetry = call(session, peer, "GET", "/ha/telemetry", timeout=timeout)

        if not got_status and not got_telemetry:
            LOGGER.error(f"SysWarden peer {peer} is unreachable: {peer_status}")
            entries.append({"peer": peer, "reachable": False})
            status = 2
            continue
        if not got_status:
            LOGGER.warning(f"Can't read the status of {peer}: {peer_status}")
        if not got_telemetry:
            LOGGER.warning(f"Can't read the telemetry of {peer}: {telemetry}")

        entry = {"peer": peer, "reachable": True}
        entry.update(
            parse_telemetry(
                telemetry if isinstance(telemetry, dict) else {},
                peer_status if isinstance(peer_status, dict) else {},
            )
        )
        entries.append(entry)

    # No timestamp in the payload on purpose: the hash guard below is what keeps a
    # minute-ly job from rewriting the cache (which the scheduler ships to every
    # instance) when nothing about the peers changed.
    content = dumps({"peers": entries}, sort_keys=True).encode()
    new_hash = bytes_hash(content)
    if new_hash == JOB.cache_hash("telemetry.json"):
        LOGGER.info("SysWarden telemetry is unchanged, nothing to write")
        sys_exit(status)

    cached, err = JOB.cache_file("telemetry.json", content, checksum=new_hash)
    if not cached:
        LOGGER.error(f"Error while caching telemetry.json: {err}")
        status = 2
    else:
        LOGGER.info(f"Polled {len(entries)} SysWarden peer(s)")
    # Always 0 or 2, never 1: telemetry changes no nginx configuration.
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running syswarden-telemetry-poll.py")

sys_exit(status)
