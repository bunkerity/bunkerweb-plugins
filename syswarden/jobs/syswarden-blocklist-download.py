#!/usr/bin/env python3

from contextlib import suppress
from json import loads
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

from syswarden_helpers import check_line, parse_telemetry  # type: ignore
from syswarden_client import call, extract_ips, get_peers, get_timeout, make_session  # type: ignore

LOGGER = setup_logger("SYSWARDEN.BLOCKLIST-DOWNLOAD", getenv("LOG_LEVEL", "INFO"))
status = 0


def any_service_uses(setting: str) -> bool:
    """True when at least one service enables `setting` (multisite) or it is on globally."""
    if getenv("MULTISITE", "no") == "yes":
        return any(getenv(f"{server}_{setting}", getenv(setting, "no")) == "yes" for server in getenv("SERVER_NAME", "").split())
    return getenv(setting, "no") == "yes"


try:
    if getenv("USE_SYSWARDEN", "no") != "yes":
        LOGGER.info("SysWarden is not activated, skipping blocklist download...")
        sys_exit(0)

    use_blocklist = any_service_uses("USE_SYSWARDEN_BLOCKLIST")
    use_whitelist = any_service_uses("USE_SYSWARDEN_WHITELIST")
    if not use_blocklist and not use_whitelist:
        LOGGER.info("No service uses the SysWarden blocklist or whitelist, skipping download...")
        sys_exit(0)

    interval = getenv("SYSWARDEN_BLOCKLIST_INTERVAL", "hour")
    if interval not in ("hour", "day"):
        interval = "hour"

    JOB = Job(LOGGER, __file__)

    if (not use_blocklist or JOB.is_cached_file("blocklist.list", interval)) and (not use_whitelist or JOB.is_cached_file("whitelist.list", interval)):
        LOGGER.info("SysWarden lists are already in cache, skipping download...")
        sys_exit(0)

    peers = get_peers(LOGGER)
    timeout = get_timeout()
    session = make_session(LOGGER)

    blocklist = set()
    whitelist = set()

    for peer in peers:
        if use_blocklist:
            got, body = call(session, peer, "GET", "/ha/sync", timeout=timeout)
            if got:
                blocklist.update(extract_ips(body))
            else:
                LOGGER.error(f"Can't read the blocklist of {peer}: {body}")
                status = 2

        if use_whitelist:
            # SysWarden exposes its whitelist only inside the telemetry payload; there is
            # no dedicated route for it yet.
            got, body = call(session, peer, "GET", "/ha/telemetry", timeout=timeout)
            if got:
                whitelist.update(parse_telemetry(body if isinstance(body, dict) else {})["whitelist_ips"])
            else:
                LOGGER.error(f"Can't read the whitelist of {peer}: {body}")
                status = 2

    if use_blocklist and getenv("SYSWARDEN_BLOCKLIST_EXCLUDE_OWN", "yes") == "yes":
        cached_owned = JOB.get_cache("pushed.json")
        if cached_owned:
            with suppress(BaseException):
                owned = loads(cached_owned.decode("utf-8", "replace") if isinstance(cached_owned, bytes) else cached_owned)
                if isinstance(owned, list):
                    before = len(blocklist)
                    blocklist -= {entry for entry in owned if isinstance(entry, str)}
                    LOGGER.info(f"Excluded {before - len(blocklist)} entry(ies) we pushed ourselves, BunkerWeb already bans them at Layer 7")

    for name, entries, wanted in (("blocklist.list", blocklist, use_blocklist), ("whitelist.list", whitelist, use_whitelist)):
        if not wanted:
            continue

        content = b""
        kept = 0
        for entry in sorted(entries):
            ok, data = check_line(entry.encode())
            if ok:
                content += data + b"\n"
                kept += 1

        if not content:
            # Keep whatever is already cached: an empty or fully invalid answer must not
            # wipe a working list (and the Lua side fails open on an empty one anyway).
            LOGGER.warning(f"No valid entry for {name}, keeping the cached file as is...")
            status = 2
            continue

        new_hash = bytes_hash(content)
        if new_hash == JOB.cache_hash(name):
            LOGGER.info(f"New {name} file is identical to cache file, reload is not needed")
            continue

        cached, err = JOB.cache_file(name, content, checksum=new_hash)
        if not cached:
            LOGGER.error(f"Error while caching {name}: {err}")
            status = 2
            continue

        LOGGER.info(f"Downloaded {kept} entry(ies) into {name}")
        # 1 asks the scheduler to reload nginx, which is what makes the new list live.
        status = status or 1
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running syswarden-blocklist-download.py")

sys_exit(status)
