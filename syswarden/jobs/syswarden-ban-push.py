#!/usr/bin/env python3

from contextlib import suppress
from json import dumps, loads
from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for syswarden_helpers / syswarden_client).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",), ("api",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from API import API  # type: ignore
from ApiCaller import ApiCaller  # type: ignore
from logger import setup_logger  # type: ignore
from common_utils import get_redis_client  # type: ignore
from jobs import Job  # type: ignore

from syswarden_helpers import cap_items, chunked, diff_push, next_owned, parse_ban_key, select_bans  # type: ignore
from syswarden_client import call, extract_ips, get_peers, get_timeout, make_session  # type: ignore

LOGGER = setup_logger("SYSWARDEN.BAN-PUSH", getenv("LOG_LEVEL", "INFO"))
status = 0

try:
    if getenv("USE_SYSWARDEN", "no") != "yes":
        LOGGER.info("SysWarden is not activated, skipping ban push...")
        sys_exit(0)

    if getenv("USE_SYSWARDEN_BAN_PUSH", "no") != "yes":
        LOGGER.info("SysWarden ban push is not activated, skipping...")
        sys_exit(0)

    audit = getenv("SYSWARDEN_ENFORCEMENT", "enforcing") == "audit"
    try:
        max_items = int(getenv("SYSWARDEN_BAN_MAX_ITEMS", "10000"))
        chunk_size = int(getenv("SYSWARDEN_BAN_CHUNK_SIZE", "500"))
        min_ttl = int(getenv("SYSWARDEN_BAN_MIN_TTL", "0"))
    except ValueError:
        LOGGER.error("SYSWARDEN_BAN_MAX_ITEMS, SYSWARDEN_BAN_CHUNK_SIZE and SYSWARDEN_BAN_MIN_TTL must be integers")
        sys_exit(2)

    peers = get_peers(LOGGER)
    timeout = get_timeout()
    JOB = Job(LOGGER, __file__)

    # Collect the current bans from both sources. Redis is optional: BunkerWeb also keeps
    # its bans in each instance's shared dict, which GET /bans returns with more detail
    # (ban_scope, service, exp, permanent), so the plugin works without USE_REDIS=yes.
    records = []

    if getenv("USE_REDIS", "no") == "yes":
        redis_client = get_redis_client(
            use_redis=True,
            redis_host=getenv("REDIS_HOST"),
            redis_port=getenv("REDIS_PORT", "6379"),
            redis_db=getenv("REDIS_DATABASE", "0"),
            redis_timeout=getenv("REDIS_TIMEOUT", "1000"),
            redis_keepalive_pool=getenv("REDIS_KEEPALIVE_POOL", "10"),
            redis_ssl=getenv("REDIS_SSL", "no") == "yes",
            redis_username=getenv("REDIS_USERNAME") or None,
            redis_password=getenv("REDIS_PASSWORD") or None,
            redis_sentinel_hosts=getenv("REDIS_SENTINEL_HOSTS", ""),
            redis_sentinel_username=getenv("REDIS_SENTINEL_USERNAME") or None,
            redis_sentinel_password=getenv("REDIS_SENTINEL_PASSWORD") or None,
            redis_sentinel_master=getenv("REDIS_SENTINEL_MASTER", ""),
            logger=LOGGER,
        )
        if redis_client is None:
            LOGGER.warning("Could not connect to Redis, falling back to the instances API only...")
        else:
            for pattern in ("bans_ip_*", "bans_service_*_ip_*"):
                for key in redis_client.scan_iter(pattern):
                    parsed = parse_ban_key(key)
                    if not parsed:
                        continue
                    record = dict(parsed)
                    raw = redis_client.get(key)
                    if raw:
                        with suppress(BaseException):
                            ban_data = loads(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
                            record["permanent"] = ban_data.get("permanent", False)
                            record["ban_scope"] = ban_data.get("ban_scope")
                    record["exp"] = redis_client.ttl(key)
                    records.append(record)
            LOGGER.info(f"Found {len(records)} ban(s) in Redis")

    api_caller = ApiCaller([API.from_instance(instance) for instance in JOB.db.get_instances()])
    ok, responses = api_caller.send_to_apis("GET", "/bans", response=True)
    if not ok:
        LOGGER.warning("At least one BunkerWeb instance did not answer GET /bans, working with what came back...")
    for instance_data in (responses or {}).values():
        if not isinstance(instance_data, dict):
            continue
        # The instance API answers {"status": ..., "msg": [...]}; older readers use "data".
        instance_bans = instance_data.get("msg")
        if not isinstance(instance_bans, list):
            instance_bans = instance_data.get("data")
        if isinstance(instance_bans, list):
            records.extend(entry for entry in instance_bans if isinstance(entry, dict))

    scope_filter = getenv("SYSWARDEN_BAN_SCOPE_FILTER", "").split()
    banned, dropped = cap_items(select_bans(records, scope_filter, min_ttl), max_items)
    if dropped:
        LOGGER.warning(f"More than {max_items} bans to push, {dropped} of them were dropped for this pass")
    LOGGER.info(f"{len(banned)} banned IP(s) to synchronize with {len(peers)} SysWarden peer(s)")

    owned = []
    cached_owned = JOB.get_cache("pushed.json")
    if cached_owned:
        with suppress(BaseException):
            loaded = loads(cached_owned.decode("utf-8", "replace") if isinstance(cached_owned, bytes) else cached_owned)
            if isinstance(loaded, list):
                owned = [entry for entry in loaded if isinstance(entry, str)]

    session = make_session(LOGGER, methods=("GET", "POST", "DELETE"))

    removed_ok = set()
    peer_failed = False

    for peer in peers:
        got, body = call(session, peer, "GET", "/ha/sync", timeout=timeout)
        if not got:
            LOGGER.error(f"Can't read the blocklist of {peer}: {body}")
            peer_failed = True
            status = 2
            continue

        remote = extract_ips(body)
        # to_remove is intersected with our own registry on purpose: /ha/sync is a shared
        # blocklist that also holds operator entries and real HA-peer entries.
        to_add, to_remove = diff_push(banned, remote, owned)

        if audit:
            LOGGER.info(f"[audit] {peer}: would add {len(to_add)} IP(s) and remove {len(to_remove)} IP(s), nothing sent")
            if to_add:
                LOGGER.info(f"[audit] {peer}: would add {' '.join(to_add)}")
            if to_remove:
                LOGGER.info(f"[audit] {peer}: would remove {' '.join(to_remove)}")
            continue

        for batch in chunked(to_add, chunk_size):
            sent, error = call(session, peer, "POST", "/ha/sync", timeout=timeout, payload={"ips": batch})
            if not sent:
                LOGGER.error(f"Can't push {len(batch)} ban(s) to {peer}: {error}")
                peer_failed = True
                status = 2
                continue
            LOGGER.info(f"➕ Pushed {len(batch)} ban(s) to {peer}")

        for batch in chunked(to_remove, chunk_size):
            sent, error = call(session, peer, "DELETE", "/ha/sync", timeout=timeout, payload={"ips": batch})
            if not sent:
                LOGGER.error(f"Can't remove {len(batch)} expired ban(s) from {peer}: {error}")
                peer_failed = True
                status = 2
                continue
            removed_ok.update(batch)
            LOGGER.info(f"➖ Removed {len(batch)} expired ban(s) from {peer}")

    if not audit:
        # Ownership is only released when every peer answered: an IP whose DELETE failed
        # somewhere stays ours, so the next pass retries instead of orphaning it there.
        deleted_everywhere = set() if peer_failed else removed_ok
        new_owned = next_owned(banned, owned, deleted_everywhere)
        if new_owned != owned:
            cached, err = JOB.cache_file("pushed.json", dumps(new_owned).encode())
            if not cached:
                LOGGER.error(f"Error while caching the ownership registry: {err}")
                status = 2

    if status == 0:
        LOGGER.info("🛡️ Successfully synchronized BunkerWeb bans with SysWarden ✅")
    # 0, not 1: nothing local changed, and returning 1 would reload nginx every minute.
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running syswarden-ban-push.py")

sys_exit(status)
