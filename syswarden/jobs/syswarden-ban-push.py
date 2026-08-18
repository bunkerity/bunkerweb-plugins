#!/usr/bin/env python3

from contextlib import suppress
from json import dumps, loads
from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path
from time import time

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

from syswarden_helpers import (  # type: ignore
    SYSWARDEN_MAX_BANS_PER_REQUEST,
    SYSWARDEN_MAX_IPS_PER_REQUEST,
    build_ban_batch,
    build_unban_batch,
    canonical_set,
    cap_items,
    chunked,
    extract_instance_bans,
    load_registry,
    membership_digest,
    next_registry,
    parse_ban_key,
    plan_peer,
    provenance_ips,
    resurrected,
    select_bans,
    supports_ban_sync,
    valid_source,
)
from syswarden_client import call, fetch_capabilities, fetch_sync, get_peers, get_timeout, make_session  # type: ignore

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

    if chunk_size <= 0:
        # chunked() reads a non-positive size as "one single batch", which SysWarden would
        # then refuse whole once there are more bans than a request may carry.
        LOGGER.warning("SYSWARDEN_BAN_CHUNK_SIZE must be at least 1, falling back to 500")
        chunk_size = 500

    source = getenv("SYSWARDEN_BAN_SOURCE", "").strip()
    if not valid_source(source):
        LOGGER.error("SYSWARDEN_BAN_SOURCE is required for ban push and must be a cluster-unique 1-64 character tag")
        sys_exit(2)

    peers = get_peers(LOGGER)
    timeout = get_timeout()
    JOB = Job(LOGGER, __file__)

    # The durable registry: what this plugin claims in each peer's *static* blocklist, which
    # carries no provenance and is therefore reachable only through the legacy dialect.
    owned = {}
    membership = ""
    cached_owned = JOB.get_cache("pushed.json")
    if cached_owned:
        with suppress(BaseException):
            owned, membership = load_registry(loads(cached_owned.decode("utf-8", "replace") if isinstance(cached_owned, bytes) else cached_owned))
    perimeter = membership_digest(peers)
    if membership != perimeter:
        # Upstream is explicit: a membership change restarts the continuous-absence clock.
        if any(since is not None for since in owned.values()):
            LOGGER.info("The peer perimeter changed, restarting the release window of every claim")
        owned = {ip: None for ip in owned}

    # Collect the current bans from both sources. Redis is optional: BunkerWeb also keeps
    # its bans in each instance's shared dict, which GET /bans returns with more detail
    # (ban_scope, service, exp, permanent), so the plugin works without USE_REDIS=yes.
    records = []
    redis_complete = False

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
            redis_complete = True
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
                            # BunkerWeb stores the reason in the same blob; without this the
                            # peer only ever sees the generic fallback when Redis is enabled.
                            record["reason"] = ban_data.get("reason")
                    record["exp"] = redis_client.ttl(key)
                    records.append(record)
            LOGGER.info(f"Found {len(records)} ban(s) in Redis")

    instances = JOB.db.get_instances()
    api_caller = ApiCaller([API.from_instance(instance) for instance in instances])
    ok, responses = api_caller.send_to_apis("GET", "/bans", response=True)
    instance_bans = extract_instance_bans(responses, len(instances)) if ok and instances else None
    if instance_bans is None:
        if not redis_complete:
            LOGGER.error("The BunkerWeb ban inventory is incomplete and Redis is not authoritative, refusing to reconcile peers")
            sys_exit(2)
        LOGGER.warning("The BunkerWeb instance inventory is incomplete, using the authoritative Redis inventory only...")
    else:
        records.extend(instance_bans)

    scope_filter = getenv("SYSWARDEN_BAN_SCOPE_FILTER", "").split()
    details = select_bans(records, scope_filter, min_ttl)
    LOGGER.info(f"{len(details)} banned IP(s) to synchronize with {len(peers)} SysWarden peer(s)")

    session = make_session(LOGGER, methods=("GET", "POST", "DELETE"))

    # Preflight the whole cluster before the first mutation. A mixed, partial or unreachable
    # cluster is not authoritative enough to make deletion decisions.
    peer_state = {}
    for peer in peers:
        # The peer states what its API can do. One that predates capability reporting, or
        # whose operator has not enabled [integrations.bunkerweb], reports nothing and gets
        # the legacy dialect; the only published SysWarden release still speaks only that.
        reachable, capabilities = fetch_capabilities(session, peer, timeout=timeout)
        if not reachable:
            LOGGER.error(f"Can't read the status of {peer}, refusing to mutate any peer")
            status = 2
            continue
        provenance = supports_ban_sync(capabilities)

        got, snapshot = fetch_sync(session, peer, timeout=timeout, details=provenance)
        if not got:
            LOGGER.error(f"Can't read the blocklist of {peer}, refusing to mutate any peer")
            status = 2
            continue
        peer_state[peer] = (provenance, canonical_set(snapshot["ips"]), provenance_ips(snapshot["bans"], source) if provenance else set())

    seen_remote = set()
    for _, remote, _ in peer_state.values():
        seen_remote |= remote

    still_banned = set(details)
    complete = status == 0 and len(peer_state) == len(peers)

    if not complete:
        # A partial view decides nothing, and it must not let a clock keep maturing either:
        # an hour of continuous absence cannot span a period where the cluster was unseen.
        new_owned = next_registry((), owned, seen_remote, still_banned, time(), False)
        cached, err = JOB.cache_file("pushed.json", dumps({"membership": perimeter, "claims": new_owned}).encode())
        if not cached:
            LOGGER.error(f"Error while caching the ownership registry: {err}")
        sys_exit(2)

    back = resurrected(owned, seen_remote)
    if back:
        LOGGER.warning(f"{len(back)} entry(ies) this plugin had removed are on a peer again, their claims are kept: {' '.join(back)}")

    peer_plans = {}
    for peer, (provenance, remote, ours) in peer_state.items():
        to_add, to_remove, stale_legacy = plan_peer(still_banned, remote, ours, owned, provenance)
        to_add, dropped = cap_items(to_add, max_items)
        if dropped:
            LOGGER.warning(f"{peer}: {dropped} missing ban(s) deferred by SYSWARDEN_BAN_MAX_ITEMS for this pass")
        peer_plans[peer] = (provenance, to_add, to_remove, stale_legacy)

    if audit:
        for peer, (provenance, to_add, to_remove, stale_legacy) in peer_plans.items():
            dialect = "provenance" if provenance else "legacy"
            LOGGER.info(f"[audit] {peer} ({dialect}): would add {len(to_add)} IP(s) and remove {len(to_remove) + len(stale_legacy)} IP(s), nothing sent")
            if to_add:
                LOGGER.info(f"[audit] {peer}: would add {' '.join(to_add)}")
            if to_remove or stale_legacy:
                LOGGER.info(f"[audit] {peer}: would remove {' '.join(to_remove + stale_legacy)}")
        sys_exit(0)

    # SysWarden refuses an oversized batch outright, and the two dialects have different
    # ceilings, so the setting can only ever lower them.
    ban_chunk = min(chunk_size, SYSWARDEN_MAX_BANS_PER_REQUEST)
    ips_chunk = min(chunk_size, SYSWARDEN_MAX_IPS_PER_REQUEST)
    pushed_ok = set()

    for peer, (provenance, to_add, to_remove, stale_legacy) in peer_plans.items():
        additions_ok = True
        for batch in chunked(to_add, ban_chunk if provenance else ips_chunk):
            payload = {"bans": build_ban_batch({ip: details[ip] for ip in batch}, source)} if provenance else {"ips": batch}
            sent, error = call(session, peer, "POST", "/ha/sync", timeout=timeout, payload=payload)
            if not sent:
                LOGGER.error(f"Can't push {len(batch)} ban(s) to {peer}: {error}")
                additions_ok = False
                status = 2
                break
            # Only a legacy push writes the static store, so only it creates a claim there.
            # Ownership is a receipt, never an intention: an address whose push failed must
            # not be recorded, or a later pass would delete an entry we never wrote.
            if not provenance:
                pushed_ok.update(batch)
            LOGGER.info(f"➕ Pushed {len(batch)} ban(s) to {peer}")

        # Never reduce coverage on a peer whose additions failed in the same pass.
        if not additions_ok:
            continue

        for batch in chunked(to_remove, ban_chunk if provenance else ips_chunk):
            payload = {"bans": build_unban_batch(batch, source)} if provenance else {"ips": batch}
            sent, error = call(session, peer, "DELETE", "/ha/sync", timeout=timeout, payload=payload)
            if not sent:
                LOGGER.error(f"Can't remove {len(batch)} lifted ban(s) from {peer}: {error}")
                status = 2
                break
            LOGGER.info(f"➖ Removed {len(batch)} lifted ban(s) from {peer}")

        # A separate request carrying only {"ips"}: upstream forbids mixing the two forms in
        # one body, and this is the only dialect that reaches the static store.
        for batch in chunked(stale_legacy, ips_chunk):
            sent, error = call(session, peer, "DELETE", "/ha/sync", timeout=timeout, payload={"ips": batch})
            if not sent:
                LOGGER.error(f"Can't remove {len(batch)} entry(ies) left over from the legacy dialect on {peer}: {error}")
                status = 2
                break
            LOGGER.info(f"➖ Removed {len(batch)} entry(ies) this plugin had pushed to {peer} before it supported ban provenance")

    # The claim is released only after a full grace window during which no peer reported the
    # address and BunkerWeb stopped banning it. A failed pass keeps every claim and restarts
    # the window, which is why this runs whatever `status` says.
    new_owned = next_registry(pushed_ok, owned, seen_remote, still_banned, time(), status == 0)
    payload = {"membership": perimeter, "claims": new_owned}
    cached, err = JOB.cache_file("pushed.json", dumps(payload).encode())
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
