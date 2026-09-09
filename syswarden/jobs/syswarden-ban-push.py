#!/usr/bin/env python3

from contextlib import suppress
from json import dumps, loads
from os import getenv, sep
from os.path import dirname, join
from pathlib import Path
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
    cluster_fenced,
    chunked,
    extract_instance_bans,
    fence_challenge,
    fence_fingerprint,
    fence_proof,
    fence_reason,
    isolate_refused,
    load_manifest,
    load_registry,
    manifest_peers,
    membership_digest,
    next_registry,
    parse_ban_key,
    plan_peer,
    provenance_ips,
    resurrected,
    select_bans,
    split_push_targets,
    supports_ban_sync,
    valid_source,
)
from syswarden_client import fetch_fence_status, fetch_sync, get_peers, get_timeout, make_session, mutate_bans, mutate_legacy  # type: ignore

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

    # The fence manifest, when the operator mounted one. It is the perimeter from then on:
    # `members` is the authoritative endpoint list and each member carries the exact leaf
    # certificate to pin, which SYSWARDEN_PEERS cannot express. A configured but unusable
    # manifest stops the job rather than falling back to the looser posture.
    manifest = None
    pins = {}
    manifest_path = getenv("SYSWARDEN_FENCE_MANIFEST", "").strip()
    if manifest_path:
        try:
            manifest = load_manifest(loads(Path(manifest_path).read_text(encoding="utf-8")))
        except BaseException as e:
            LOGGER.error(f"Can't read the fence manifest at {manifest_path}: {e}")
            sys_exit(2)
        if manifest is None:
            LOGGER.error(f"The fence manifest at {manifest_path} is not a complete asserted manifest, refusing to mutate any peer")
            sys_exit(2)
        members = manifest_peers(manifest)
        peers = [peer for peer, _ in members]
        pins = dict(members)
        LOGGER.info(f"Fence manifest loaded: epoch {manifest['epoch']}, {len(peers)} member(s), SYSWARDEN_PEERS is not used for this pass")
    else:
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
    # With a manifest the epoch is the perimeter: upstream restarts the continuous-absence
    # clock on a new epoch, and a new manifest is exactly what a membership change produces.
    perimeter = manifest["epoch"] if manifest else membership_digest(peers)
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
    # SysWarden v4.03.2 runs every POSTed address through validateHAMutationTargets and
    # answers the *whole* batch with a 400 on the first protected one, so an address it
    # would refuse is dropped here rather than sent. Dropping it from the ban set (instead
    # of skipping it at send time) is deliberate: one this plugin pushed before the upgrade
    # is then simply no longer banned, so the ordinary diff turns it into a to_remove and
    # the DELETE — which upstream does not validate — cleans it up.
    details, refused = split_push_targets(details)
    if refused:
        sample = " ".join(refused[:5])
        suffix = " ..." if len(refused) > 5 else ""
        LOGGER.info(
            f"{len(refused)} banned IP(s) are not legal SysWarden firewall targets and stay local to BunkerWeb "
            f"(private, loopback, link-local or otherwise special-use): {sample}{suffix}"
        )
    LOGGER.info(f"{len(details)} banned IP(s) to synchronize with {len(peers)} SysWarden peer(s)")

    session = make_session(LOGGER, methods=("GET", "POST", "DELETE"), pins=pins)

    # Preflight the whole cluster before the first mutation. A mixed, partial or unreachable
    # cluster is not authoritative enough to make deletion decisions.
    peer_state = {}
    fence_state = {}
    fence_marks = {}
    for peer in peers:
        # One authenticated GET carries both halves of the preflight: what the peer's API can
        # do, and the fence proof for the challenge minted right here. A peer that predates
        # capability reporting, or whose operator has not enabled [integrations.bunkerweb],
        # reports nothing and gets the legacy dialect.
        challenge = fence_challenge()
        reachable, body = fetch_fence_status(session, peer, challenge, timeout=timeout)
        if not reachable:
            LOGGER.error(f"Can't read the status of {peer} ({body}), refusing to mutate any peer")
            status = 2
            continue
        capabilities = body.get("capabilities") or []
        if not isinstance(capabilities, list) or any(not isinstance(entry, str) for entry in capabilities):
            LOGGER.error(f"{peer} reported malformed capabilities, refusing to mutate any peer")
            status = 2
            continue
        provenance = supports_ban_sync(capabilities)

        if manifest:
            verdict, condition, reason = fence_proof(body, manifest, challenge)
            fence_state[peer] = (verdict, condition)
            fence_marks[peer] = fence_fingerprint(body)
            if verdict == "unusable":
                LOGGER.error(f"{peer}: no usable fence proof ({reason}), nothing will be written to its static blocklist")
                status = 2
            else:
                LOGGER.info(f"{peer}: fence {verdict} ({reason})")

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

    back = resurrected(owned, seen_remote)
    # Under a complete and proven fence, a reappearance is no longer attributable to
    # SysWarden's own ha-sync replication: every peer attests it is drained and refusing
    # legacy writes, so something outside the contract wrote the address back. Deleting it
    # again would put the plugin in a loop against an operator, so the pass stops instead and
    # hands the decision over.
    fenced_cluster = bool(manifest) and cluster_fenced((verdict for verdict, _ in fence_state.values()), len(peers))
    if back and fenced_cluster:
        LOGGER.error(
            f"{len(back)} entry(ies) this plugin had removed are on a peer again while every peer proves a drained fence. "
            f"This is an operator decision, not HA replication, so nothing is deleted this pass: {' '.join(back)}"
        )
        status = 2
    elif back:
        LOGGER.warning(f"{len(back)} entry(ies) this plugin had removed are on a peer again, their claims are kept: {' '.join(back)}")

    complete = status == 0 and len(peer_state) == len(peers)

    if not complete:
        # A partial view decides nothing, and it must not let a clock keep maturing either:
        # an hour of continuous absence cannot span a period where the cluster was unseen.
        new_owned = next_registry((), owned, seen_remote, still_banned, time(), False)
        cached, err = JOB.cache_file("pushed.json", dumps({"membership": perimeter, "claims": new_owned}).encode())
        if not cached:
            LOGGER.error(f"Error while caching the ownership registry: {err}")
        sys_exit(2)

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
    legacy_touched = False

    for peer, (provenance, to_add, to_remove, stale_legacy) in peer_plans.items():
        verdict, condition = fence_state.get(peer, ("inactive", None))
        if manifest and verdict not in ("fenced", "inactive"):
            LOGGER.error(f"Skipping {peer} entirely: it produced no usable fence proof this pass")
            continue
        # A fence engaged over legacy mutations answers a new {"ips"} write with 423 by
        # design, so those additions are held instead of being attempted and logged as errors.
        legacy_open = verdict != "fenced"
        additions_ok = True

        def push_additions(items):
            """Send one additions request in whichever dialect this peer speaks."""
            if provenance:
                return mutate_bans(session, peer, "POST", build_ban_batch({ip: details[ip] for ip in items}, source), timeout=timeout)
            return mutate_legacy(session, peer, "POST", items, timeout=timeout)

        for batch in chunked(to_add, ban_chunk if provenance else ips_chunk):
            if not provenance and not legacy_open:
                # Held, not failed. The cleanup below is the whole point of the fence, so it
                # must still run: skipping it here would fence the peer and then leave the
                # entries the campaign exists to remove exactly where they were.
                LOGGER.info(f"{peer} is fenced, holding {len(to_add)} legacy addition(s) until its fence is released")
                break
            sent, code, error = push_additions(batch)
            if not sent and code == 400:
                LOGGER.warning(f"{peer} refused a batch of {len(batch)} ban(s) as a protected firewall target, isolating it")
                landed, rejected, failure = isolate_refused(batch, push_additions)
                # Only a legacy push writes the static store, so only it creates a claim there.
                if not provenance:
                    pushed_ok.update(landed)
                if landed:
                    LOGGER.info(f"➕ Pushed {len(landed)} ban(s) to {peer}")
                if rejected:
                    # Three of upstream's rules read state only the peer has — its own
                    # interface addresses, its configured HA peer prefixes and its whitelist —
                    # so the local filter cannot preempt these, and no retry will ever change
                    # the verdict. Refusing an address is the peer's decision, not our failure:
                    # going red every minute over it would bury the failures that do matter.
                    LOGGER.warning(f"{peer} refuses {len(rejected)} address(es) as a firewall target, they stay local to BunkerWeb: {' '.join(rejected)}")
                if failure:
                    LOGGER.error(f"Can't push ban(s) to {peer}: {failure[1]}. {fence_reason(failure[0])}".strip())
                    additions_ok = False
                    status = 2
                    break
                continue
            if not sent:
                LOGGER.error(f"Can't push {len(batch)} ban(s) to {peer}: {error}. {fence_reason(code)}".strip())
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
            if provenance:
                sent, code, error = mutate_bans(session, peer, "DELETE", build_unban_batch(batch, source), timeout=timeout)
            else:
                # The condition is sent only when this pass holds a live proof: upstream
                # answers 412 to a condition presented while the fence is inactive.
                sent, code, error = mutate_legacy(session, peer, "DELETE", batch, condition=condition, timeout=timeout)
                legacy_touched = True
            if not sent:
                LOGGER.error(f"Can't remove {len(batch)} lifted ban(s) from {peer}: {error}. {fence_reason(code)}".strip())
                status = 2
                break
            LOGGER.info(f"➖ Removed {len(batch)} lifted ban(s) from {peer}")

        # A separate request carrying only {"ips"}: upstream forbids mixing the two forms in
        # one body, and this is the only dialect that reaches the static store.
        for batch in chunked(stale_legacy, ips_chunk):
            sent, code, error = mutate_legacy(session, peer, "DELETE", batch, condition=condition, timeout=timeout)
            legacy_touched = True
            if not sent:
                LOGGER.error(f"Can't remove {len(batch)} entry(ies) left over from the legacy dialect on {peer}: {error}. {fence_reason(code)}".strip())
                status = 2
                break
            LOGGER.info(f"➖ Removed {len(batch)} entry(ies) this plugin had pushed to {peer} before it supported ban provenance")

    # Re-read every fence after mutating. A condition accepted at the moment of the DELETE
    # only proves the fence held then; if the epoch, the generation, the server identity or
    # the condition moved during the pass, the deletions may have landed across a boundary
    # and nothing released this pass can be trusted.
    # Re-read whenever this pass could act on the fence, not only when it deleted: releasing
    # a claim that has simply been absent for an hour is just as fence-dependent, and a fence
    # that recovered mid-pass would otherwise go unnoticed on a pass that sent nothing.
    if manifest and (legacy_touched or fenced_cluster):
        for peer in peers:
            challenge = fence_challenge()
            still_there, body = fetch_fence_status(session, peer, challenge, timeout=timeout)
            if not still_there:
                LOGGER.error(f"Can't re-read the fence of {peer} after mutating ({body}), holding every claim")
                status = 2
                continue
            verdict, _, reason = fence_proof(body, manifest, challenge)
            if verdict == "unusable" or fence_fingerprint(body) != fence_marks.get(peer):
                LOGGER.error(f"The fence of {peer} moved during the pass ({reason}), holding every claim")
                status = 2

    # The claim is released only after a full grace window during which no peer reported the
    # address and BunkerWeb stopped banning it. A failed pass keeps every claim and restarts
    # the window, which is why this runs whatever `status` says.
    # Once a manifest is mounted, an hour of absence stops being enough on its own: the
    # contract is that a claim is released only under a fence proven on every member. A
    # manifest with no campaign engaged therefore holds every claim instead of ageing them
    # out, which is the conservative half of "a missing proof is a broken barrier".
    may_release = status == 0 and (not manifest or fenced_cluster)
    if manifest and not fenced_cluster and owned:
        # Guarding on a running clock would never fire: a pass that may not release resets
        # every clock to None, so from the second pass on there is none left to observe.
        LOGGER.info(f"A manifest is mounted but no complete fence is proven, holding {len(owned)} claim(s) this pass")
    new_owned = next_registry(pushed_ok, owned, seen_remote, still_banned, time(), may_release)
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
