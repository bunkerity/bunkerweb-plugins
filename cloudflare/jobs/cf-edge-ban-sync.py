#!/usr/bin/env python3

from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for cloudflare_helpers).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from cloudflare import APIError, Cloudflare  # type: ignore

from logger import setup_logger  # type: ignore
from common_utils import get_redis_client  # type: ignore

from cloudflare_helpers import CF_API_DEFAULT_URL, get_env_secret, parse_ban_key  # type: ignore

LOGGER = setup_logger("CLOUDFLARE.EDGE-BAN-SYNC", getenv("LOG_LEVEL", "INFO"))
status = 0
# Cloudflare's default per-account IP List capacity. We never push more than this.
MAX_ITEMS = 10000

try:
    if getenv("USE_CLOUDFLARE_EDGE_BAN_SYNC", "no") != "yes":
        LOGGER.info("Cloudflare edge ban sync is not enabled, skipping...")
        sys_exit(0)

    if getenv("USE_REDIS", "no") != "yes":
        LOGGER.warning("Cloudflare edge ban sync requires USE_REDIS=yes (bans are read from Redis), skipping...")
        sys_exit(0)

    account_id = getenv("CLOUDFLARE_ACCOUNT_ID", "")
    if not account_id:
        LOGGER.error("CLOUDFLARE_ACCOUNT_ID is required for edge ban sync, skipping...")
        sys_exit(2)

    token = get_env_secret("CLOUDFLARE_EDGE_BAN_API_TOKEN", "CLOUDFLARE_API_TOKEN").strip().removeprefix("Bearer ").strip()
    if not token:
        LOGGER.error("No API token available for edge ban sync (set CLOUDFLARE_EDGE_BAN_API_TOKEN or CLOUDFLARE_API_TOKEN), skipping...")
        sys_exit(2)

    list_name = getenv("CLOUDFLARE_BAN_LIST_NAME", "bunkerweb_bans")

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
        LOGGER.error("Could not connect to Redis, skipping edge ban sync...")
        sys_exit(2)

    # Collect currently banned IPs (both global and service-scoped) from Redis.
    banned = set()
    for pattern in ("bans_ip_*", "bans_service_*_ip_*"):
        for key in redis_client.scan_iter(pattern):
            ip = parse_ban_key(key)
            if ip:
                banned.add(ip)
    LOGGER.info(f"Found {len(banned)} active banned IP(s) in Redis")

    if len(banned) > MAX_ITEMS:
        LOGGER.warning(f"More than {MAX_ITEMS} banned IPs ({len(banned)}); only {MAX_ITEMS} will be synced to the Cloudflare list")
        banned = set(sorted(banned)[:MAX_ITEMS])

    try:
        api_timeout = float(getenv("CLOUDFLARE_API_TIMEOUT", "10"))
    except ValueError:
        api_timeout = 10.0
    client = Cloudflare(api_token=token, base_url=getenv("CLOUDFLARE_API_URL", CF_API_DEFAULT_URL).rstrip("/"), timeout=api_timeout)

    # Find or create the account IP List.
    list_id = None
    try:
        for lst in client.rules.lists.list(account_id=account_id):
            if getattr(lst, "name", None) == list_name and getattr(lst, "kind", None) == "ip":
                list_id = lst.id
                break
        if not list_id:
            LOGGER.info(f"Creating Cloudflare IP List '{list_name}'...")
            created = client.rules.lists.create(account_id=account_id, kind="ip", name=list_name)
            list_id = created.id
    except APIError as e:
        LOGGER.error(f"Failed to find/create the Cloudflare IP List '{list_name}': {e}")
        sys_exit(2)

    # Current items in the list (ip -> item id).
    current = {}
    try:
        for item in client.rules.lists.items.list(list_id=list_id, account_id=account_id):
            ip = getattr(item, "ip", None)
            if ip:
                current[ip] = getattr(item, "id", None)
    except APIError as e:
        LOGGER.error(f"Failed to list items of the Cloudflare IP List: {e}")
        sys_exit(2)

    current_ips = set(current.keys())
    to_add = banned - current_ips
    to_remove = current_ips - banned

    if not to_add and not to_remove:
        LOGGER.info("Cloudflare edge IP List already in sync with BunkerWeb bans, nothing to do")
        sys_exit(0)

    try:
        if to_add:
            client.rules.lists.items.create(list_id=list_id, account_id=account_id, body=[{"ip": ip} for ip in to_add])
            LOGGER.info(f"➕ Queued {len(to_add)} IP(s) to add to the Cloudflare edge IP List")
        if to_remove:
            items = [{"id": current[ip]} for ip in to_remove if current.get(ip)]
            if items:
                client.rules.lists.items.delete(list_id=list_id, account_id=account_id, items=items)
                LOGGER.info(f"➖ Queued {len(items)} IP(s) to remove from the Cloudflare edge IP List")
    except APIError as e:
        LOGGER.error(f"Failed to update the Cloudflare edge IP List: {e}")
        sys_exit(2)

    LOGGER.info("☁️ Successfully synced BunkerWeb bans to the Cloudflare edge IP List ✅")
    # 0, not 1: the sync only changes Cloudflare's edge (no local nginx config changed).
    # The scheduler reloads nginx on a job returning 1, so success must be 0 to avoid a
    # needless reload every run (it does NOT honor the per-job reload:false at runtime).
    status = 0
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running cf-edge-ban-sync.py")

sys_exit(status)
