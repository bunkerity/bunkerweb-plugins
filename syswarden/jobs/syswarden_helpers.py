#!/usr/bin/env python3
"""Pure, dependency-free helpers shared by the SysWarden plugin jobs.

Kept free of any BunkerWeb (`/usr/share/bunkerweb/...`) or third-party imports so the
logic can be unit-tested with pytest outside the scheduler image (see tests/). The job
scripts import these and keep all the I/O (requests / Redis / instance API / JOB cache)
to themselves.
"""

from contextlib import suppress
from ipaddress import ip_address, ip_network
from itertools import islice
from os import getenv, sep
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Default port of SysWarden's HA API (`[integrations.ha] peer_port`).
SYSWARDEN_DEFAULT_PORT = 62026


def get_env_secret(primary: str, fallback: str = "", default: str = "") -> str:
    """Resolve a secret value, supporting the Docker-secret ``<NAME>_FILE`` convention.

    For each candidate env name (``primary`` then ``fallback``) we try ``<NAME>_FILE``
    (read the file), then ``<NAME>`` (raw value). BunkerWeb's scheduler does not apply
    the ``_FILE`` convention to job env itself, so the plugin does it here. Returns
    ``default`` when nothing is set.
    """
    for name in (primary, fallback):
        if not name:
            continue
        file_path = getenv(f"{name}_FILE")
        if file_path:
            with suppress(OSError):
                value = Path(file_path).read_text(encoding="utf-8").strip()
                if value:
                    return value
        value = getenv(name)
        if value:
            return value.strip() if isinstance(value, str) else value
    return default


def read_run_secret(name: str) -> Optional[str]:
    """Read ``/run/secrets/<name>`` (lowercased) if present, else None."""
    secret_path = Path(sep, "run", "secrets", name.lower())
    if secret_path.is_file():
        with suppress(OSError):
            return secret_path.read_text(encoding="utf-8").strip()
    return None


def parse_peers(value: Optional[str], default_port: int = SYSWARDEN_DEFAULT_PORT) -> Tuple[List[str], List[str]]:
    """Turn the ``SYSWARDEN_PEERS`` setting into base URLs.

    Accepts ``host``, ``host:port``, a bare IPv6 literal (``2001:db8::1``) and a
    bracketed one with a port (``[2001:db8::1]:62026``). A bare IPv6 literal cannot
    carry a port — the colons are the address — so it always gets ``default_port``.

    Returns ``(urls, errors)`` rather than raising: one malformed entry must not stop
    the plugin from talking to the peers that are fine. The caller logs ``errors``.
    """
    urls: List[str] = []
    errors: List[str] = []
    for entry in (value or "").split():
        host, port = entry, str(default_port)
        if entry.startswith("["):
            host, sep_found, rest = entry[1:].partition("]")
            if not sep_found:
                errors.append(f"{entry} (unclosed '[')")
                continue
            if rest:
                if not rest.startswith(":"):
                    errors.append(f"{entry} (trailing data after ']')")
                    continue
                port = rest[1:]
        elif entry.count(":") == 1:
            host, _, port = entry.partition(":")

        if not host:
            errors.append(f"{entry} (empty host)")
            continue
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            errors.append(f"{entry} (invalid port)")
            continue
        if not 1 <= port_number <= 65535:
            errors.append(f"{entry} (port out of range)")
            continue

        # A URL authority needs the brackets back for IPv6.
        authority = f"[{host}]" if ":" in host else host
        urls.append(f"https://{authority}:{port_number}")
    return urls, errors


def parse_ban_key(key) -> Optional[Dict[str, str]]:
    """Extract ``{"ip", "service"}`` from a BunkerWeb Redis ban key.

    Global bans use ``bans_ip_<IP>``; service bans use ``bans_service_<service>_ip_<IP>``.
    Returns None if the key is not a ban key. ``service`` is ``""`` for a global ban.
    """
    if isinstance(key, bytes):
        key = key.decode("utf-8", "replace")
    if key.startswith("bans_service_") and "_ip_" in key:
        service, _, ip = key.removeprefix("bans_service_").rpartition("_ip_")
        if not ip:
            return None
        return {"ip": ip, "service": service}
    if key.startswith("bans_ip_"):
        ip = key.removeprefix("bans_ip_")
        return {"ip": ip, "service": ""} if ip else None
    return None


def normalize_ban(record: Dict) -> Optional[Dict]:
    """Normalize one ban into ``{"ip", "service", "ban_scope", "ttl"}``.

    Accepts both shapes the plugin reads: a Redis-derived dict (ip/service only) and a
    record from ``GET /bans`` on the instance API (``ip, service, ban_scope, exp,
    permanent, ...``). ``ttl`` is the remaining lifetime in seconds, or None when the
    ban is permanent or carries no expiry — callers must treat None as "never expires",
    never as "expired".
    """
    ip = str(record.get("ip") or "").strip()
    if not ip:
        return None
    service = str(record.get("service") or "").strip()
    ban_scope = str(record.get("ban_scope") or ("service" if service else "global")).strip()

    ttl = None
    if not record.get("permanent"):
        exp = record.get("exp", record.get("ttl"))
        if isinstance(exp, (int, float)):
            ttl = int(exp)
    return {"ip": ip, "service": service, "ban_scope": ban_scope, "ttl": ttl}


def select_bans(records: Iterable[Dict], scope_filter: Sequence[str] = (), min_ttl: int = 0) -> Set[str]:
    """Merge ban records into the set of IPs to push.

    Deduplicates on ``(ip, ban_scope, service)`` the way BunkerWeb's own bans page does,
    then flattens to IPs: SysWarden's blocklist is host-wide, so a per-service scope has
    no meaning once the ban reaches nftables.

    ``scope_filter`` limits which *services* are propagated; global bans always pass,
    since they are not tied to a service. ``min_ttl`` drops short-lived bans (rate-limit
    noise) — a permanent ban (``ttl is None``) is never dropped by it.
    """
    allowed = {service for service in scope_filter if service}
    seen: Set[Tuple[str, str, str]] = set()
    ips: Set[str] = set()
    for record in records:
        ban = normalize_ban(record)
        if not ban:
            continue
        if allowed and ban["service"] and ban["service"] not in allowed:
            continue
        if min_ttl > 0 and ban["ttl"] is not None and ban["ttl"] < min_ttl:
            continue
        key = (ban["ip"], ban["ban_scope"], ban["service"])
        if key in seen:
            continue
        seen.add(key)
        ips.add(ban["ip"])
    return ips


def cap_items(ips: Iterable[str], max_items: int) -> Tuple[List[str], int]:
    """Sort and truncate to ``max_items``. Returns ``(kept, dropped_count)``.

    Sorting first makes the truncation deterministic: the same overflowing ban set
    yields the same pushed subset on every pass, instead of a set-iteration lottery
    that would churn the peer's blocklist.
    """
    ordered = sorted(ips)
    if max_items <= 0 or len(ordered) <= max_items:
        return ordered, 0
    return ordered[:max_items], len(ordered) - max_items


def diff_push(banned: Iterable[str], remote: Iterable[str], owned: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Compute what to POST and what to DELETE on one peer.

    ``to_add`` is what we ban and the peer does not have yet. ``to_remove`` is the
    intersection of the peer's list with *our own registry*, minus what is still
    banned — never ``remote - banned``. ``/ha/sync`` writes into a shared blocklist
    holding operator entries (``syswarden block``) and real HA-peer entries; deleting
    blindly would wipe them.
    """
    banned_set, remote_set, owned_set = set(banned), set(remote), set(owned)
    to_add = banned_set - remote_set
    to_remove = (remote_set & owned_set) - banned_set
    return sorted(to_add), sorted(to_remove)


def next_owned(banned: Iterable[str], owned: Iterable[str], deleted_everywhere: Iterable[str]) -> List[str]:
    """The ownership registry to persist after a pass.

    ``banned ∪ (owned − deleted_everywhere)``: an IP whose DELETE failed on one peer
    stays ours, so the next pass retries it instead of orphaning it in that peer's
    blocklist forever.
    """
    return sorted(set(banned) | (set(owned) - set(deleted_everywhere)))


def chunked(items: Sequence[str], size: int) -> List[List[str]]:
    """Split into batches of at most ``size`` (``size <= 0`` means one single batch)."""
    if size <= 0:
        return [list(items)] if items else []
    # islice rather than a slice expression: black formats `items[i : i + size]` with the
    # space flake8 then flags as E203.
    return [list(islice(items, index, index + size)) for index in range(0, len(items), size)]


def check_line(line: bytes) -> Tuple[bool, bytes]:
    """Validate a single IP / CIDR line coming from a peer's blocklist."""
    with suppress(ValueError):
        if b"/" in line:
            ip_network(line.decode())
            return True, line
        ip_address(line.decode())
        return True, line
    return False, b""


def split_families(entries: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Split validated entries into (v4, v6). Invalid entries are dropped.

    SysWarden keeps two nftables sets (``syswarden_blacklist`` / ``syswarden_blacklist6``)
    and sorts pushed entries itself, so this exists for reporting and tests rather than
    for the wire format.
    """
    v4: List[str] = []
    v6: List[str] = []
    for entry in entries:
        with suppress(ValueError):
            version = ip_network(entry, strict=False).version if "/" in entry else ip_address(entry).version
            (v4 if version == 4 else v6).append(entry)
    return v4, v6


def normalize_fingerprint(value: Optional[str]) -> str:
    """Normalize a certificate fingerprint for comparison.

    Accepts what ``openssl x509 -fingerprint -sha256`` prints
    (``SHA256 Fingerprint=AB:CD:...``), a bare hex digest, or a ``sha256:`` prefixed
    one, and returns lowercase hex with no separator.
    """
    text = (value or "").strip()
    if "=" in text:
        text = text.split("=", 1)[1]
    text = text.strip().lower()
    for prefix in ("sha256:", "sha-256:"):
        text = text.removeprefix(prefix)
    return text.replace(":", "").replace(" ", "")


def fingerprint_matches(expected: str, actual: str) -> bool:
    """Compare two fingerprints after normalization. Empty values never match.

    Fails closed on purpose: an unset or unparsable expected fingerprint must not be
    read as "anything goes".
    """
    left, right = normalize_fingerprint(expected), normalize_fingerprint(actual)
    return bool(left) and bool(right) and left == right


def _section(payload: Dict, key: str) -> Dict:
    """Return ``payload[key]`` when it is a dict, else an empty dict."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def parse_telemetry(payload: Dict, status: Optional[Dict] = None) -> Dict:
    """Flatten a ``/ha/telemetry`` (+ optional ``/ha/status``) payload for the web UI.

    Every field is optional: the shape is a contract of the SysWarden version being
    talked to, and a missing section must degrade the card, never raise.
    """
    payload = payload if isinstance(payload, dict) else {}
    status = status if isinstance(status, dict) else {}
    system = _section(payload, "system")
    layer3 = _section(payload, "layer3")
    waf = _section(payload, "waf")
    whitelist = _section(payload, "whitelist")

    return {
        "hostname": status.get("hostname") or system.get("hostname") or "",
        "os": status.get("os") or system.get("os") or "",
        "version": status.get("version") or payload.get("github_release") or "",
        "status": status.get("status") or "",
        "global_blocked": layer3.get("global_blocked", 0),
        "geoip_blocked": layer3.get("geoip_blocked", 0),
        "asn_blocked": layer3.get("asn_blocked", 0),
        "l7_banned": layer3.get("l7_banned", 0),
        "waf_total_banned": waf.get("total_banned", 0),
        "waf_total_detected": waf.get("total_detected", 0),
        "waf_active_signatures": waf.get("active_signatures", 0),
        "whitelist_active_ips": whitelist.get("active_ips", 0),
        "whitelist_ips": [entry for entry in (whitelist.get("ips") or []) if isinstance(entry, str)],
        "top_attackers": waf.get("top_attackers") or [],
        "targeted_ports": waf.get("targeted_ports") or [],
        "services": system.get("services") or [],
        "ports": system.get("ports") or [],
    }
