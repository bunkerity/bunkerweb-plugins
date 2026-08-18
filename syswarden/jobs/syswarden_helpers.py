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
from os import getenv
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Default port of SysWarden's HA API (`[integrations.ha] peer_port`).
SYSWARDEN_DEFAULT_PORT = 62026

# Bounds SysWarden enforces on a temporary ban. TTL comes from firewall.MinimumBanTTL /
# MaximumBanTTL, the two byte caps from maxHAReasonBytes / maxHASourceBytes, and the batch
# size from maxHABansPerRequest. A payload outside any of them is answered with a 400, so
# the plugin clamps rather than letting a whole batch be refused.
SYSWARDEN_MIN_TTL = 1
SYSWARDEN_MAX_TTL = 30 * 24 * 3600
SYSWARDEN_MAX_REASON_BYTES = 512
SYSWARDEN_MAX_SOURCE_BYTES = 64
SYSWARDEN_MAX_BANS_PER_REQUEST = 500
SYSWARDEN_MAX_IPS_PER_REQUEST = 1024

# Provenance tag written on every ban this plugin pushes. SysWarden keys its ledger on
# (ip, source, peer_scope) and only ever deletes records matching all three, so this value
# is what tells our own entries apart from an operator's `syswarden block`.
SYSWARDEN_BAN_SOURCE = "bunkerweb"

# The charset SysWarden accepts for `source` (validHASource in ha_api.go).
_SOURCE_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-")


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


def canonical_address(value: Optional[str]) -> str:
    """Render an address the way SysWarden stores it, or ``""`` if it would be refused.

    Mirrors Go's ``canonicalHAAddress``: ``netip`` parsing, IPv4-mapped and zoned
    addresses rejected, a network masked to its prefix. Two reasons this has to happen
    before anything goes on the wire. A single refused entry makes SysWarden reject the
    *entire* batch of up to 500 bans, so one malformed address would stop every ban that
    minute. And an address that differs only in case (``2001:DB8::1``) is accepted but
    stored canonicalized, so without this the next pass sees it as both "to add" and "to
    remove" and oscillates forever.
    """
    text = (value or "").strip()
    if not text:
        return ""
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
            return "" if network.version == 6 and network[0].ipv4_mapped else str(network)
        address = ip_address(text)
    except ValueError:
        return ""
    if address.version == 6 and (address.ipv4_mapped or "%" in text):
        return ""
    return str(address)


def normalize_ban(record: Dict) -> Optional[Dict]:
    """Normalize one ban into ``{"ip", "service", "ban_scope", "ttl", "reason"}``.

    Accepts both shapes the plugin reads: a Redis-derived dict (ip/service only) and a
    record from ``GET /bans`` on the instance API (``ip, service, ban_scope, exp,
    permanent, reason, ...``). ``ttl`` is the remaining lifetime in seconds, or None when
    the ban is permanent or carries no expiry — callers must treat None as "never
    expires", never as "expired".
    """
    ip = canonical_address(str(record.get("ip") or ""))
    if not ip:
        return None
    service = str(record.get("service") or "").strip()
    ban_scope = str(record.get("ban_scope") or ("service" if service else "global")).strip()

    ttl = None
    if not record.get("permanent"):
        exp = record.get("exp", record.get("ttl"))
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            # Redis answers -1 for a key with no expiry and -2 for one that vanished
            # between the scan and the read; the instance API answers 0 for an expired
            # ban. Only the first of those is a ban, and pushing the others would ban an
            # address BunkerWeb no longer bans — permanently so, on a peer without TTLs.
            if exp == -1:
                ttl = None
            elif exp <= 0:
                return None
            else:
                ttl = int(exp)
    return {"ip": ip, "service": service, "ban_scope": ban_scope, "ttl": ttl, "reason": str(record.get("reason") or "").strip()}


def select_bans(records: Iterable[Dict], scope_filter: Sequence[str] = (), min_ttl: int = 0) -> Dict[str, Dict]:
    """Merge ban records into ``{ip: {"ttl", "reason"}}``, ready to push.

    Deduplicates on ``(ip, ban_scope, service)`` the way BunkerWeb's own bans page does,
    then flattens to IPs: SysWarden's blocklist is host-wide, so a per-service scope has
    no meaning once the ban reaches nftables. The mapping is keyed by IP, so iterating it
    (or wrapping it in ``set()``) still yields exactly the addresses to ban.

    ``scope_filter`` limits which *services* are propagated; global bans always pass,
    since they are not tied to a service. ``min_ttl`` drops short-lived bans (rate-limit
    noise) — a permanent ban (``ttl is None``) is never dropped by it.

    When several bans collide on one IP, the longest one wins: a permanent ban (``ttl is
    None``) beats every dated one, so a shorter service ban can never cut it short.
    """
    allowed = {service for service in scope_filter if service}
    seen: Set[Tuple[str, str, str]] = set()
    bans: Dict[str, Dict] = {}
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
        current = bans.get(ban["ip"])
        if current is None or (current["ttl"] is not None and (ban["ttl"] is None or ban["ttl"] > current["ttl"])):
            bans[ban["ip"]] = {"ttl": ban["ttl"], "reason": ban["reason"]}
    return bans


def clamp_ttl(ttl: Optional[int], minimum: int = SYSWARDEN_MIN_TTL, maximum: int = SYSWARDEN_MAX_TTL) -> int:
    """Fit a BunkerWeb ban lifetime into the window SysWarden accepts.

    A permanent ban (``ttl is None``) becomes ``maximum``: SysWarden has no permanent
    temporary-ban state, and the push job re-sends every still-banned IP each minute, so
    the ceiling is refreshed long before it is reached.
    """
    if ttl is None or ttl > maximum:
        return maximum
    return max(int(ttl), minimum)


def sanitize_reason(reason: Optional[str], default: str = "BunkerWeb ban") -> str:
    """Make a ban reason acceptable to SysWarden's ``validHAReason``.

    Control and non-printable characters are dropped and the result is truncated on
    *bytes*, since that is what SysWarden counts. An empty result falls back to
    ``default`` rather than failing the whole batch on a 400.
    """
    text = "".join(character for character in (reason or "") if character.isprintable()).strip()
    if not text:
        text = default
    encoded = text.encode("utf-8")[:SYSWARDEN_MAX_REASON_BYTES]
    return encoded.decode("utf-8", "ignore").strip() or default


def sanitize_source(source: Optional[str], default: str = SYSWARDEN_BAN_SOURCE) -> str:
    """Make a provenance tag acceptable to SysWarden's ``validHASource``."""
    text = "".join(character for character in (source or "") if character in _SOURCE_ALLOWED)[:SYSWARDEN_MAX_SOURCE_BYTES]
    return text or default


def build_ban_batch(bans: Dict[str, Dict], source: str = SYSWARDEN_BAN_SOURCE) -> List[Dict]:
    """Turn ``{ip: {"ttl", "reason"}}`` into the ``bans`` array of a temporary POST.

    Every entry carries exactly the four fields SysWarden requires — it rejects an object
    holding anything else — with the TTL clamped and the reason sanitized.
    """
    tag = sanitize_source(source)
    return [{"ip": ip, "ttl": clamp_ttl(bans[ip].get("ttl")), "reason": sanitize_reason(bans[ip].get("reason", "")), "source": tag} for ip in sorted(bans)]


def build_unban_batch(ips: Iterable[str], source: str = SYSWARDEN_BAN_SOURCE) -> List[Dict]:
    """Turn IPs into the ``bans`` array of a temporary DELETE (``ip`` and ``source`` only)."""
    tag = sanitize_source(source)
    return [{"ip": ip, "source": tag} for ip in sorted(ips)]


def canonical_set(values: Iterable[str]) -> Set[str]:
    """Canonicalize a peer's addresses so both sides of a comparison use one spelling.

    Our own side is canonicalized in ``normalize_ban``. Doing only that would move the
    oscillation rather than fix it: an address the peer spells differently would show up
    as both "to add" and "to remove" on every pass. Anything unparsable is dropped, since
    it can match nothing we would ever send.
    """
    return {canonical for canonical in (canonical_address(value) for value in values) if canonical}


def provenance_ips(bans: Iterable, source: str = SYSWARDEN_BAN_SOURCE) -> Set[str]:
    """The addresses a peer reports as banned under our own provenance tag.

    This replaces the ``pushed.json`` registry wherever the peer supports provenance: the
    peer is then the one holding the ownership, and its answer survives a lost job cache.
    """
    tag = sanitize_source(source)
    return canonical_set(str(ban.get("ip") or "") for ban in bans if isinstance(ban, dict) and ban.get("source") == tag)


def plan_peer(
    banned: Iterable[str], still_banned: Iterable[str], remote: Iterable[str], ours: Iterable[str], owned: Iterable[str], provenance: bool
) -> Tuple[List[str], List[str], List[str]]:
    """Decide what to send one peer: ``(to_add, to_remove, stale_legacy)``.

    This is the whole consequential computation of a pass, kept here rather than in the
    job script so it can be tested without Docker.

    ``still_banned`` is every address BunkerWeb bans, the ``SYSWARDEN_BAN_MAX_ITEMS`` cap
    ignored, while ``banned`` is what this pass may push. Removals are computed against
    the former: being over the cap delays a ban, it must never remove one.

    ``stale_legacy`` only exists for a peer that reports provenance. Expiring bans and the
    peer's static blocklist are disjoint stores on the SysWarden side, and a legacy push
    wrote the static one — reachable only through the legacy dialect. Without this, an
    address pushed before the peer was upgraded stays blocked in its kernel forever. It is
    also the one decision that still depends on ``pushed.json``: a lost cache orphans those
    entries, which is the tradeoff for not being able to ask the peer who wrote them.
    """
    banned, still, remote, ours, owned = set(banned), set(still_banned), set(remote), set(ours), set(owned)
    held = ours if provenance else remote
    to_add, to_remove = diff_push(banned, held, ours if provenance else owned)
    stale_legacy = sorted(((owned & remote) - ours) - still) if provenance else []
    return to_add, sorted(set(to_remove) - still), stale_legacy


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
