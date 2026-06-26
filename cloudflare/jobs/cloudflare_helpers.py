#!/usr/bin/env python3
"""Pure, dependency-free helpers shared by the Cloudflare plugin jobs.

Kept free of any BunkerWeb (`/usr/share/bunkerweb/...`) or third-party imports so the
logic can be unit-tested with pytest outside the scheduler image (see tests/). The job
scripts import these and keep all the I/O (requests / Cloudflare SDK / JOB cache) to
themselves.
"""

from contextlib import suppress
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from os import getenv, sep
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CF_API_DEFAULT_URL = "https://api.cloudflare.com/client/v4"
CF_IPS_V4_DEFAULT_URL = "https://www.cloudflare.com/ips-v4/"
CF_IPS_V6_DEFAULT_URL = "https://www.cloudflare.com/ips-v6/"
# Static, well-known Cloudflare Authenticated Origin Pull CA (shared across all CF
# customers — proves "came through Cloudflare", same trust level as IP allowlisting
# but cryptographic). NOT the Origin CA cert.
CF_AOP_CA_DEFAULT_URL = "https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem"


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


def parse_ban_key(key) -> Optional[str]:
    """Extract the banned IP from a BunkerWeb Redis ban key.

    Global bans use ``bans_ip_<IP>``; service bans use ``bans_service_<service>_ip_<IP>``.
    Returns the IP string, or None if the key is not a ban key.
    """
    if isinstance(key, bytes):
        key = key.decode("utf-8", "replace")
    if key.startswith("bans_service_") and "_ip_" in key:
        return key.rsplit("_ip_", 1)[1] or None
    if key.startswith("bans_ip_"):
        return key.removeprefix("bans_ip_") or None
    return None


def check_line(line: bytes) -> Tuple[bool, bytes]:
    """Validate a single IP / CIDR line from a Cloudflare IP-range list."""
    with suppress(ValueError):
        if b"/" in line:
            ip_network(line.decode())
            return True, line
        ip_address(line.decode())
        return True, line
    return False, b""


def build_csr_config(first_server: str, domains: List[str]) -> str:
    """Render the OpenSSL CSR config for a service (no Jinja / no template file).

    A plugin's ``templates/`` directory is reserved by BunkerWeb for JSON config
    templates, so the CSR config is built here in pure Python and cached as ``csr.conf``.
    Deterministic so the daily job can diff it to detect domain changes.
    """
    lines = [
        "[req]",
        "default_bits        = 2048",
        "distinguished_name  = req_distinguished_name",
        "req_extensions      = req_ext",
        "prompt              = no",
        "",
        "[req_distinguished_name]",
        "C                   = AU",
        "ST                  = Some-State",
        "O                   = Internet Widgits Pty Ltd",
        "OU                  = IT Department",
        f"CN                  = {first_server}",
        f"emailAddress        = contact@{first_server}",
        "",
        "[req_ext]",
        "subjectAltName = @alt_names",
        "",
        "[alt_names]",
    ]
    for index, domain in enumerate(domains, start=1):
        lines.append(f"DNS.{index} = {domain}")
    return "\n".join(lines) + "\n"


def request_type_for(cert_type: str) -> str:
    """Map the plugin's cert type to the Cloudflare Origin CA ``request_type``."""
    return "origin-ecc" if cert_type == "ecdsa" else "origin-rsa"


def select_zone_name(domains: List[str]) -> str:
    """Pick the most likely zone name to query from a service's domains.

    Strips the first label of multi-label domains to a registrable-ish suffix, then
    returns the shortest candidate. NOTE: this is public-suffix-naive — for second-level
    ccTLDs (e.g. ``a.co.uk`` -> ``co.uk``) set ``CLOUDFLARE_ZONE_ID`` explicitly.
    """
    wildcards = set()
    for domain in domains:
        parts = domain.split(".")
        if len(parts) > 2:
            wildcards.add(".".join(parts[1:]))
        else:
            wildcards.add(domain)
    if not wildcards:
        return ""
    return min(wildcards, key=len)


def select_zone(zones: List[Dict]) -> Optional[Dict]:
    """From candidate zones, pick the one with the most recent ``modified_on``."""
    if not zones:
        return None
    return max(zones, key=lambda z: z.get("modified_on") or "1970-01-01T00:00:00Z")


def parse_expires_on(value) -> datetime:
    """Parse a Cloudflare ``expires_on`` timestamp into a tz-aware datetime.

    Origin CA returns the Go style ``2024-01-01 00:00:00 +0000 UTC``; we also accept
    RFC3339 in case the API changes. Falls back to the epoch (treated as expired) for
    anything non-string (the SDK exposes ``expires_on`` as Optional[str], i.e. may be None).
    """
    if not isinstance(value, str):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    for fmt in ("%Y-%m-%d %H:%M:%S %z %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        with suppress(ValueError):
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def is_expired(expires_on: str, now: Optional[datetime] = None) -> bool:
    """True if the given ``expires_on`` is at or before ``now`` (default: utcnow)."""
    now = now or datetime.now(timezone.utc)
    return now >= parse_expires_on(expires_on)


def hostnames_match(cert_hostnames: List[str], domains: List[str]) -> bool:
    """True if a certificate's hostname set exactly matches the service's domains."""
    return set(cert_hostnames) == set(domains)


def find_matching_cert(certs: List[Dict], domains: List[str], now: Optional[datetime] = None) -> Tuple[Optional[str], bool, bool]:
    """Find an existing Origin CA cert whose hostnames match the service's domains.

    Returns ``(cert_id, found, expired)``. ``cert_id``/``found`` describe the match;
    ``expired`` is True when the matched cert is past its ``expires_on``.
    """
    now = now or datetime.now(timezone.utc)
    for cert in certs:
        if hostnames_match(cert.get("hostnames", []), domains):
            return cert.get("id"), True, is_expired(cert.get("expires_on", ""), now)
    return None, False, False
