#!/usr/bin/env python3
"""HTTP client shared by the three SysWarden jobs.

Holds everything the pure helpers can't: the TLS posture gate, the requests Session,
and the per-peer call wrapper. Kept out of syswarden_helpers.py so that module stays
importable (and unit-testable) without requests.
"""

from json import JSONDecodeError
from os import getenv
from pathlib import Path
from sys import exit as sys_exit
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from syswarden_helpers import get_env_secret, normalize_fingerprint, parse_peers  # type: ignore


class FingerprintAdapter(HTTPAdapter):
    """Pin the peer certificate by SHA-256 instead of validating a chain.

    SysWarden self-signs a per-host certificate (/var/lib/syswarden/ha/server.crt), so a
    CA bundle is often not an option. urllib3 checks the pin on the connection itself, so
    the certificate is verified during the handshake, not read back afterwards.
    """

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        return super().init_poolmanager(*args, **kwargs)


def get_timeout(default: int = 5) -> int:
    """SYSWARDEN_TIMEOUT bounded to 1-30 seconds."""
    try:
        value = int(getenv("SYSWARDEN_TIMEOUT", str(default)))
    except ValueError:
        return default
    return value if 1 <= value <= 30 else default


def tls_settings(logger) -> Tuple[Union[bool, str], str]:
    """Resolve the TLS posture as ``(verify, fingerprint)``.

    Order: CA bundle, then SHA-256 pin, then the explicit insecure opt-out. With none of
    the three the job exits 2 instead of quietly talking to an unverified peer — the
    bearer token travels on this connection, so a silent downgrade would hand it to
    whoever answers.
    """
    ca_bundle = getenv("SYSWARDEN_CA_BUNDLE", "").strip()
    if ca_bundle:
        if Path(ca_bundle).is_file():
            return ca_bundle, ""
        logger.warning(f"SYSWARDEN_CA_BUNDLE is set to {ca_bundle} but that file is not readable, falling back...")

    fingerprint = normalize_fingerprint(getenv("SYSWARDEN_SSL_FINGERPRINT", ""))
    if fingerprint:
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            logger.error("SYSWARDEN_SSL_FINGERPRINT is not a SHA-256 fingerprint (64 hex chars), refusing to contact the peers...")
            sys_exit(2)
        # The pin replaces chain validation, so requests must not also reject the self-signed cert.
        disable_warnings(InsecureRequestWarning)
        return False, fingerprint

    if getenv("SYSWARDEN_SSL_INSECURE", "no") == "yes":
        logger.warning("SYSWARDEN_SSL_INSECURE is set: talking to SysWarden without verifying its certificate, the API token is exposed to an active MITM")
        disable_warnings(InsecureRequestWarning)
        return False, ""

    logger.error("No usable TLS setting: set SYSWARDEN_CA_BUNDLE, or SYSWARDEN_SSL_FINGERPRINT, or SYSWARDEN_SSL_INSECURE=yes to accept the risk")
    sys_exit(2)


def get_peers(logger) -> List[str]:
    """Parse SYSWARDEN_PEERS into base URLs. Exits 2 when none is usable."""
    urls, errors = parse_peers(getenv("SYSWARDEN_PEERS", ""))
    for error in errors:
        logger.error(f"Ignoring malformed SYSWARDEN_PEERS entry: {error}")
    if not urls:
        logger.error("No usable SysWarden peer, set SYSWARDEN_PEERS (host or host:port, default port 62026)")
        sys_exit(2)
    return urls


def make_session(logger, *, methods: Tuple[str, ...] = ("GET",)) -> Session:
    """Build the shared Session: TLS posture, retries and the bearer token.

    An empty token is refused: SysWarden skips the token check entirely when its own
    [integrations.ha] token is empty (ha_api.go), which leaves the peer authenticating on
    the source IP alone. That is not a posture to build an integration on.
    """
    token = get_env_secret("SYSWARDEN_API_TOKEN").removeprefix("Bearer ").strip()
    if not token:
        logger.error("SYSWARDEN_API_TOKEN is required (a peer with an empty token authenticates on the peer IP alone)")
        sys_exit(2)

    verify, fingerprint = tls_settings(logger)

    session = Session()
    # SysWarden peers are private, explicitly configured destinations. Ignoring ambient
    # proxy variables also keeps fingerprint pinning on the adapter's direct pool.
    session.trust_env = False
    session.verify = verify
    session.headers.update({"Authorization": f"Bearer {token}", "User-Agent": "bunkerweb-syswarden"})

    retry = Retry(
        total=1,
        backoff_factor=0.25,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=methods,
        respect_retry_after_header=False,
    )
    adapter = FingerprintAdapter(fingerprint, max_retries=retry) if fingerprint else HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


def call(
    session: Session,
    peer: str,
    method: str,
    path: str,
    *,
    timeout: int = 5,
    payload: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Any]:
    """Call one peer. Returns ``(True, decoded_body)`` or ``(False, error_message)``.

    Never raises: a dead peer must not stop the pass on the other ones.
    """
    try:
        response = session.request(method, f"{peer}{path}", json=payload, timeout=timeout, allow_redirects=False)
    except Exception as e:
        return False, f"{method} {peer}{path} failed: {e}"

    if response.status_code != 200:
        return False, f"{method} {peer}{path} returned status {response.status_code}"
    try:
        return True, response.json()
    except (JSONDecodeError, ValueError) as e:
        return False, f"{method} {peer}{path} returned an unreadable body: {e}"


def extract_ips(body: Any) -> Optional[List[str]]:
    """Pull a complete IP list from a /ha/sync response.

    A peer with an empty blocklist answers ``{"ips": null}``, which lands here as an
    authoritative empty list. Missing or malformed fields return ``None`` instead, so a
    broken response can never masquerade as "the peer holds nothing".
    """
    if isinstance(body, dict):
        if "ips" not in body:
            return None
        body = body.get("ips")
    if body is None:
        return []
    if not isinstance(body, list) or any(not isinstance(entry, str) for entry in body):
        return None
    return [entry.strip() for entry in body if entry.strip()]


def fetch_capabilities(session: Session, peer: str, *, timeout: int = 5) -> Tuple[bool, Set[str]]:
    """Ask a peer what its HA API can do, through ``GET /ha/status``.

    Returns ``(reachable, capabilities)``. A peer that predates capability reporting
    answers without the field, which yields an empty set. The push job treats that peer
    as readable but unsupported for mutation. The set is also empty when the peer has
    ``integrations.bunkerweb.enabled`` off.

    An unreachable or malformed peer is not reported as capability-less: both cases make
    the cluster preflight incomplete and block every mutation.
    """
    try:
        response = session.get(f"{peer}/ha/status", timeout=timeout, allow_redirects=False)
    except Exception:
        return False, set()
    if response.status_code != 200:
        return False, set()
    try:
        body = response.json()
    except (JSONDecodeError, ValueError):
        return False, set()
    if not isinstance(body, dict):
        return False, set()
    capabilities = body.get("capabilities")
    if capabilities is None:
        return True, set()
    if not isinstance(capabilities, list) or any(not isinstance(entry, str) for entry in capabilities):
        return False, set()
    return True, set(capabilities)


def fetch_sync(session: Session, peer: str, *, timeout: int = 5, details: bool = False, page_size: int = 500) -> Tuple[bool, Dict[str, List]]:
    """Read a peer's blocklist through ``GET /ha/sync``, following the provenance pages.

    Returns ``(ok, {"ips": [...], "bans": [...]})``. ``ips`` is the whole blocklist the
    peer enforces, static entries included; ``bans`` is the ledger of expiring bans with
    their provenance, and stays empty unless ``details`` is set and the peer supports it.

    ``bans`` is omitted from the answer when the ledger is empty, so an empty list here
    means "nothing expiring", never "unsupported". Mutation support comes from the
    peer's advertised capabilities, not from the shape of this answer.
    """
    snapshot: Dict[str, List] = {"ips": [], "bans": []}
    params: Dict[str, Any] = {"details": "true", "limit": page_size} if details else {}
    # Bounded rather than while True: the ledger holds at most maxHALedgerRecords (16384)
    # entries, so a cursor that keeps pointing forward is a bug on the other side.
    for page in range(64):
        try:
            response = session.get(f"{peer}/ha/sync", params=params or None, timeout=timeout, allow_redirects=False)
        except Exception:
            return False, snapshot
        if response.status_code != 200:
            return False, snapshot
        try:
            body = response.json()
        except (JSONDecodeError, ValueError):
            return False, snapshot
        if not isinstance(body, dict):
            return False, snapshot
        if page == 0:
            ips = extract_ips(body)
            if ips is None:
                return False, snapshot
            snapshot["ips"] = ips
        entries = body.get("bans", [])
        if details:
            if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                return False, snapshot
            snapshot["bans"].extend(entries)
        cursor = body.get("next_cursor")
        if not details or cursor is None:
            return True, snapshot
        if not isinstance(cursor, str) or not cursor:
            return False, snapshot
        params = {"details": "true", "limit": page_size, "cursor": cursor}
    return False, snapshot
