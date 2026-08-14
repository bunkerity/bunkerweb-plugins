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
from typing import Any, Dict, List, Optional, Tuple, Union

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


def get_timeout(default: int = 10) -> int:
    """SYSWARDEN_TIMEOUT as an int, falling back to the default on garbage."""
    try:
        return int(getenv("SYSWARDEN_TIMEOUT", str(default)))
    except ValueError:
        return default


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
    session.verify = verify
    session.headers.update({"Authorization": f"Bearer {token}", "User-Agent": "bunkerweb-syswarden"})

    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=methods)
    adapter = FingerprintAdapter(fingerprint, max_retries=retry) if fingerprint else HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


def call(
    session: Session,
    peer: str,
    method: str,
    path: str,
    *,
    timeout: int = 10,
    payload: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Any]:
    """Call one peer. Returns ``(True, decoded_body)`` or ``(False, error_message)``.

    Never raises: a dead peer must not stop the pass on the other ones.
    """
    try:
        response = session.request(method, f"{peer}{path}", json=payload, timeout=timeout)
    except BaseException as e:
        return False, f"{method} {peer}{path} failed: {e}"

    if response.status_code != 200:
        return False, f"{method} {peer}{path} returned status {response.status_code}"
    try:
        return True, response.json()
    except (JSONDecodeError, ValueError) as e:
        return False, f"{method} {peer}{path} returned an unreadable body: {e}"


def extract_ips(body: Any) -> List[str]:
    """Pull the IP list out of a /ha/sync response, tolerating both shapes seen so far."""
    if isinstance(body, dict):
        body = body.get("ips", [])
    if not isinstance(body, list):
        return []
    return [entry.strip() for entry in body if isinstance(entry, str) and entry.strip()]
