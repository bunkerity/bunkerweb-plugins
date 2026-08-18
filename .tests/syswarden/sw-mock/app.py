#!/usr/bin/env python3
"""Deterministic mock of SysWarden's HA API for the syswarden plugin e2e tests.

Implements the surface the plugin uses, over TLS on :62026, with the bearer + peer-IP
authorization SysWarden enforces:

  GET    /ha/sync                 -> {"ips": [...]} (null when empty, as SysWarden does)
  GET    /ha/sync?details=true    -> the same plus {"bans": [...], "next_cursor": ...},
                                     the provenance view, paginated like the real one
  POST   /ha/sync                 -> {"ips": [...]} (permanent) or {"bans": [{ip, ttl,
                                     reason, source}, ...]} (expiring, with provenance)
  DELETE /ha/sync                 -> {"ips": [...]} or {"bans": [{ip, source}, ...]}, the
                                     second only removing records of that source
  GET    /ha/status               -> {hostname, os, version, status}
  GET    /ha/telemetry            -> the dashboard payload, whitelist included

`SW_MOCK_LEGACY=yes` drops the provenance half: the query string is ignored and the ban
payloads are refused, which is how a pre-provenance SysWarden behaves. That is what makes
the plugin's per-peer capability detection testable.

Every request is logged to stdout, with the decoded payload, so the test can assert what
the plugin actually sent rather than just what it claims to have done.
"""

import json
import re
import ssl
from base64 import urlsafe_b64decode, urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from os import getenv
from threading import Lock
from time import gmtime, strftime, time
from urllib.parse import parse_qs, urlparse

TOKEN = getenv("SW_MOCK_TOKEN", "")
LEGACY = getenv("SW_MOCK_LEGACY", "no") == "yes"
# Peer allowlist, CIDR accepted the way current SysWarden does. Empty means "any", which
# only exists so the mock stays usable when the test does not care about that check.
PEERS = [ip_network(entry, strict=False) for entry in getenv("SW_MOCK_PEERS", "").split() if entry]

# Entries an operator added on the SysWarden side (`syswarden block`). They carry no
# provenance, so the plugin must never delete them.
OPERATOR_IPS = set(getenv("SW_MOCK_OPERATOR_IPS", "").split())
# Extra addresses served in the blocklist so the pull direction has something to deny on.
SEEDED_IPS = set(getenv("SW_MOCK_SEEDED_IPS", "").split())
WHITELIST_IPS = [entry for entry in getenv("SW_MOCK_WHITELIST_IPS", "").split() if entry]

# (ip, source) -> expiry timestamp, the ledger the provenance view reports on.
_ledger = {}
# (ip, source) -> the reason that came with the ban, echoed back in the provenance view.
_reasons = {}
# Permanent entries pushed through the legacy {"ips": [...]} payload.
_permanent = set()
_lock = Lock()

_SOURCE_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,64}$")
MIN_TTL = 1
MAX_TTL = 30 * 24 * 3600
MAX_BANS = 500


def active_ledger(now):
    return {key: expires for key, expires in _ledger.items() if expires > now}


def blocklist(now):
    ips = OPERATOR_IPS | SEEDED_IPS | _permanent
    ips.update(ip for ip, _ in active_ledger(now))
    return sorted(ips)


def provenance(now):
    return [
        {
            "ip": ip,
            "source": source,
            "reason": _reasons.get((ip, source), ""),
            "peer_scope": "0.0.0.0/0",
            "origin_peer_ip": "mock",
            "expires_at": strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(expires)),
        }
        for (ip, source), expires in sorted(active_ledger(now).items())
    ]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002
        print(f"MOCK {self.command} {self.path}", flush=True)

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        print(f"MOCK REFUSED {self.command} {self.path} -> {code} {message}", flush=True)
        body = f"{message}\n".encode()
        # A refusal can happen before the request body was read, which would leave the
        # keep-alive connection desynchronized for the next request on it.
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        if PEERS:
            try:
                peer = ip_address(self.client_address[0])
            except ValueError:
                self._error(403, "Forbidden")
                return False
            if not any(peer in allowed for allowed in PEERS):
                self._error(403, "Forbidden")
                return False
        # SysWarden refuses to start without a token, so the mock always demands one.
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._error(401, "Unauthorized")
            return False
        return True

    def _payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return None
        print(f"MOCK BODY {self.command} {self.path} {json.dumps(body, sort_keys=True)}", flush=True)
        return body if isinstance(body, dict) else None

    def do_GET(self):
        if not self._authorized():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/ha/status":
            if LEGACY:
                # A peer that predates capability reporting: no api_version, no
                # capabilities. This is the field the plugin keys its dialect on.
                return self._send(200, {"hostname": "sw-mock-legacy", "os": "linux", "version": "v4.02.8", "status": "online"})
            return self._send(
                200,
                {
                    "hostname": "sw-mock",
                    "os": "linux",
                    "version": "v4.02.14",
                    "status": "online",
                    "api_version": "2",
                    "capabilities": ["auth_all_routes", "peer_cidr", "sync_ttl", "sync_provenance", "tls_verified_client"],
                },
            )
        if parsed.path == "/ha/telemetry":
            return self._send(200, self._telemetry())
        if parsed.path != "/ha/sync":
            return self._error(404, "Not Found")

        now = time()
        with _lock:
            payload: dict = {"ips": blocklist(now) or None}
            if not parsed.query or LEGACY:
                # A legacy peer ignores the query string entirely, which is exactly what
                # makes an empty ledger indistinguishable from it without the probe.
                return self._send(200, payload)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if set(query) - {"details", "limit", "cursor"} or query.get("details") != ["true"]:
                return self._error(400, "Invalid provenance query")
            limit = int(query.get("limit", ["100"])[0] or "100")
            if not 1 <= limit <= MAX_BANS:
                return self._error(400, "Invalid provenance limit")
            start = 0
            if query.get("cursor"):
                try:
                    start = int(urlsafe_b64decode(query["cursor"][0] + "==").decode())
                except ValueError:
                    return self._error(400, "Invalid provenance cursor")
            bans = provenance(now)
            if start > len(bans):
                return self._error(400, "Invalid provenance cursor")
            end = min(start + limit, len(bans))
            if bans[start:end]:
                payload["bans"] = bans[start:end]
            if end < len(bans):
                payload["next_cursor"] = urlsafe_b64encode(str(end).encode()).decode().rstrip("=")
            return self._send(200, payload)

    def _telemetry(self):
        now = time()
        with _lock:
            banned = len(active_ledger(now)) + len(_permanent)
        return {
            "github_release": "v4.02.14",
            "system": {"hostname": "sw-mock", "os": "linux", "services": [], "ports": []},
            "layer3": {"global_blocked": 42, "geoip_blocked": 7, "asn_blocked": 3, "l7_banned": banned},
            "waf": {"total_banned": banned, "total_detected": 12, "active_signatures": 99, "top_attackers": [], "targeted_ports": []},
            "whitelist": {"active_ips": len(WHITELIST_IPS), "ips": WHITELIST_IPS},
        }

    def _decode_bans(self, body, expiring):
        """Validate a ban array the way SysWarden does. Returns None on a refusal."""
        items = body.get("bans")
        if not isinstance(items, list) or not items or len(items) > MAX_BANS:
            return None
        decoded = []
        for item in items:
            if not isinstance(item, dict) or len(item) != (4 if expiring else 2):
                return None
            ip, source = item.get("ip"), item.get("source")
            if not isinstance(ip, str) or not isinstance(source, str) or not _SOURCE_RE.match(source):
                return None
            ttl, reason = None, ""
            if expiring:
                ttl, reason = item.get("ttl"), item.get("reason")
                if not isinstance(ttl, int) or isinstance(ttl, bool) or not MIN_TTL <= ttl <= MAX_TTL:
                    return None
                if not isinstance(reason, str) or not reason.strip() or len(reason.encode()) > 512:
                    return None
            decoded.append((ip, source, ttl, reason))
        return decoded

    def do_POST(self):
        if not self._authorized():
            return
        if urlparse(self.path).path != "/ha/sync":
            return self._error(404, "Not Found")
        body = self._payload()
        if body is None:
            return self._error(400, "Invalid JSON")

        if "bans" in body:
            if LEGACY:
                return self._error(400, "Invalid JSON")
            decoded = self._decode_bans(body, expiring=True)
            if decoded is None:
                return self._error(400, "Invalid temporary ban batch")
            now = time()
            with _lock:
                for ip, source, ttl, reason in decoded:
                    _ledger[(ip, source)] = max(_ledger.get((ip, source), 0), now + ttl)
                    _reasons[(ip, source)] = reason
            return self._send(200, {"status": "ok"})

        ips = body.get("ips")
        if not isinstance(ips, list) or any(not isinstance(entry, str) for entry in ips):
            return self._error(400, "Invalid JSON")
        with _lock:
            _permanent.update(ips)
        return self._send(200, {"status": "ok"})

    def do_DELETE(self):
        if not self._authorized():
            return
        if urlparse(self.path).path != "/ha/sync":
            return self._error(404, "Not Found")
        body = self._payload()
        if body is None:
            return self._error(400, "Invalid JSON")

        if "bans" in body:
            if LEGACY:
                return self._error(400, "Invalid JSON")
            decoded = self._decode_bans(body, expiring=False)
            if decoded is None:
                return self._error(400, "Invalid temporary ban batch")
            with _lock:
                # Keyed on (ip, source): an operator entry with another provenance, or no
                # provenance at all, is out of reach of this delete.
                for ip, source, _, _ in decoded:
                    _ledger.pop((ip, source), None)
                    _reasons.pop((ip, source), None)
            return self._send(200, {"status": "ok"})

        ips = body.get("ips")
        if not isinstance(ips, list) or any(not isinstance(entry, str) for entry in ips):
            return self._error(400, "Invalid JSON")
        with _lock:
            _permanent.difference_update(ips)
        return self._send(200, {"status": "ok"})


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/certs/server.crt", "/certs/server.key")
    server = ThreadingHTTPServer(("0.0.0.0", 62026), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"MOCK ready legacy={LEGACY} peers={[str(peer) for peer in PEERS]}", flush=True)
    server.serve_forever()
