#!/usr/bin/env python3
"""Deterministic mock of the Cloudflare API for the cloudflare plugin e2e tests.

Implements just enough of the REST surface the plugin's Origin CA flow uses (the
official `cloudflare` SDK is pointed here via CLOUDFLARE_API_URL):

  GET    /user/tokens/verify   -> active token
  GET    /zones                -> one active zone (only hit if no CLOUDFLARE_ZONE_ID)
  GET    /certificates         -> [] (forces a fresh generation)
  POST   /certificates         -> SIGNS the submitted CSR with a mock Origin CA and
                                  echoes the CSR back verbatim (the job verifies the
                                  returned csr == the one it sent)
  GET    /certificates/<id>    -> the stored cert
  DELETE /certificates/<id>    -> revoke
  GET    /aop-ca.pem           -> the mock CA in PEM (Authenticated Origin Pull CA)

Each request is logged to stdout so the test can assert the plugin reached the mock.
"""

import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_NOW = datetime.now(timezone.utc)

# Mock Origin CA (also reused as the Authenticated Origin Pull CA).
_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock Cloudflare Origin CA")])
_ca_cert = (
    x509.CertificateBuilder()
    .subject_name(_ca_name)
    .issuer_name(_ca_name)
    .public_key(_ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(_NOW - timedelta(days=1))
    .not_valid_after(_NOW + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(_ca_key, hashes.SHA256())
)
_CA_PEM = _ca_cert.public_bytes(serialization.Encoding.PEM)

_certs = {}


def sign_csr(csr_pem: str) -> str:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(_ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=3650))
    )
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass
    return builder.sign(_ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def envelope(result):
    return {"success": True, "errors": [], "messages": [], "result": result}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        print(f"MOCK {self.command} {self.path}", flush=True)

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self._send(404, {"success": False, "errors": [{"code": 1, "message": "not found"}], "messages": [], "result": None})

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/user/tokens/verify":
            return self._send(200, envelope({"id": "mock-token", "status": "active"}))
        if path == "/aop-ca.pem":
            return self._send_raw(200, _CA_PEM, "application/x-pem-file")
        if path == "/zones":
            zone = {"id": "zone-mock-123", "name": "example.com", "status": "active", "type": "full", "modified_on": "2025-01-01T00:00:00Z"}
            obj = envelope([zone])
            obj["result_info"] = {"page": 1, "per_page": 25, "count": 1, "total_count": 1}
            return self._send(200, obj)
        if path == "/certificates":
            obj = envelope([])
            obj["result_info"] = {"page": 1, "per_page": 25, "count": 0, "total_count": 0}
            return self._send(200, obj)
        if path.startswith("/certificates/"):
            cert = _certs.get(path.rsplit("/", 1)[-1])
            return self._send(200, envelope(cert)) if cert else self._not_found()
        return self._not_found()

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        except Exception:
            body = {}
        if path == "/certificates":
            csr = body.get("csr", "")
            cert_id = f"cert-mock-{len(_certs) + 1}"
            result = {
                "id": cert_id,
                "certificate": sign_csr(csr),
                "csr": csr,  # exact echo: the plugin verifies result.csr == the CSR it sent
                "hostnames": body.get("hostnames", []),
                "request_type": body.get("request_type", "origin-rsa"),
                "requested_validity": body.get("requested_validity", 5475),
                "expires_on": "2039-01-01 00:00:00 +0000 UTC",
            }
            _certs[cert_id] = result
            return self._send(200, envelope(result))
        return self._not_found()

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/certificates/"):
            cert_id = path.rsplit("/", 1)[-1]
            _certs.pop(cert_id, None)
            return self._send(200, envelope({"id": cert_id}))
        return self._not_found()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
