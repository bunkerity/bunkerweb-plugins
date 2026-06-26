#!/usr/bin/env python3

from datetime import datetime
from json import dumps
from os import getenv, sep
from os.path import dirname, join
from pathlib import Path
from subprocess import run
from sys import exit as sys_exit, path as sys_path
from typing import Dict

# BunkerWeb deps + this job's own directory (for cloudflare_helpers).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from cloudflare import APIError, Cloudflare  # type: ignore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from logger import setup_logger  # type: ignore
from jobs import Job  # type: ignore

from cloudflare_helpers import (  # type: ignore
    CF_API_DEFAULT_URL,
    build_csr_config,
    find_matching_cert,
    get_env_secret,
    is_expired,
    request_type_for,
    select_zone,
    select_zone_name,
)

LOGGER = setup_logger("CLOUDFLARE.MANAGE-ORIGIN-CERTS", getenv("LOG_LEVEL", "INFO"))
CLOUDFLARE_API_URL = getenv("CLOUDFLARE_API_URL", CF_API_DEFAULT_URL).rstrip("/")
try:
    CLOUDFLARE_API_TIMEOUT = float(getenv("CLOUDFLARE_API_TIMEOUT", "10"))
except ValueError:
    CLOUDFLARE_API_TIMEOUT = 10.0
CACHE_PATH = Path(sep, "var", "cache", "bunkerweb", "cloudflare")
status = 0

# Cache one SDK client per token (multisite services may use distinct tokens).
_clients: Dict[str, Cloudflare] = {}


def get_client(api_token: str) -> Cloudflare:
    if api_token not in _clients:
        _clients[api_token] = Cloudflare(api_token=api_token, base_url=CLOUDFLARE_API_URL, timeout=CLOUDFLARE_API_TIMEOUT)
    return _clients[api_token]


def token_is_active(client: Cloudflare) -> bool:
    """Verify the API token via /user/tokens/verify."""
    try:
        result = client.user.tokens.verify()
        return getattr(result, "status", None) == "active"
    except APIError as e:
        LOGGER.error(f"Failed to verify API token: {e}")
        return False


def revoke_cert(client: Cloudflare, first_server: str, cert_id: str) -> bool:
    """Revoke an Origin CA cert on Cloudflare, THEN clear the local cache.

    Order matters: if we cleared the cache first and the API delete failed, the cert
    would be orphaned on Cloudflare with no local id left to revoke it.
    """
    try:
        client.origin_ca_certificates.delete(cert_id)
    except APIError as e:
        message = str(e)
        if "already revoked" not in message.casefold():
            LOGGER.error(f"Failed to revoke origin certificate {cert_id}: {e}")
            return False
        LOGGER.warning(f"Certificate {cert_id} was already revoked")

    for name in ("cert.id", "origin_cert.pem", "private.key", "csr.pem", "csr.conf"):
        JOB.del_cache(name, service_id=first_server)
    return True


try:
    # Check if at least a server has Cloudflare activated. Keep the original case: the
    # service id is the cache-dir name the Lua side reads back (it uses the original-case
    # SERVER_NAME). Domains/CF hostnames are lowercased separately below.
    servers = getenv("SERVER_NAME", "") or []

    if isinstance(servers, str):
        servers = servers.split(" ")

    if not servers:
        LOGGER.error("There are no server names, skipping generation...")
        sys_exit(0)

    cf_activated = False
    is_multisite = getenv("MULTISITE", "no") == "yes"

    # Multisite case
    if is_multisite:
        for first_server in servers:
            if first_server and (
                getenv(f"{first_server}_USE_CLOUDFLARE", getenv("USE_CLOUDFLARE", "no")) == "yes"
                or get_env_secret(f"{first_server}_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN")
            ):
                cf_activated = True
                break
    # Singlesite case
    elif getenv("USE_CLOUDFLARE", "no") == "yes" or get_env_secret("CLOUDFLARE_API_TOKEN"):
        servers = [servers[0]]
        cf_activated = True

    if not cf_activated:
        LOGGER.info("Cloudflare is not activated, skipping origin certs generation...")
        sys_exit(0)

    JOB = Job(LOGGER, __file__)

    valid_tokens = set()
    invalid_tokens = set()
    for first_server in servers:
        if not first_server:
            continue
        service_cache_path = CACHE_PATH.joinpath(first_server)

        cert_id_file = service_cache_path.joinpath("cert.id")
        origin_cert_file = service_cache_path.joinpath("origin_cert.pem")
        csr_file = service_cache_path.joinpath("csr.pem")
        private_key_file = service_cache_path.joinpath("private.key")
        csr_conf_file = service_cache_path.joinpath("csr.conf")

        # * Getting all the necessary data (api_token / zone_id support the _FILE secret convention)
        api_token = get_env_secret(f"{first_server}_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN").strip().removeprefix("Bearer ").strip()
        data = {
            "use_cloudflare": getenv(f"{first_server}_USE_CLOUDFLARE", getenv("USE_CLOUDFLARE", "no")),
            "manage_origin_certs": getenv(f"{first_server}_CLOUDFLARE_MANAGE_ORIGIN_CERTS", getenv("CLOUDFLARE_MANAGE_ORIGIN_CERTS", "yes")),
            "api_token": api_token,
            "domains": [
                domain for domain in (getenv(f"{first_server}_SERVER_NAME", getenv("SERVER_NAME", "")).lower() or first_server).strip().split(" ") if domain
            ],
            "zone_id": get_env_secret(f"{first_server}_CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ZONE_ID"),
            "type": getenv(f"{first_server}_CLOUDFLARE_ORIGIN_CERT_TYPE", getenv("CLOUDFLARE_ORIGIN_CERT_TYPE", "rsa")),
            "validity": getenv(f"{first_server}_CLOUDFLARE_ORIGIN_CERT_VALIDITY", getenv("CLOUDFLARE_ORIGIN_CERT_VALIDITY", "5475")),
        }

        if data["use_cloudflare"] != "yes" or data["manage_origin_certs"] != "yes":
            LOGGER.info(f"Skipping origin certs generation for {first_server} because it is not configured to use Cloudflare or manage origin certs")

            if cert_id_file.is_file():
                if not api_token or api_token in invalid_tokens or (api_token not in valid_tokens and not token_is_active(get_client(api_token))):
                    LOGGER.warning(
                        f"API token for {first_server} is either not set or invalid, therefore we cannot revoke the existing origin certificate, check your Cloudflare account to see if the certificate isn't still active"
                    )
                    for name in ("cert.id", "origin_cert.pem", "csr.pem", "private.key", "csr.conf"):
                        JOB.del_cache(name, service_id=first_server)
                else:
                    valid_tokens.add(api_token)
                    LOGGER.info(f"Revoking existing origin certificate for {first_server}...")
                    if revoke_cert(get_client(api_token), first_server, cert_id_file.read_text().strip()):
                        LOGGER.info(f"Successfully deleted existing origin certificate for {first_server}")
            elif origin_cert_file.is_file() or csr_file.is_file() or private_key_file.is_file() or csr_conf_file.is_file():
                LOGGER.warning(
                    f"Cache files found for {first_server} but no certificate ID, therefore we cannot revoke the existing origin certificate, check your Cloudflare account to see if the certificate isn't still active"
                )
                for name in ("origin_cert.pem", "csr.pem", "private.key", "csr.conf"):
                    JOB.del_cache(name, service_id=first_server)
            continue

        LOGGER.debug(f"Data for service {first_server}: {dumps({k: v for k, v in data.items() if k != 'api_token'})}")

        # * Checking if the data is valid
        if not data["api_token"]:
            LOGGER.warning(f"API token for {first_server} is not set, skipping origin certs generation...")
            status = 2
            continue

        client = get_client(data["api_token"])

        # * Checking if the API token is valid (cached across services)
        if data["api_token"] in invalid_tokens:
            LOGGER.warning(f"API token for {first_server} is invalid, skipping origin certs generation...")
            status = 2
            continue

        if data["api_token"] not in valid_tokens:
            LOGGER.info(f"Checking if the API token for {first_server} is valid...")
            if not token_is_active(client):
                invalid_tokens.add(data["api_token"])
                LOGGER.warning(f"API token for {first_server} is invalid or not active, skipping origin certs generation...")
                status = 2
                continue
            LOGGER.info(f"🔑 API token for {first_server} is valid ✅")
            valid_tokens.add(data["api_token"])

        service_cache_path.mkdir(parents=True, exist_ok=True)

        cert_id = None
        expired = False
        changed = False
        # * Inspecting the locally cached cert/key/CSR config to decide if we must act
        if cert_id_file.is_file():
            cert_id = cert_id_file.read_text().strip()

            if csr_conf_file.is_file():
                LOGGER.info(f"CSR configuration file found for {first_server}, checking if the subdomains have changed...")
                changed = csr_conf_file.read_text() != build_csr_config(first_server, data["domains"])

            if origin_cert_file.is_file() and private_key_file.is_file():
                LOGGER.info(f"Certificate file found for {first_server}, checking if the certificate is still valid...")
                certificate = x509.load_pem_x509_certificate(origin_cert_file.read_bytes(), default_backend())
                not_valid_after = certificate.not_valid_after_utc  # type: ignore[attr-defined]  # cryptography>=42 (image ships 49)
                if not_valid_after < datetime.now(tz=not_valid_after.tzinfo):
                    expired = True

                public_key = certificate.public_key()
                if isinstance(public_key, rsa.RSAPublicKey) and data["type"] == "ecdsa":
                    LOGGER.warning(f"Certificate type for {first_server} does not match the one we want to generate (ECDSA vs RSA)")
                    changed = True
                elif isinstance(public_key, ec.EllipticCurvePublicKey) and data["type"] == "rsa":
                    LOGGER.warning(f"Certificate type for {first_server} does not match the one we want to generate (RSA vs ECDSA)")
                    changed = True
            else:
                expired = True

        try:
            if not cert_id:
                # * Getting the zone ID if it is not set
                if not data["zone_id"]:
                    zone_name = select_zone_name(data["domains"])
                    LOGGER.info(f"Getting the active zone ID for {first_server} (querying zone '{zone_name}')...")

                    zones = [
                        {"id": z.id, "name": z.name, "type": getattr(z, "type", ""), "modified_on": str(getattr(z, "modified_on", ""))}
                        for z in client.zones.list(name=zone_name, status="active")
                    ]
                    if not zones:
                        LOGGER.error(f"No active zone found for {first_server}'s API token, skipping origin certs generation...")
                        status = 2
                        continue
                    if len(zones) > 1:
                        LOGGER.warning(f"More than one zone found for {first_server}, using the one with the most recent modification date...")

                    zone = select_zone(zones)
                    if not zone:
                        status = 2
                        continue
                    data["zone_id"] = zone.get("id", "")
                    if not data["zone_id"]:
                        status = 2
                        continue
                    LOGGER.info(f"🌐 Zone ID for {first_server} is {data['zone_id']} (name: {zone.get('name', '')}, type: {zone.get('type', '')})")

                # * Getting all existing origin certificates for the zone (SDK auto-paginates)
                certs = [
                    {"id": c.id, "hostnames": list(getattr(c, "hostnames", []) or []), "expires_on": getattr(c, "expires_on", "")}
                    for c in client.origin_ca_certificates.list(zone_id=data["zone_id"])
                ]

                cert_id, found, cert_expired = find_matching_cert(certs, data["domains"])
                if cert_expired:
                    expired = True
                if not found:
                    cert_id = None

                if cert_id and not expired:
                    if cert_id_file.is_file() and origin_cert_file.is_file() and private_key_file.is_file():
                        LOGGER.info(f"Origin certificate for {','.join(data['domains'])} already exists, skipping origin certs generation...")
                        continue
                    LOGGER.info(f"Origin certificate for {','.join(data['domains'])} exists on Cloudflare's side but not locally, regenerating it...")
                    expired = True
            elif not expired and not changed:
                LOGGER.info(
                    f"Origin certificate for {','.join(data['domains'])} already exists and is still valid locally, checking if it is still valid on Cloudflare's side..."
                )
                remote = client.origin_ca_certificates.get(cert_id)
                if is_expired(getattr(remote, "expires_on", "")):
                    expired = True
                else:
                    LOGGER.info(f"Origin certificate for {','.join(data['domains'])} is still valid on Cloudflare's side, no need to regenerate it")
                    continue
        except APIError as e:
            LOGGER.error(f"Cloudflare API error while resolving certificate state for {first_server}: {e}")
            status = 2
            continue

        if cert_id and (expired or changed):
            LOGGER.info(f"Origin certificate for {','.join(data['domains'])} has {'expired' if expired else 'changed'}, revoking it...")
            if revoke_cert(client, first_server, cert_id):
                LOGGER.info(f"Successfully deleted expired origin certificate for {','.join(data['domains'])}")
                cert_id = None

        # * Generating the CSR + private key if they are missing or the subdomains changed.
        # (CSRs have no expiry — regeneration is driven only by missing files / changes.)
        csr_content = csr_file.read_text() if csr_file.is_file() else None
        if not csr_content or changed:
            if changed:
                LOGGER.info(f"Subdomains for {first_server} have changed, generating a new Certificate Signing Request (CSR)...")
            else:
                LOGGER.info(f"Generating a Certificate Signing Request (CSR) for {first_server}")

            if changed or not csr_conf_file.is_file():
                content = build_csr_config(first_server, data["domains"]).encode()
                cached, err = JOB.cache_file("csr.conf", content, service_id=first_server)
                if not cached:
                    LOGGER.error(f"Error while caching csr.conf file for {first_server} : {err}")
                    status = 2
                    continue
                LOGGER.info(f"🔩 Successfully generated CSR configuration file for {first_server} ✅")

            command = [
                "openssl",
                "req",
                "-nodes",
                "-new",
                "-newkey",
                "-keyout",
                private_key_file.as_posix(),
                "-out",
                csr_file.as_posix(),
                "-config",
                csr_conf_file.as_posix(),
            ]
            if data["type"] == "ecdsa":
                command.insert(5, "ec")
                command.insert(6, "-pkeyopt")
                command.insert(7, "ec_paramgen_curve:prime256v1")
            else:
                command.insert(5, "rsa:2048")

            result = run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                LOGGER.error(f"CSR generation failed for {first_server}: {result.stderr}")
                status = 2
                continue

            cached, err = JOB.cache_file("csr.pem", csr_file, service_id=first_server, overwrite_file=False)
            if not cached:
                LOGGER.error(f"Error while caching csr.pem file for {first_server} : {err}")
                status = 2
                continue

            cached, err = JOB.cache_file("private.key", private_key_file, service_id=first_server, overwrite_file=False)
            if not cached:
                LOGGER.error(f"Error while caching private.key file for {first_server} : {err}")
                status = 2
                continue

            LOGGER.info(f"🔐 Successfully generated CSR for {first_server} ✅")
            csr_content = csr_file.read_text()
        else:
            LOGGER.info(f"Certificate Signing Request (CSR) for {first_server} is still valid, no need to regenerate it")

        # * Generating a new origin certificate
        LOGGER.info(f"Generating a new origin certificate for {','.join(data['domains'])}...")
        try:
            created = client.origin_ca_certificates.create(
                csr=csr_content,
                hostnames=data["domains"],
                request_type=request_type_for(data["type"]),
                requested_validity=int(data["validity"]),
            )
        except APIError as e:
            LOGGER.error(f"Failed to generate origin certificate for {','.join(data['domains'])}: {e}")
            status = 2
            continue

        # Tolerate whitespace/newline normalization by the API (the CSR is "newline-encoded")
        # so a successfully issued (already-billed) cert isn't discarded over a trailing \n.
        if (getattr(created, "csr", None) or "").strip() != csr_content.strip():
            LOGGER.error("CSR of generated certificate does not match the one we sent")
            status = 2
            continue

        cert_id = getattr(created, "id", None)
        cert_content = getattr(created, "certificate", None)
        if not cert_id or not cert_content:
            LOGGER.error("No certificate ID or content received from Cloudflare")
            status = 2
            continue

        cached, err = JOB.cache_file("origin_cert.pem", cert_content.encode(), service_id=first_server)
        if not cached:
            LOGGER.error(f"Error while caching origin_cert.pem file for {first_server} : {err}")
            status = 2
            continue

        cached, err = JOB.cache_file("cert.id", cert_id.encode(), service_id=first_server)
        if not cached:
            LOGGER.error(f"Error while caching cert.id file for {first_server} : {err}")
            status = 2
            continue

        LOGGER.info(f"📜 Successfully generated origin certificate for {','.join(data['domains'])} ✅")
        status = status or 1
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running cf-manage-origin-certs.py")

sys_exit(status)
