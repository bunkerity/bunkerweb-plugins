#!/usr/bin/env python3

from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for cloudflare_helpers).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from logger import setup_logger  # type: ignore
from common_utils import bytes_hash  # type: ignore
from jobs import Job  # type: ignore

from cloudflare_helpers import CF_AOP_CA_DEFAULT_URL  # type: ignore

LOGGER = setup_logger("CLOUDFLARE.AOP-CA-DOWNLOAD", getenv("LOG_LEVEL", "INFO"))
status = 0


def aop_enabled() -> bool:
    """True if any (multisite) service or the global config enables Authenticated Origin Pulls."""
    if getenv("MULTISITE", "no") == "yes":
        for server in getenv("SERVER_NAME", "").split():
            if (
                getenv(f"{server}_USE_CLOUDFLARE", getenv("USE_CLOUDFLARE", "no")) == "yes"
                and getenv(f"{server}_CLOUDFLARE_AUTHENTICATED_ORIGIN_PULLS", getenv("CLOUDFLARE_AUTHENTICATED_ORIGIN_PULLS", "no")) == "yes"
            ):
                return True
        return False
    return getenv("USE_CLOUDFLARE", "no") == "yes" and getenv("CLOUDFLARE_AUTHENTICATED_ORIGIN_PULLS", "no") == "yes"


try:
    if not aop_enabled():
        LOGGER.info("Authenticated Origin Pulls not enabled, skipping CA download...")
        sys_exit(0)

    JOB = Job(LOGGER, __file__)

    if JOB.is_cached_file("aop_ca.pem", "week"):
        LOGGER.info("Cloudflare Authenticated Origin Pull CA is already in cache, skipping download...")
        sys_exit(0)

    url = getenv("CLOUDFLARE_AOP_CA_URL", CF_AOP_CA_DEFAULT_URL)
    try:
        timeout = int(getenv("CLOUDFLARE_API_TIMEOUT", "10"))
    except ValueError:
        timeout = 10

    session = Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET",))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    LOGGER.info(f"Downloading Cloudflare Authenticated Origin Pull CA from {url}...")
    resp = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
    if resp.status_code != 200:
        LOGGER.error(f"Got status code {resp.status_code} while downloading the AOP CA, skipping...")
        sys_exit(2)

    content = resp.content
    # Validate it really is a PEM certificate before trusting it as a client CA.
    try:
        x509.load_pem_x509_certificate(content, default_backend())
    except Exception as e:
        LOGGER.error(f"Downloaded AOP CA is not a valid PEM certificate: {e}")
        sys_exit(2)

    new_hash = bytes_hash(content)
    if new_hash == JOB.cache_hash("aop_ca.pem"):
        LOGGER.info("AOP CA is identical to the cached one, reload is not needed")
        sys_exit(0)

    cached, err = JOB.cache_file("aop_ca.pem", content, checksum=new_hash)
    if not cached:
        LOGGER.error(f"Error while caching the AOP CA : {err}")
        sys_exit(2)

    LOGGER.info("🔒 Successfully downloaded the Cloudflare Authenticated Origin Pull CA ✅")
    status = 1
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running cf-aop-ca-download.py")

sys_exit(status)
