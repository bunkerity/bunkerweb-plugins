#!/usr/bin/env python3

from os import getenv, sep
from os.path import dirname, join
from sys import exit as sys_exit, path as sys_path

# BunkerWeb deps + this job's own directory (for cloudflare_helpers).
sys_path.insert(0, dirname(__file__))
for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from logger import setup_logger  # type: ignore
from common_utils import bytes_hash  # type: ignore
from jobs import Job  # type: ignore

from cloudflare_helpers import CF_IPS_V4_DEFAULT_URL, CF_IPS_V6_DEFAULT_URL, check_line  # type: ignore

LOGGER = setup_logger("CLOUDFLARE.TRUSTED-IPS-DOWNLOAD", getenv("LOG_LEVEL", "INFO"))
try:
    _timeout = int(getenv("CLOUDFLARE_API_TIMEOUT", "10"))
except ValueError:
    _timeout = 10
status = 0


def make_session() -> Session:
    """A requests Session with retry/backoff on transient errors."""
    session = Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET",))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


try:
    # Check if at least a server has Cloudflare activated
    cf_activated = False
    # Multisite case
    if getenv("MULTISITE", "no") == "yes":
        servers = getenv("SERVER_NAME", [])

        if isinstance(servers, str):
            servers = servers.split(" ")

        for first_server in servers:
            if getenv(f"{first_server}_USE_CLOUDFLARE", getenv("USE_CLOUDFLARE", "no")) == "yes":
                cf_activated = True
                break
    # Singlesite case
    elif getenv("USE_CLOUDFLARE", "no") == "yes":
        cf_activated = True

    if not cf_activated:
        LOGGER.info("Cloudflare is not activated, skipping trusted IPs download...")
        sys_exit(0)

    JOB = Job(LOGGER, __file__)

    # Don't go further if the cache is fresh (the job runs daily; CF ranges change rarely)
    if JOB.is_cached_file("ipv4.list", "day") and JOB.is_cached_file("ipv6.list", "day"):
        LOGGER.info("Cloudflare's IPv4 and IPv6 trusted IPs/nets lists are already in cache, skipping download...")
        sys_exit(0)

    # URLs are overridable (testing / Cloudflare-compatible mirrors); each pair carries
    # its own type so an override URL is never mislabelled by sniffing its suffix.
    sources = (
        (getenv("CLOUDFLARE_IPS_V4_URL", CF_IPS_V4_DEFAULT_URL), "ipv4"),
        (getenv("CLOUDFLARE_IPS_V6_URL", CF_IPS_V6_DEFAULT_URL), "ipv6"),
    )

    session = make_session()

    # Download and write data to cache
    for url, _type in sources:
        i = 0
        content = b""
        try:
            LOGGER.info(f"Downloading Cloudflare's {_type} list from {url}...")
            resp = session.get(url, stream=True, timeout=_timeout, allow_redirects=True, verify=True)

            if resp.status_code != 200:
                LOGGER.warning(f"Got status code {resp.status_code}, skipping {_type} list download...")
                status = 2
                continue

            for line in resp.iter_lines():
                line = line.strip().split(b" ")[0]

                if not line or line.startswith((b"#", b";")):
                    continue

                ok, data = check_line(line)
                if ok:
                    content += data + b"\n"
                    i += 1

            if not content:
                LOGGER.warning(f"No valid {_type} IPs/nets found at {url}, skipping...")
                status = 2
                continue

            # Check if file has changed
            new_hash = bytes_hash(content)
            old_hash = JOB.cache_hash(f"{_type}.list")
            if new_hash == old_hash:
                LOGGER.info(f"New {_type}.list file is identical to cache file, reload is not needed")
                continue

            # Put file in cache
            cached, err = JOB.cache_file(f"{_type}.list", content, checksum=new_hash)
            if not cached:
                LOGGER.error(f"Error while caching {_type} list : {err}")
                status = 2
                continue

            LOGGER.info(f"Downloaded {i} trusted {_type} IPs/nets")

            status = status or 1
        except BaseException as e:
            status = 2
            LOGGER.error(f"Exception while getting Cloudflare {_type} list from {url} :\n{e}")
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.exception("Exception while running cf-trusted-ips-download.py")

sys_exit(status)
