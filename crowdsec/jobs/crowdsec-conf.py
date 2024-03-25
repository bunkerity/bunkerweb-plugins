#!/usr/bin/env python3

from os import getenv, sep
from os.path import join
from pathlib import Path
from sys import exit as sys_exit, path as sys_path
from traceback import format_exc


for deps_path in [join(sep, "usr", "share", "bunkerweb", *paths) for paths in (("deps", "python"), ("utils",), ("db",))]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from jinja2 import Environment, FileSystemLoader
from logger import setup_logger  # type: ignore
from jobs import Job  # type: ignore

LOGGER = setup_logger("CROWDSEC", getenv("LOG_LEVEL", "INFO"))
PLUGIN_PATH = Path(sep, "etc", "bunkerweb", "plugins", "crowdsec")
status = 0

try:
    # Check if at least a server has CrowdSec activated
    cs_activated = False
    # Multisite case
    if getenv("MULTISITE", "no") == "yes":
        for first_server in getenv("SERVER_NAME", "").strip().split(" "):
            if getenv(f"{first_server}_USE_CROWDSEC", getenv("USE_CROWDSEC", "no")) == "yes":
                cs_activated = True
                break
    # Singlesite case
    elif getenv("USE_CROWDSEC", "no") == "yes":
        cs_activated = True

    if not cs_activated:
        LOGGER.info("CrowdSec is not activated, skipping job...")
        sys_exit(status)

    JOB = Job(LOGGER)

    # Generate content
    jinja_env = Environment(loader=FileSystemLoader(PLUGIN_PATH.joinpath("misc")))
    content = (
        jinja_env.get_template("crowdsec.conf")
        .render(
            CROWDSEC_API=getenv("CROWDSEC_API", ""),
            CROWDSEC_API_KEY=getenv("CROWDSEC_API_KEY", ""),
            CROWDSEC_REQUEST_TIMEOUT=getenv("CROWDSEC_REQUEST_TIMEOUT", "500"),
            CROWDSEC_STREAM_REQUEST_TIMEOUT=getenv("CROWDSEC_STREAM_REQUEST_TIMEOUT", "15000"),
            CROWDSEC_UPDATE_FREQUENCY=getenv("CROWDSEC_UPDATE_FREQUENCY", "10"),
            CROWDSEC_MODE=getenv("CROWDSEC_MODE", "live"),
        )
        .encode()
    )

    # Update db
    cached, err = JOB.cache_file("crowdsec.conf", content)
    if not cached:
        LOGGER.error(f"Error while caching crowdsec.conf file : {err}")

    # Done
    LOGGER.info("CrowdSec configuration successfully generated")
except SystemExit as e:
    status = e.code
except:
    status = 2
    LOGGER.error(f"Exception while running crowdsec-init.py :\n{format_exc()}")

sys_exit(status)
