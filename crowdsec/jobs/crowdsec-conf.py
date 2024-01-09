#!/usr/bin/env python3

from os import getenv, sep
from os.path import join
from pathlib import Path
from sys import exit as sys_exit, path as sys_path
from traceback import format_exc

for deps_path in [
    join(sep, "usr", "share", "bunkerweb", *paths)
    for paths in (("deps", "python"), ("utils",), ("db",))
]:
    if deps_path not in sys_path:
        sys_path.append(deps_path)

from Database import Database  # type: ignore
from logger import setup_logger  # type: ignore
from jobs import set_file_in_db

logger = setup_logger("CROWDSEC", getenv("LOG_LEVEL", "INFO"))
status = 0

try:
    # Check if at least a server has CrowdSec activated
    cs_activated = False
    # Multisite case
    if getenv("MULTISITE", "no") == "yes":
        for first_server in getenv("SERVER_NAME", "").strip().split(" "):
            if (
                getenv(f"{first_server}_USE_CROWDSEC", getenv("USE_CROWDSEC", "no"))
                == "yes"
            ):
                cs_activated = True
                break
    # Singlesite case
    elif getenv("USE_CROWDSEC", "no") == "yes":
        cs_activated = True

    if not cs_activated:
        logger.info("CrowdSec is not activated, skipping job...")
        sys_exit(status)

    # Create directory
    cs_path = Path(sep, "var", "cache", "bunkerweb", "crowdsec")
    cs_path.mkdir(parents=True, exist_ok=True)

    db = Database(
        logger,
        sqlalchemy_string=getenv("DATABASE_URI", None),
    )

    # Copy template
    content = (
        Path(sep, "etc", "bunkerweb", "plugins", "crowdsec", "misc", "crowdsec.conf")
        .read_bytes()
        .replace(b"%CROWDSEC_API%", getenv("CROWDSEC_API", "").encode())
        .replace(b"%CROWDSEC_API_KEY%", getenv("CROWDSEC_API_KEY", "").encode())
        .replace(b"%CROWDSEC_MODE%", getenv("CROWDSEC_MODE", "live").encode())
        .replace(
            b"%CROWDSEC_REQUEST_TIMEOUT%",
            getenv("CROWDSEC_REQUEST_TIMEOUT", "500").encode(),
        )
        .replace(b"%CROWDSEC_UPDATE_FREQUENCY%", getenv("CROWDSEC_UPDATE_FREQUENCY", "10").encode())
        .replace(b"%UPDATE_FREQUENCY%", getenv("UPDATE_FREQUENCY", "10").encode())
        .replace(
            b"%CROWDSEC_STREAM_REQUEST_TIMEOUT%",
            getenv("CROWDSEC_STREAM_REQUEST_TIMEOUT", "15000").encode(),
        )
    )

    # Write configuration in cache
    cs_path.joinpath("crowdsec.conf").write_bytes(content)

    # Update db
    cached, err = set_file_in_db(
        "crowdsec.conf",
        content,
        db,
    )
    if not cached:
        logger.error(f"Error while caching crowdsec.conf file : {err}")

    # Done
    logger.info("CrowdSec configuration successfully generated")

except SystemExit as e:
    raise e
except:
    status = 2
    logger.error(f"Exception while running crowdsec-init.py :\n{format_exc()}")

sys_exit(status)
