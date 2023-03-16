#!/usr/bin/python3

from os import getenv
from pathlib import Path
from sys import exit as sys_exit, path as sys_path
from threading import Lock
from traceback import format_exc

if "/usr/share/bunkerweb/deps/python" not in sys_path:
    sys_path.append("/usr/share/bunkerweb/deps/python")
if "/usr/share/bunkerweb/utils" not in sys_path:
    sys_path.append("/usr/share/bunkerweb/utils")
if "/usr/share/bunkerweb/db" not in sys_path:
    sys_path.append("/usr/share/bunkerweb/db")

from Database import Database
from logger import setup_logger

logger = setup_logger("CROWDSEC", getenv("LOG_LEVEL", "INFO"))
status = 0

try:
    # Check if at least a server has CrowdSec activated
    crowdsec_activated = False
    # Multisite case
    if getenv("MULTISITE") == "yes":
        for first_server in getenv("SERVER_NAME").split(" "):
            if (
                getenv(f"{first_server}_USE_CROWDSEC", getenv("USE_CROWDSEC", "no"))
                == "yes"
            ):
                crowdsec_activated = True
                break
    # Singlesite case
    elif getenv("USE_CROWDSEC", "no") == "yes":
        crowdsec_activated = True
    if not crowdsec_activated:
        logger.info("CrowdSec is not activated, skipping job...")
        sys_exit(status)

    # Create directory
    Path("/var/cache/bunkerweb/crowdsec").mkdir(parents=True, exist_ok=True)

    db = Database(
        logger,
        sqlalchemy_string=getenv("DATABASE_URI", None),
    )
    lock = Lock()

    # Copy template
    content = (
        Path("/etc/bunkerweb/plugins/crowdsec/misc/crowdsec.conf")
        .read_bytes()
        .replace(b"%CROWDSEC_API%", getenv("CROWDSEC_API", "").encode())
        .replace(b"%CROWDSEC_API_KEY%", getenv("CROWDSEC_API_KEY", "").encode())
    )

    # Write configuration in cache
    Path("/var/cache/bunkerweb/crowdsec/crowdsec.conf").write_bytes(content)

    with lock:
        err = db.update_job_cache(
            "crowdsec-conf",
            None,
            "crowdsec.conf",
            content,
        )

    if err:
        logger.warning(f"Couldn't update db cache for crowdsec.conf: {err}")

    # Done
    logger.info("CrowdSec configuration successfully generated")

except SystemExit as e:
    raise e
except:
    status = 2
    logger.error(f"Exception while running crowdsec-init.py :\n{format_exc()}")

sys_exit(status)
