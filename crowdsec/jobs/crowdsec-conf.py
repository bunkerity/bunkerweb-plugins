#!/usr/bin/python3

import sys, os, traceback, shutil

sys.path.append("/opt/bunkerweb/deps/python")
sys.path.append("/opt/bunkerweb/utils")

import logger

status = 0

try :

    # Check if at least a server has CrowdSec activated
    crowdsec_activated = False
    # Multisite case
    if os.getenv("MULTISITE") == "yes" :
        for first_server in os.getenv("SERVER_NAME").split(" ") :
            if os.getenv(first_server + "_USE_CROWDSEC", os.getenv("USE_CROWDSEC")) == "yes" :
                crowdsec_activated = True
                break
    # Singlesite case
    elif os.getenv("USE_CROWDSEC") == "yes" :
        crowdsec_activated = True
    if not crowdsec_activated :
        logger.log("CROWDSEC", "ℹ️", "CrowdSec is not activated, skipping job...")
        os._exit(0)

    # Create directory
    os.makedirs("/opt/bunkerweb/cache/crowdsec", exist_ok=True)

    # Copy template
    with open("/opt/bunkerweb/plugins/crowdsec/misc/crowdsec.conf", "r") as src :
        content = src.read().replace("%CROWDSEC_API%", os.getenv("CROWDSEC_API", "")).replace("%CROWDSEC_API_KEY%", os.getenv("CROWDSEC_API_KEY", ""))
    with open("/opt/bunkerweb/cache/crowdsec/crowdsec.conf", "w") as dst :
        dst.write(content)

    # Done
    logger.log("CROWDSEC", "ℹ️", "CrowdSec configuration successfully generated")

except :
    status = 2
    logger.log("CROWDSEC", "❌", "Exception while running crowdsec-init.py :")
    print(traceback.format_exc())

sys.exit(status)
