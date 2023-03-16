from socket import inet_aton
from typing import Optional, Tuple
from fastapi import FastAPI, Request
from hashlib import sha256
from logging import (
    CRITICAL,
    DEBUG,
    ERROR,
    INFO,
    WARNING,
    _nameToLevel,
    addLevelName,
    basicConfig,
    getLogger,
)
from os import getenv
from starlette.datastructures import UploadFile
from redis import Redis
from traceback import format_exc
from vt import Client
from vt.error import APIError

default_level = _nameToLevel.get(getenv("LOG_LEVEL", "INFO").upper(), INFO)
basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%Y-%m-%d %H:%M:%S]",
    level=default_level,
)

# Edit the default levels of the logging module
addLevelName(CRITICAL, "🚨")
addLevelName(DEBUG, "🐛")
addLevelName(ERROR, "❌")
addLevelName(INFO, "ℹ️ ")
addLevelName(WARNING, "⚠️ ")

logger = getLogger("uvicorn.access")

app = FastAPI()

api_key = getenv("API_KEY")
file_malicious = getenv("MALICIOUS_COUNT", "3")
file_suspicious = getenv("SUSPICIOUS_COUNT", "5")
ip_malicious = getenv("IP_MALICIOUS_COUNT", "3")
ip_suspicious = getenv("IP_SUSPICIOUS_COUNT", "5")

if api_key is None:
    logger.error("API_KEY environment variable is not set")
    exit(1)
elif not file_malicious.isdigit():
    logger.error(
        "MALICIOUS_COUNT environment variable doesn't have a valid value, must be an integer"
    )
    exit(1)
elif not file_suspicious.isdigit():
    logger.error(
        "SUSPICIOUS_COUNT environment variable doesn't have a valid value, must be an integer"
    )
    exit(1)
elif not ip_malicious.isdigit():
    logger.error(
        "IP_MALICIOUS_COUNT environment variable doesn't have a valid value, must be an integer"
    )
    exit(1)
elif not ip_suspicious.isdigit():
    logger.error(
        "IP_SUSPICIOUS_COUNT environment variable doesn't have a valid value, must be an integer"
    )
    exit(1)

app.client = Client(api_key)
app.file_malicious = int(file_malicious)
app.file_suspicious = int(file_suspicious)
app.ip_malicious = int(ip_malicious)
app.ip_suspicious = int(ip_suspicious)
app.redis = None

redis_host = getenv("REDIS_HOST")
if redis_host:
    redis_port = getenv("REDIS_PORT", "6379")
    redis_db = getenv("REDIS_DB", "0")

    if not redis_port.isdigit():
        logger.error(
            "REDIS_PORT environment variable doesn't have a valid value, must be an integer"
        )
        exit(1)
    elif not redis_db.isdigit():
        logger.error(
            "REDIS_DB environment variable doesn't have a valid value, must be an integer"
        )
        exit(1)

    app.redis = Redis(
        host=redis_host, port=int(redis_port), db=int(redis_db), decode_responses=True
    )


@app.on_event("startup")
async def startup_event():
    logger.info("BunkerWeb VirusTotal API started")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("BunkerWeb VirusTotal API stopped")


@app.post("/check_ip")
async def check_ip(body: dict):
    detected = False
    digest = ""
    success = True
    error = "success"
    try:
        ip = body.get("ip")

        if ip is None:
            raise Exception("IP is not set")

        if is_ip(ip):
            logger.info(f"Checking ip {ip}")

            if app.redis is not None:
                cache, _ = is_in_cache(app.redis, ip, "ip")
                if cache is not None:
                    if cache == "detected":
                        logger.warning(f"Ip {ip} is detected (cached)")
                        return {
                            "success": True,
                            "error": "success",
                            "detected": True,
                            "hash": ip,
                        }
                    else:
                        logger.info(f"Ip {ip} is {cache} (cached)")

                    return {
                        "success": success,
                        "error": error,
                        "detected": detected,
                        "hash": digest,
                    }

            try:
                vt_ip = await app.client.get_object_async(f"/ip_addresses/{ip}")
                analysis_stats = vt_ip.get("last_analysis_stats")

                if analysis_stats is not None:
                    if (
                        analysis_stats["malicious"] >= app.ip_malicious
                        or analysis_stats["suspicious"] >= app.ip_suspicious
                    ):
                        logger.warning(f"Ip {ip} is detected")
                        if app.redis is not None:
                            put_in_cache(app.redis, ip, "detected", "ip")
                        return {
                            "success": True,
                            "error": "success",
                            "detected": True,
                            "hash": ip,
                        }

                logger.info(f"Ip {ip} is not detected")
                if app.redis is not None:
                    put_in_cache(app.redis, ip, "clean", "ip")
            except APIError as ex:
                if ex.code == "NotFoundError":
                    logger.info(f"Ip {ip} not found")
                    if app.redis is not None:
                        put_in_cache(app.redis, ip, "not found", "ip")
                else:
                    success = False
                    error = f"{ex.code} - {ex.message}"
                    error(f"Error {ex.code} from VirusTotal API : {ex.message}")
    except:
        print(format_exc(), flush=True)
        return {
            "success": False,
            "error": "internal server error, see bunkerweb-virustotal logs for more information",
        }
    return {"success": success, "error": error, "detected": detected, "hash": digest}


@app.post("/check")
async def check_files(request: Request):
    detected = False
    digest = ""
    success = True
    error = "success"
    try:
        form = await request.form()

        for name, data in form.items():
            if isinstance(data, UploadFile):
                _hash = sha256()
                while True:
                    chunk = await data.read(4096)
                    if not chunk:
                        break
                    _hash.update(chunk)

                digest = _hash.hexdigest()
                logger.info(f"Checking file {name} with SHA256 {digest}")

                if app.redis is not None:
                    cache, _ = is_in_cache(app.redis, digest, "file")
                    if cache is not None:
                        if cache == "detected":
                            logger.warning(
                                f"File {name} with SHA256 {digest} is detected (cached)"
                            )
                            return {
                                "success": True,
                                "error": "success",
                                "detected": True,
                                "hash": digest,
                            }
                        else:
                            logger.info(
                                f"File {name} with SHA256 {digest} is {cache} (cached)"
                            )
                        continue

                try:
                    vt_file = await app.client.get_object_async(f"/files/{digest}")
                    analysis_stats = vt_file.get("last_analysis_stats")

                    if analysis_stats is not None:
                        if (
                            analysis_stats["malicious"] >= app.file_malicious
                            or analysis_stats["suspicious"] >= app.file_suspicious
                        ):
                            logger.warning(
                                f"File {name} with SHA256 {digest} is detected"
                            )
                            if app.redis is not None:
                                put_in_cache(app.redis, digest, "detected", "file")
                            return {
                                "success": True,
                                "error": "success",
                                "detected": True,
                                "hash": digest,
                            }

                    logger.info(f"File {name} with SHA256 {digest} is not detected")
                    if app.redis is not None:
                        put_in_cache(app.redis, digest, "clean", "file")
                except APIError as ex:
                    if ex.code == "NotFoundError":
                        logger.info(f"File {name} with SHA256 {digest} not found")
                        if app.redis is not None:
                            put_in_cache(app.redis, digest, "not found", "file")
                    else:
                        success = False
                        error = f"{ex.code} - {ex.message}"
                        error(f"Error {ex.code} from VirusTotal API : {ex.message}")
    except:
        print(format_exc(), flush=True)
        return {
            "success": False,
            "error": "internal server error, see bunkerweb-virustotal logs for more information",
        }
    return {"success": success, "error": error, "detected": detected, "hash": digest}


def is_in_cache(redis: Redis, key: str, _type: str) -> Tuple[Optional[str], bool]:
    try:
        return redis.get(f"{_type}:{key}"), False
    except:
        print(format_exc(), flush=True)
        return None, True


def put_in_cache(redis: Redis, key: str, result: str, _type: str) -> Tuple[bool, str]:
    try:
        return redis.set(f"{_type}:{key}", result, ex=86400), False
    except:
        print(format_exc(), flush=True)
        return False, True


def is_ip(ip: str) -> bool:
    try:
        inet_aton(ip)
        return True
    except:
        return False
