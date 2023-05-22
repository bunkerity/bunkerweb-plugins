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
from os import getenv, remove
from redis import Redis
from starlette.datastructures import UploadFile
from traceback import format_exc
from uuid import uuid4

from clamd import ClamdNetworkSocket

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

clamav_host = getenv("CLAMAV_HOST")

if clamav_host is None:
    logger.error("CLAMAV_HOST environment variable is not set")
    exit(1)

clamav_port = getenv("CLAMAV_PORT", "3310")

if not clamav_port.isdigit():
    logger.error(
        "CLAMAV_PORT environment variable doesn't have a valid value, must be an integer"
    )
    exit(1)

clamav_port = int(clamav_port)

clamav_timeout = getenv("CLAMAV_TIMEOUT", "1.0")

try:
    clamav_timeout = float(clamav_timeout)
except:
    logger.error(
        "CLAMAV_TIMEOUT environment variable doesn't have a valid value, must be a float"
    )
    exit(1)

app.client = ClamdNetworkSocket(
    host=clamav_host, port=clamav_port, timeout=clamav_timeout
)
app.redis = None
redis_host = getenv("REDIS_HOST")

if redis_host is not None:
    redis_port = getenv("REDIS_PORT", "6379")

    if not redis_port.isdigit():
        logger.error(
            "REDIS_PORT environment variable doesn't have a valid value, must be an integer"
        )
        exit(1)

    redis_port = int(redis_port)

    redis_db = getenv("REDIS_DB", "0")

    if not redis_db.isdigit():
        logger.error(
            "REDIS_DB environment variable doesn't have a valid value, must be an integer"
        )
        exit(1)

    redis_db = int(redis_db)

    app.redis = Redis(
        host=redis_host, port=redis_port, db=redis_db, decode_responses=True
    )


@app.on_event("startup")
async def startup_event():
    logger.info("BunkerWeb ClamAV API started")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("BunkerWeb ClamAV API stopped")


@app.get("/ping")
async def ping(request: Request):
     return {"success": True, "error": "pong"}

@app.post("/check")
async def check_files(request: Request):
    detected = False
    dhash = ""
    success = True
    error = "success"
    tmp_files = []
    try:
        form = await request.form()
        for name, data in form.items():
            if isinstance(data, UploadFile):
                tmp_file = f"/tmp/{uuid4()}.clamav"
                tmp_files.append(tmp_file)
                _hash = sha256()

                with open(tmp_file, "wb") as f:
                    while True:
                        chunk = await data.read(4096)
                        if not chunk:
                            break
                        _hash.update(chunk)
                        f.write(chunk)

                digest = _hash.hexdigest()
                logger.info(f"Checking file {name} with SHA256 {digest}")

                if app.redis is not None:
                    cache, _ = is_in_cache(app.redis, digest)

                    if cache is not None:
                        remove(tmp_file)
                        tmp_files.remove(tmp_file)

                        if cache == "detected":
                            logger.warning(
                                f"{name.title()} with SHA256 {digest} was detected (cached)"
                            )
                            return {
                                "success": True,
                                "error": "success",
                                "detected": True,
                                "hash": digest,
                            }

                        logger.info(
                            f"{name.title()} with SHA256 {digest} was {cache} (cached)"
                        )
                        continue

                try:
                    with open(tmp_file, "rb") as f:
                        result = app.client.instream(f)
                        detected = result["stream"][0] == "FOUND"

                    if detected:
                        if app.redis is not None:
                            put_in_cache(app.redis, digest, "detected")

                        logger.warning(
                            f"{name.title()} with SHA256 {digest} was detected"
                        )
                        remove(tmp_file)
                        tmp_files.remove(tmp_file)
                        return {
                            "success": True,
                            "error": "success",
                            "detected": True,
                            "hash": digest,
                        }

                    logger.info(f"{name.title()} with SHA256 {digest} was not detected")
                    if app.redis is not None:
                        put_in_cache(app.redis, digest, "clean")
                except:
                    logger.error(f"Exception while scanning file :\n{format_exc()}")
                    success = False
                    error = "at least one file was not scanned"

                remove(tmp_file)
                tmp_files.remove(tmp_file)
    except:
        print(format_exc(), flush=True)
        remove_tmp(tmp_files)
        return {
            "success": False,
            "error": "internal server error, see bunkerweb-clamav logs for more information",
        }
    remove_tmp(tmp_files)
    return {"success": success, "error": error, "detected": detected, "hash": dhash}


def is_in_cache(redis: Redis, digest: str) -> Tuple[Optional[bytes], str]:
    try:
        return redis.get(digest), False
    except:
        print(format_exc(), flush=True)
        return None, True


def put_in_cache(redis: Redis, digest: str, result: str) -> Tuple[bool, str]:
    try:
        return redis.set(digest, result, ex=86400), False
    except:
        print(format_exc(), flush=True)
        return False, True


def remove_tmp(tmp_files) -> None:
    for tmp_file in tmp_files:
        try:
            remove(tmp_file)
        except:
            print(format_exc(), flush=True)
