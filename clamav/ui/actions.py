from io import BytesIO
from base64 import b64decode
from requests import post
from requests.exceptions import ConnectionError as RequestsConnectionError


def clamav() -> dict:
    # Test file from https://www.eicar.com/download-anti-malware-testfile/ encoded in base64
    coded_content = b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
    eicar_file = BytesIO(b64decode(coded_content))
    # Try to upload the file to the server
    try:
        resp = post(
            "http://clamav-api:8000/check",
            files={"file": eicar_file},
        )
    except RequestsConnectionError:
        # If the connection fails, return an error
        return {"result": "ko", "error": "Connection failed"}

    data = resp.json()

    response = {"result": "ok" if data.get("detected", False) else "ko"}

    if data.get("error", "success") != "success":
        response["error"] = data["error"]

    return response
