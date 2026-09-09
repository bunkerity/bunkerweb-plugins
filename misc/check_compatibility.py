#!/usr/bin/env python3
"""Assert COMPATIBILITY.json declares the BunkerWeb version the tests actually run against.

`COMPATIBILITY.json` is the table users read to decide whether this plugin collection
supports their BunkerWeb. CI checks the entry matching the shared manifest version
so an older collection entry cannot silently validate a new release.

Usage:  check_compatibility.py <bunkerweb-version> [path/to/COMPATIBILITY.json]
Exits 1 with a GitHub-annotated error when the version is not declared.
"""

from json import loads
from pathlib import Path
from sys import argv, exit as sys_exit


def latest_collection(data):
    """The highest collection version key, compared numerically rather than as text."""
    return max(data, key=lambda key: [int(part) for part in key.split(".")])


def check(data, version, collection=None):
    """Return an error message, or None when the version is declared."""
    latest = collection or latest_collection(data)
    if latest not in data:
        return f"COMPATIBILITY.json has no entry for collection {latest}."
    if version in data[latest]:
        return None
    return (
        f"COMPATIBILITY.json collection {latest} does not list BunkerWeb {version}. "
        f"Add it once the integration suite is green against that release, or open a new collection key."
    )


def main():
    if not 2 <= len(argv) <= 3:
        print(__doc__)
        return 2
    version = argv[1]
    path = Path(argv[2]) if len(argv) == 3 else Path(__file__).resolve().parent.parent / "COMPATIBILITY.json"
    data = loads(path.read_text())
    manifests = sorted(path.parent.glob("*/plugin.json"))
    versions = {loads(manifest.read_text())["version"] for manifest in manifests}
    if len(versions) != 1:
        print(f"::error::Expected one shared plugin version, got {sorted(versions)}")
        return 1
    collection = versions.pop()
    problem = check(data, version, collection)
    if problem:
        print(f"::error::{problem}")
        return 1
    print(f"COMPATIBILITY.json collection {collection} declares BunkerWeb {version}")
    return 0


if __name__ == "__main__":
    sys_exit(main())
