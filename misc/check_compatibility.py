#!/usr/bin/env python3
"""Assert COMPATIBILITY.json declares the BunkerWeb version the tests actually run against.

`COMPATIBILITY.json` is the table users read to decide whether this plugin collection
supports their BunkerWeb. Nothing in CI consults it, so it drifts in silence: it still
stopped at 1.6.11 while the integration suite had been green against 1.6.14 for weeks.

Usage:  check_compatibility.py <bunkerweb-version> [path/to/COMPATIBILITY.json]
Exits 1 with a GitHub-annotated error when the version is not declared.
"""

from json import loads
from pathlib import Path
from sys import argv, exit as sys_exit


def latest_collection(data):
    """The highest collection version key, compared numerically rather than as text."""
    return max(data, key=lambda key: [int(part) for part in key.split(".")])


def check(data, version):
    """Return an error message, or None when the version is declared."""
    latest = latest_collection(data)
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
    problem = check(data, version)
    if problem:
        print(f"::error::{problem}")
        return 1
    print(f"COMPATIBILITY.json collection {latest_collection(data)} declares BunkerWeb {version}")
    return 0


if __name__ == "__main__":
    sys_exit(main())
