"""Release metadata must describe the version actually being shipped."""

import json
from pathlib import Path
import subprocess
import sys


def test_compatibility_checks_the_manifest_version(tmp_path):
    script = Path(__file__).resolve().parents[1] / "misc/check_compatibility.py"
    table = tmp_path / "COMPATIBILITY.json"
    table.write_text(json.dumps({"1.8": ["1.6.14"]}))
    plugin = tmp_path / "clamav"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(json.dumps({"version": "1.12"}))

    def run():
        return subprocess.run([sys.executable, str(script), "1.6.14", str(table)], capture_output=True, text=True)

    assert run().returncode == 1  # An older entry cannot validate a new release.
    table.write_text(json.dumps({"1.12": ["1.6.14"]}))
    assert run().returncode == 0
    table.write_text(json.dumps({"1.12": ["1.6.13"]}))
    assert run().returncode == 1
    table.write_text(json.dumps({"1.12": ["1.6.14"]}))
    sibling = tmp_path / "coraza"
    sibling.mkdir()
    (sibling / "plugin.json").write_text(json.dumps({"version": "1.11"}))
    assert run().returncode == 1
