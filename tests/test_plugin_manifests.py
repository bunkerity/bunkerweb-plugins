"""Guards on ``plugin.json`` and the documentation generated from it.

None of these caught a live defect the day they were written. They exist because the
things they check are edited by hand, drift silently, and are only noticed by a user: a
setting whose default its own regex rejects is refused by the UI the first time someone
opens the page, and a README settings table is the only place an operator reads what a
setting does.
"""

from json import loads
from pathlib import Path
from re import compile as re_compile, error as re_error

import pytest

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = sorted(ROOT.glob("*/plugin.json"))
CONTEXTS = {"global", "multisite"}


def _settings(manifest):
    return loads(manifest.read_text()).get("settings", {})


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.parent.name)
def test_every_default_satisfies_its_own_regex(manifest):
    broken = []
    for name, data in _settings(manifest).items():
        pattern, default = data.get("regex"), data.get("default")
        if pattern is None or default is None:
            continue
        try:
            if not re_compile(pattern).match(str(default)):
                broken.append(f"{name}={default!r} rejected by {pattern!r}")
        except re_error as exc:
            broken.append(f"{name} has an uncompilable regex: {exc}")
    assert not broken, f"{manifest.parent.name}: {broken}"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.parent.name)
def test_every_setting_is_completely_declared(manifest):
    """BunkerWeb reads these to register the setting and render its UI row."""
    incomplete = []
    for name, data in _settings(manifest).items():
        missing = [key for key in ("context", "default", "help", "id", "label", "type") if key not in data]
        if missing:
            incomplete.append(f"{name} is missing {missing}")
        if data.get("context") not in CONTEXTS:
            incomplete.append(f"{name} has context {data.get('context')!r}")
        # The id is rendered straight into an HTML id attribute by the web UI
        # (`models/input_setting.html`, `models/select_setting.html`). Whitespace there
        # makes the attribute invalid, so the label's `for` never resolves and the field
        # stops responding to a click on its own label. It need not equal the kebab-case
        # of the key: core itself maps API_HTTP_PORT to api-http-listen.
        if "id" in data and (not data["id"] or data["id"] != data["id"].strip() or any(c.isspace() for c in data["id"])):
            incomplete.append(f"{name} has a non-slug id {data['id']!r}")
    assert not incomplete, f"{manifest.parent.name}: {incomplete}"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.parent.name)
def test_the_readme_settings_table_matches_the_manifest(manifest):
    """``.tests/misc/json2md.py`` is run by hand, so the table it produces goes stale."""
    readme = manifest.parent / "README.md"
    if not readme.is_file():
        pytest.skip("no README")
    text = readme.read_text()
    for name, data in _settings(manifest).items():
        row = next((line for line in text.splitlines() if line.startswith(f"| `{name}`")), None)
        assert row, f"{manifest.parent.name}: {name} is not in the README settings table"
        default = data["default"]
        expected_default = "" if default == "" else f"`{default}`"
        assert expected_default in row or default == "", f"{manifest.parent.name}: {name} default drifted from {default!r}: {row}"
        assert data["context"] in row, f"{manifest.parent.name}: {name} context drifted from {data['context']!r}: {row}"
