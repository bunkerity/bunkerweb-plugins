"""A Lua plugin must not gate a global setting through utils.has_variable().

``has_variable`` walks the per-service tables as soon as ``MULTISITE`` is on, and
``helpers.load_variables`` fills those from ``<server>_``-prefixed entries alone. A setting
declared ``context: global`` never lands in one, so the helper answers "no" on every
multisite instance and the plugin turns itself off: no lists loaded, no deny, and a ping
that fails. ``self.variables[...]`` is the correct read, since ``plugin:initialize`` already
resolves a global setting against the global table.

This shipped once, in syswarden, and it is invisible to a single-site end-to-end run.
"""

from json import loads
from pathlib import Path
from re import findall

import pytest

ROOT = Path(__file__).resolve().parent.parent
GATE = r"has_(?:not_)?variable\(\s*\"([A-Z0-9_]+)\""


def _plugins():
    for manifest in sorted(ROOT.glob("*/plugin.json")):
        plugin = loads(manifest.read_text())
        lua = manifest.parent / f"{plugin['id']}.lua"
        if lua.is_file():
            yield pytest.param(plugin, lua, id=plugin["id"])


@pytest.mark.parametrize("plugin, lua", list(_plugins()))
def test_no_global_setting_is_gated_through_has_variable(plugin, lua):
    contexts = {name: data.get("context") for name, data in plugin.get("settings", {}).items()}
    gated = {name for name in findall(GATE, lua.read_text()) if contexts.get(name) == "global"}
    assert not gated, (
        f"{lua.name} gates {sorted(gated)} through has_variable(), but they are declared " f"context: global. Read them off self.variables instead."
    )
