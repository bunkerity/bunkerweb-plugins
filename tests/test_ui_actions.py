"""Unit tests for every plugin's ``ui/actions.py``.

The ``actions.py`` files are byte-identical apart from the plugin name, so one
parametrized suite covers them all. Each module is loaded under a unique
synthetic name to avoid the ``sys.modules`` collision that would otherwise make
us test a single plugin many times. (authentik is excluded: it ships no
``ui/actions.py``.)
"""

import importlib.util
from json import dumps
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGINS = ["clamav", "cloudflare", "coraza", "discord", "matrix", "sentinelone", "slack", "syswarden", "virustotal", "webhook"]


def load_actions(plugin):
    path = REPO_ROOT / plugin / "ui" / "actions.py"
    spec = importlib.util.spec_from_file_location(f"actions_{plugin}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("plugin", PLUGINS)
def test_pre_render_happy_path(plugin, fake_ping_utils):
    module = load_actions(plugin)
    fake = fake_ping_utils(status="up")
    ret = module.pre_render(bw_instances_utils=fake)
    assert fake.called_with == plugin
    assert ret["ping_status"]["value"] == "up"
    assert "error" not in ret


@pytest.mark.parametrize("plugin", PLUGINS)
def test_pre_render_error_path(plugin, fake_ping_utils):
    module = load_actions(plugin)
    # The exception message stands in for something sensitive (e.g. an internal
    # URL) that must never reach the rendered card.
    fake = fake_ping_utils(exc=RuntimeError("boom https://internal.scheduler:8080"))
    ret = module.pre_render(bw_instances_utils=fake)
    # A generic marker is shown; the raw exception text is not leaked to the UI.
    assert ret["error"] == "Could not retrieve the plugin status"
    # Scan the whole payload, not just the field pinned above: a leak would surface in
    # some other card's value, where nothing is asserting on it.
    rendered = dumps(ret, default=str)
    assert "boom" not in rendered
    assert "internal.scheduler" not in rendered
    assert ret["ping_status"]["value"] == "error"


# plugin_page.html draws a card only when its key carries one of these prefixes, and drops
# every other key without a word. syswarden shipped six counters under bare names once and
# none of them ever reached the page.
CARD_PREFIXES = ("ping_", "info_", "date_", "count_", "counter_", "top_", "list_")


@pytest.mark.parametrize("plugin", PLUGINS)
def test_every_card_key_is_one_the_ui_renders(plugin, fake_ping_utils):
    module = load_actions(plugin)
    ret = module.pre_render(bw_instances_utils=fake_ping_utils(status="up"))
    unrendered = sorted(key for key in ret if key != "error" and not key.startswith(CARD_PREFIXES))
    assert not unrendered, f"{plugin}/ui/actions.py returns {unrendered}, which plugin_page.html drops"
    # A counter card is rendered through human_readable_number(), which calls int() on the
    # value: a string there is a 500 on the plugin page, not a badly formatted number.
    for key, card in ret.items():
        if key.startswith(("count_", "counter_")):
            int(card["value"])


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_stub_is_noop(plugin):
    module = load_actions(plugin)
    fn = getattr(module, plugin)
    assert callable(fn)
    assert fn() is None
