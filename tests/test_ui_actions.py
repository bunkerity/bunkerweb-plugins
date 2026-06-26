"""Unit tests for every plugin's ``ui/actions.py``.

The ``actions.py`` files are byte-identical apart from the plugin name, so one
parametrized suite covers them all. Each module is loaded under a unique
synthetic name to avoid the ``sys.modules`` collision that would otherwise make
us test a single plugin many times. (authentik is excluded: it ships no
``ui/actions.py``.)
"""

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGINS = ["clamav", "cloudflare", "coraza", "discord", "matrix", "slack", "virustotal", "webhook"]


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
    assert "boom" not in ret["error"]
    assert "internal" not in ret["error"]
    assert ret["ping_status"]["value"] == "error"


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_stub_is_noop(plugin):
    module = load_actions(plugin)
    fn = getattr(module, plugin)
    assert callable(fn)
    assert fn() is None
