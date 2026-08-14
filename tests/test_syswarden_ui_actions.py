"""Tests for the SysWarden telemetry cards in ``syswarden/ui/actions.py``.

The generic suite in ``test_ui_actions.py`` covers the ping card for every plugin; this
one covers what is specific to SysWarden, the counters read from the cached telemetry.
"""

import importlib.util
from json import dumps
from pathlib import Path

import pytest

ACTIONS_PATH = Path(__file__).resolve().parent.parent / "syswarden" / "ui" / "actions.py"

TELEMETRY = {
    "peers": [
        {
            "peer": "https://10.0.0.1:62026",
            "reachable": True,
            "global_blocked": 12,
            "geoip_blocked": 3,
            "asn_blocked": 1,
            "waf_total_banned": 7,
            "whitelist_active_ips": 2,
        },
        {"peer": "https://10.0.0.2:62026", "reachable": False},
    ]
}


class FakeDB:
    """Stand-in for ``kwargs['db']``: serves (or refuses) one job cache file."""

    def __init__(self, payload=None, exc=None):
        self._payload = payload
        self._exc = exc

    def get_job_cache_file(self, job_name, file_name, **kwargs):
        if self._exc is not None:
            raise self._exc
        assert (job_name, file_name) == ("syswarden-telemetry-poll", "telemetry.json")
        return dumps(self._payload).encode() if self._payload is not None else None


@pytest.fixture
def actions():
    spec = importlib.util.spec_from_file_location("actions_syswarden_ui", ACTIONS_PATH)
    assert spec and spec.loader, f"cannot load {ACTIONS_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakePing:
    def get_ping(self, plugin):
        return {"status": "up"}


def test_counters_are_summed_over_peers(actions):
    ret = actions.pre_render(bw_instances_utils=FakePing(), db=FakeDB(TELEMETRY))
    assert ret["peers_reachable"]["value"] == "1/2"
    assert ret["kernel_blocked"]["value"] == 12
    assert ret["waf_banned"]["value"] == 7
    assert "error" not in ret


def test_no_telemetry_yet_degrades_to_zero(actions):
    # The poll job has not run: the cards show zeros rather than an error, because
    # nothing is wrong yet.
    ret = actions.pre_render(bw_instances_utils=FakePing(), db=FakeDB(None))
    assert ret["peers_reachable"]["value"] == "0/0"
    assert ret["kernel_blocked"]["value"] == 0
    assert "error" not in ret


def test_broken_database_never_leaks_the_exception(actions):
    ret = actions.pre_render(bw_instances_utils=FakePing(), db=FakeDB(exc=RuntimeError("boom postgres://user:pass@db")))
    assert ret["error"] == "Could not retrieve the SysWarden telemetry"
    assert "postgres" not in ret["error"]
    # The ping card still answers: one broken source must not blank the whole page.
    assert ret["ping_status"]["value"] == "up"
