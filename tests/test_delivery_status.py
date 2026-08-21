"""Unit tests for delivery_status(), the guard against a cached-but-never-shipped file.

The scheduler ships /var/cache/bunkerweb to the BunkerWeb instances only when a job in the
same batch exits 1 (JobScheduler.run_pending). Without this guard, a run that caches a file
and then fails on a later item exits >=2, the file stays scheduler-side, and the next run
finds the hash unchanged, exits 0, and never delivers it.

Both plugins carry their own copy of the helper — each plugin directory is mounted into
/data/plugins on its own — so both copies are tested, and asserted to behave identically.
"""

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

MODULES = {
    "cloudflare": REPO_ROOT / "cloudflare" / "jobs" / "cloudflare_helpers.py",
    "syswarden": REPO_ROOT / "syswarden" / "jobs" / "syswarden_helpers.py",
}


@pytest.fixture(params=sorted(MODULES), scope="module")
def delivery_status(request):
    path = MODULES[request.param]
    spec = importlib.util.spec_from_file_location(f"{request.param}_helpers_delivery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.delivery_status


def test_clean_run_with_nothing_cached_is_untouched(delivery_status):
    assert delivery_status(0, False, False) == (0, False)


def test_cached_this_run_asks_for_the_ship(delivery_status):
    assert delivery_status(0, True, False) == (1, False)


def test_job_that_already_asked_for_a_reload_stays_at_one(delivery_status):
    assert delivery_status(1, True, False) == (1, False)


def test_failure_after_a_cache_write_keeps_the_marker(delivery_status):
    # The regression: ipv4 cached, then the ipv6 fetch failed.
    assert delivery_status(2, True, False) == (2, True)


def test_failure_with_nothing_cached_leaves_no_marker(delivery_status):
    assert delivery_status(2, False, False) == (2, False)


def test_next_clean_run_delivers_the_stranded_file(delivery_status):
    # Nothing changed this run, so nothing is re-cached — the marker is what forces the ship.
    assert delivery_status(0, False, True) == (1, False)


def test_repeated_failure_keeps_the_marker_alive(delivery_status):
    assert delivery_status(2, False, True) == (2, True)


def test_marker_survives_an_early_exit_that_failed(delivery_status):
    # sys_exit(2) from a config guard must not drop a pending delivery.
    assert delivery_status(2, False, True) == (2, True)


def test_both_plugin_copies_agree():
    loaded = []
    for name, path in sorted(MODULES.items()):
        spec = importlib.util.spec_from_file_location(f"{name}_helpers_agree", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        loaded.append(module.delivery_status)
    cases = [(s, c, p) for s in (0, 1, 2, 3) for c in (False, True) for p in (False, True)]
    assert [loaded[0](*case) for case in cases] == [loaded[1](*case) for case in cases]
