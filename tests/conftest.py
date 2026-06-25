"""Shared fixtures for the plugin UI unit tests."""

import pytest


class FakePingUtils:
    """Stand-in for ``kwargs['bw_instances_utils']`` used by ``ui/actions.py``.

    ``get_ping`` either returns a canned ``{"status": ...}`` payload or raises,
    so both the happy path and the broad ``except BaseException`` path of
    ``pre_render`` can be exercised without a running BunkerWeb instance.
    """

    def __init__(self, status=None, exc=None):
        self._status = status
        self._exc = exc
        self.called_with = None

    def get_ping(self, plugin):
        self.called_with = plugin
        if self._exc is not None:
            raise self._exc
        return {"status": self._status}


@pytest.fixture
def fake_ping_utils():
    return FakePingUtils
