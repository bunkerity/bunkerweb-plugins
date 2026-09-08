"""A job that caches a file the instances read must carry a pending-delivery marker.

``JobScheduler.run_pending()`` POSTs ``/var/cache/bunkerweb`` to the instances only when
some job in that batch exits ``1``. A job that writes a cache file and then exits ``0`` or
``>=2`` leaves it scheduler-side; on the next run its hash is unchanged, so nothing is
re-cached, the job exits ``0`` again, and the file is never delivered.

``delivery_status()`` plus a marker in the job cache closes that hole. This test is a
lint, not a behaviour check: it only asserts that a job which caches something either
resolves the delivery or is listed below with the reason it does not have to.
"""

from pathlib import Path
from re import search

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Jobs whose cache is never read by an instance, so nothing has to be shipped.
EXEMPT = {
    # The ownership registry the push job keeps for itself, scheduler-side only.
    "syswarden-ban-push.py": "pushed.json is read by the next run of this same job",
    # ui/actions.py reads this straight from the database, which is always current.
    "syswarden-telemetry-poll.py": "telemetry.json is read from the database by the web UI",
}


def _jobs():
    for job in sorted(ROOT.glob("*/jobs/*.py")):
        if job.name.endswith("_helpers.py") or job.name.endswith("_client.py"):
            continue
        yield pytest.param(job, id=job.name)


@pytest.mark.parametrize("job", list(_jobs()))
def test_a_job_that_caches_resolves_its_delivery(job):
    source = job.read_text()
    # A cache_file() call that is not the marker write itself.
    caches = search(r"cache_file\(\s*(?!PENDING_MARKER)", source) is not None
    if not caches:
        return
    if job.name in EXEMPT:
        assert "delivery_status" not in source, f"{job.name} is listed as exempt ({EXEMPT[job.name]}) but resolves a delivery anyway; update EXEMPT"
        return
    assert "delivery_status" in source, (
        f"{job.name} writes a cache file but never calls delivery_status(). The scheduler ships "
        f"/var/cache/bunkerweb only on exit code 1, so that file can sit undelivered forever. "
        f"Wire the marker as cf-trusted-ips-download.py does, or add the job to EXEMPT with a reason."
    )
