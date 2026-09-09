"""Unit tests for the SysWarden HTTP client.

Three things are covered here. `fetch_fence_status` / `fetch_sync` decide which wire format
the push job speaks to each peer, and getting that wrong means either pushing a payload an
older peer refuses, or falling back to shared-blocklist semantics against a peer that
actually tracks ownership. `mutate_legacy` carries the fence condition, and the codes it
hands back are the difference between "retry later" and "stop, the fence moved". `tls_settings` and `make_session` decide whether to talk to a
peer at all: the bearer token travels on that connection, so every refusal there has to
stop the job rather than downgrade it.
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from sys import path as sys_path

import pytest

JOBS_DIR = Path(__file__).resolve().parent.parent / "syswarden" / "jobs"


def _load_client():
    # syswarden_client imports syswarden_helpers by name, the way the scheduler runs it.
    if str(JOBS_DIR) not in sys_path:
        sys_path.insert(0, str(JOBS_DIR))
    spec = spec_from_file_location("syswarden_client", JOBS_DIR / "syswarden_client.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client = _load_client()


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no body")
        return self._payload


class FakeLogger:
    """Collects what the client logged, so a refusal's reasoning can be asserted."""

    def __init__(self):
        self.warnings = []
        self.errors = []

    def warning(self, message):
        self.warnings.append(str(message))

    def error(self, message):
        self.errors.append(str(message))

    def info(self, message):
        pass


class FakeSession:
    """Answers a scripted sequence of responses and records every query it was asked."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.queries = []
        self.requests = []

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        self.queries.append({"params": params, "headers": headers, "allow_redirects": allow_redirects})
        answer = self._responses.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def request(self, method, url, json=None, headers=None, timeout=None, allow_redirects=True):
        self.requests.append({"method": method, "payload": json, "headers": headers, "allow_redirects": allow_redirects})
        answer = self._responses.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


class TestFetchFenceStatus:
    def test_a_current_peer_reports_its_capabilities(self):
        body = {"hostname": "sw", "api_version": "2", "capabilities": ["peer_cidr", "sync_ttl", "sync_provenance"]}
        session = FakeSession(FakeResponse(200, body))
        assert client.fetch_fence_status(session, "https://peer:62026", "c" * 43) == (True, body)

    def test_the_challenge_travels_and_the_answer_is_never_cached(self):
        session = FakeSession(FakeResponse(200, {"capabilities": []}))
        client.fetch_fence_status(session, "https://peer:62026", "c" * 43)
        assert session.queries == [
            {
                "params": None,
                "headers": {"X-SysWarden-HA-Challenge": "c" * 43, "Cache-Control": "no-store"},
                "allow_redirects": False,
            }
        ]

    @pytest.mark.parametrize("answer", (OSError("connection refused"), FakeResponse(500), FakeResponse(403), FakeResponse(200)))
    def test_an_unreachable_peer_is_never_reported_as_readable(self, answer):
        # Every one of these blocks the cluster-wide preflight. FakeResponse(200) with no
        # body is the unreadable-answer case.
        reachable, _ = client.fetch_fence_status(FakeSession(answer), "https://peer:62026", "c" * 43)
        assert reachable is False

    def test_a_body_that_is_not_an_object_is_refused(self):
        reachable, _ = client.fetch_fence_status(FakeSession(FakeResponse(200, ["capabilities"])), "https://peer:62026", "c" * 43)
        assert reachable is False


class TestMutateLegacy:
    def test_the_condition_header_is_sent_only_when_there_is_one(self):
        session = FakeSession(FakeResponse(200, {"status": "ok"}), FakeResponse(200, {"status": "ok"}))
        client.mutate_legacy(session, "https://peer:62026", "DELETE", ["1.2.3.4"], condition="sw-fence-v1-" + "a" * 43)
        client.mutate_legacy(session, "https://peer:62026", "POST", ["1.2.3.4"])
        assert session.requests[0]["headers"] == {"X-SysWarden-HA-Fence-Condition": "sw-fence-v1-" + "a" * 43}
        # Upstream answers 412 to a condition presented while the fence is inactive, so an
        # unconditional header would break the very pass it means to protect.
        assert session.requests[1]["headers"] is None

    @pytest.mark.parametrize("code", (400, 412, 423, 428, 503))
    def test_the_fence_codes_are_handed_back_instead_of_being_flattened(self, code):
        sent, status_code, error = client.mutate_legacy(FakeSession(FakeResponse(code)), "https://peer:62026", "DELETE", ["1.2.3.4"])
        assert (sent, status_code) == (False, code)
        assert str(code) in error

    def test_a_request_that_never_completed_reports_no_code(self):
        sent, status_code, _ = client.mutate_legacy(FakeSession(OSError("reset")), "https://peer:62026", "DELETE", ["1.2.3.4"])
        assert (sent, status_code) == (False, 0)

    def test_a_success_is_a_plain_ok(self):
        assert client.mutate_legacy(FakeSession(FakeResponse(200, {"status": "ok"})), "https://peer:62026", "POST", ["1.2.3.4"]) == (True, 200, "")


class TestCall:
    def test_mutations_never_follow_redirects(self):
        session = FakeSession(FakeResponse(200, {"status": "ok"}))
        assert client.call(session, "https://peer:62026", "POST", "/ha/sync", payload={"bans": []}) == (True, {"status": "ok"})
        assert session.requests == [{"method": "POST", "payload": {"bans": []}, "headers": None, "allow_redirects": False}]


class TestFetchSync:
    def test_the_plain_read_sends_no_query(self):
        session = FakeSession(FakeResponse(200, {"ips": ["1.1.1.1"]}))
        ok, snapshot = client.fetch_sync(session, "https://peer:62026")
        assert ok
        assert snapshot == {"ips": ["1.1.1.1"], "bans": []}
        assert session.queries == [{"params": None, "headers": None, "allow_redirects": False}]

    def test_the_detailed_read_returns_both_halves(self):
        bans = [{"ip": "1.1.1.1", "source": "bunkerweb", "expires_at": "2026-08-17T12:00:00Z"}]
        session = FakeSession(FakeResponse(200, {"ips": ["1.1.1.1", "9.9.9.9"], "bans": bans}))
        ok, snapshot = client.fetch_sync(session, "https://peer:62026", details=True)
        assert ok
        assert snapshot == {"ips": ["1.1.1.1", "9.9.9.9"], "bans": bans}
        assert session.queries[0]["params"]["details"] == "true"

    def test_pagination_follows_the_cursor_and_keeps_the_first_page_blocklist(self):
        first = {"ips": ["1.1.1.1"], "bans": [{"ip": "1.1.1.1"}], "next_cursor": "MTAw"}
        session = FakeSession(FakeResponse(200, first), FakeResponse(200, {"ips": ["1.1.1.1"], "bans": [{"ip": "2.2.2.2"}]}))
        ok, snapshot = client.fetch_sync(session, "https://peer:62026", details=True)
        assert ok
        assert snapshot["bans"] == [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]
        assert snapshot["ips"] == ["1.1.1.1"]
        assert session.queries[1]["params"]["cursor"] == "MTAw"

    def test_an_empty_ledger_is_not_an_error(self):
        # `bans` is omitted from the answer when the ledger is empty. That is "nothing
        # expiring", never "unsupported" — the dialect is decided from the capabilities.
        session = FakeSession(FakeResponse(200, {"ips": ["9.9.9.9"]}))
        assert client.fetch_sync(session, "https://peer:62026", details=True) == (True, {"ips": ["9.9.9.9"], "bans": []})

    @pytest.mark.parametrize("answer", (OSError("connection refused"), FakeResponse(500), FakeResponse(403), FakeResponse(200)))
    def test_any_unusable_answer_fails_rather_than_reporting_an_empty_blocklist(self, answer):
        # Reporting an empty blocklist here would read as "the peer holds nothing of
        # ours" and could trigger deletions.
        ok, _ = client.fetch_sync(FakeSession(answer), "https://peer:62026")
        assert ok is False

    def test_a_peer_that_dies_mid_pagination_fails(self):
        first = {"ips": [], "bans": [{"ip": "1.1.1.1"}], "next_cursor": "MTAw"}
        session = FakeSession(FakeResponse(200, first), OSError("connection reset"))
        ok, _ = client.fetch_sync(session, "https://peer:62026", details=True)
        assert ok is False

    @pytest.mark.parametrize("payload", ({"ips": [], "bans": "not-a-list"}, {"ips": [], "bans": [], "next_cursor": 42}))
    def test_a_malformed_provenance_page_is_incomplete(self, payload):
        ok, _ = client.fetch_sync(FakeSession(FakeResponse(200, payload)), "https://peer:62026", details=True)
        assert ok is False

    def test_a_snapshot_that_exceeds_the_page_bound_is_incomplete(self):
        pages = [FakeResponse(200, {"ips": [], "bans": [], "next_cursor": str(index)}) for index in range(64)]
        ok, _ = client.fetch_sync(FakeSession(*pages), "https://peer:62026", details=True)
        assert ok is False


class TestExtractIPs:
    def test_the_empty_blocklist_contract_is_tolerated(self):
        # A peer with nothing banned answers {"ips": null}.
        assert client.extract_ips({"ips": None}) == []

    def test_entries_are_stripped_and_filtered(self):
        assert client.extract_ips({"ips": [" 1.1.1.1 ", ""]}) == ["1.1.1.1"]

    def test_a_bare_list_is_accepted(self):
        assert client.extract_ips(["1.1.1.1"]) == ["1.1.1.1"]

    @pytest.mark.parametrize("payload", ({}, {"ips": "1.1.1.1"}, {"ips": ["1.1.1.1", 42]}, "nope"))
    def test_a_missing_or_malformed_contract_is_not_an_empty_blocklist(self, payload):
        assert client.extract_ips(payload) is None


class TestTLSSettings:
    """The gate that decides whether to trust a peer at all.

    Every refusal branch exits the job rather than downgrading: the bearer token travels
    on this connection, so a silent fallback would hand it to whoever answers.
    """

    @staticmethod
    def _clear(monkeypatch):
        for name in ("SYSWARDEN_CA_BUNDLE", "SYSWARDEN_SSL_FINGERPRINT", "SYSWARDEN_SSL_INSECURE"):
            monkeypatch.delenv(name, raising=False)

    def test_a_ca_bundle_wins_and_is_used_as_is(self, tmp_path, monkeypatch):
        self._clear(monkeypatch)
        bundle = tmp_path / "ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
        monkeypatch.setenv("SYSWARDEN_CA_BUNDLE", str(bundle))
        monkeypatch.setenv("SYSWARDEN_SSL_FINGERPRINT", "ab" * 32)
        assert client.tls_settings(FakeLogger()) == (str(bundle), "")

    def test_an_unreadable_bundle_falls_through_to_the_pin(self, tmp_path, monkeypatch):
        self._clear(monkeypatch)
        monkeypatch.setenv("SYSWARDEN_CA_BUNDLE", str(tmp_path / "missing.pem"))
        monkeypatch.setenv("SYSWARDEN_SSL_FINGERPRINT", "AB:" * 31 + "AB")
        verify, fingerprint = client.tls_settings(FakeLogger())
        assert verify is False
        assert fingerprint == "ab" * 32

    def test_the_openssl_form_of_a_pin_is_accepted(self, monkeypatch):
        # This is the exact string the README tells the operator to paste.
        self._clear(monkeypatch)
        monkeypatch.setenv("SYSWARDEN_SSL_FINGERPRINT", "SHA256 Fingerprint=" + ":".join(["AB"] * 32))
        assert client.tls_settings(FakeLogger())[1] == "ab" * 32

    @pytest.mark.parametrize("pin", ("abcdef01", "zz" * 32))
    def test_a_pin_that_is_not_a_sha256_digest_refuses_to_run(self, pin, monkeypatch):
        # Short or non-hex: the setting's own regex lets both through, so this is the
        # only thing standing between a typo and an unverified connection.
        self._clear(monkeypatch)
        monkeypatch.setenv("SYSWARDEN_SSL_FINGERPRINT", pin)
        with pytest.raises(SystemExit) as refusal:
            client.tls_settings(FakeLogger())
        assert refusal.value.code == 2

    def test_nothing_configured_refuses_to_run(self, monkeypatch):
        self._clear(monkeypatch)
        with pytest.raises(SystemExit) as refusal:
            client.tls_settings(FakeLogger())
        assert refusal.value.code == 2

    def test_the_explicit_opt_out_is_honoured_and_warned_about(self, monkeypatch):
        self._clear(monkeypatch)
        monkeypatch.setenv("SYSWARDEN_SSL_INSECURE", "yes")
        logger = FakeLogger()
        assert client.tls_settings(logger) == (False, "")
        assert any("MITM" in message for message in logger.warnings)


class TestMakeSession:
    def test_an_empty_token_refuses_to_run(self, monkeypatch):
        # A peer whose own token is empty authenticates on the source IP alone. Building
        # an integration on that posture is what this refusal prevents.
        monkeypatch.delenv("SYSWARDEN_API_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SYSWARDEN_API_TOKEN", "")
        monkeypatch.setenv("SYSWARDEN_SSL_INSECURE", "yes")
        with pytest.raises(SystemExit) as refusal:
            client.make_session(FakeLogger())
        assert refusal.value.code == 2

    def test_the_bearer_header_is_set_once_for_every_call(self, monkeypatch):
        monkeypatch.delenv("SYSWARDEN_API_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SYSWARDEN_API_TOKEN", "Bearer  s3cr3t ")
        monkeypatch.setenv("SYSWARDEN_SSL_INSECURE", "yes")
        session = client.make_session(FakeLogger())
        assert session.headers["Authorization"] == "Bearer s3cr3t"

    def test_environment_proxies_are_disabled_and_retries_are_bounded(self, monkeypatch):
        monkeypatch.delenv("SYSWARDEN_API_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SYSWARDEN_API_TOKEN", "s3cr3t")
        monkeypatch.setenv("SYSWARDEN_SSL_INSECURE", "yes")
        session = client.make_session(FakeLogger())
        retry = session.get_adapter("https://").max_retries
        assert session.trust_env is False
        assert retry.total == 1
        assert retry.respect_retry_after_header is False


class TestManifestPinnedSession:
    def _pinned(self, monkeypatch):
        monkeypatch.delenv("SYSWARDEN_API_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SYSWARDEN_API_TOKEN", "s3cr3t")
        # No CA bundle, no fingerprint, no insecure opt-out: the pins are the posture, and
        # make_session must not fall back on the global gate (which would exit 2 here).
        monkeypatch.delenv("SYSWARDEN_CA_BUNDLE", raising=False)
        monkeypatch.delenv("SYSWARDEN_SSL_FINGERPRINT", raising=False)
        monkeypatch.setenv("SYSWARDEN_SSL_INSECURE", "no")
        return client.make_session(FakeLogger(), pins={"https://10.0.0.5:62026": "c" * 64})

    def test_a_manifest_member_gets_its_own_pinned_adapter(self, monkeypatch):
        session = self._pinned(monkeypatch)
        adapter = session.get_adapter("https://10.0.0.5:62026/ha/status")
        assert isinstance(adapter, client.FingerprintAdapter)

    def test_a_host_outside_the_manifest_is_refused_instead_of_trusted(self, monkeypatch):
        # The pinned session runs with chain validation off, so a fall-through adapter would
        # accept any certificate and hand it the bearer token.
        session = self._pinned(monkeypatch)
        assert isinstance(session.get_adapter("https://10.0.0.9:62026/ha/status"), client.UnpinnedRefusalAdapter)
        reachable, error = client.fetch_fence_status(session, "https://10.0.0.9:62026", "c" * 43)
        assert reachable is False
        assert "manifest" in error

    def test_pins_do_not_go_through_the_global_tls_gate(self, monkeypatch):
        # Without pins this environment exits 2; with them it must build a session.
        session = self._pinned(monkeypatch)
        assert session.verify is False


class TestGetPeers:
    def test_no_usable_peer_refuses_to_run(self, monkeypatch):
        monkeypatch.setenv("SYSWARDEN_PEERS", "")
        with pytest.raises(SystemExit) as refusal:
            client.get_peers(FakeLogger())
        assert refusal.value.code == 2

    def test_a_malformed_entry_is_logged_and_the_good_ones_survive(self, monkeypatch):
        monkeypatch.setenv("SYSWARDEN_PEERS", "good.example host:abc")
        logger = FakeLogger()
        assert client.get_peers(logger) == ["https://good.example:62026"]
        assert any("host:abc" in message for message in logger.errors)


class TestGetTimeout:
    def test_garbage_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("SYSWARDEN_TIMEOUT", "not-a-number")
        assert client.get_timeout() == 5

    def test_a_configured_value_wins(self, monkeypatch):
        monkeypatch.setenv("SYSWARDEN_TIMEOUT", "3")
        assert client.get_timeout() == 3

    @pytest.mark.parametrize("value", ("0", "31", "-1"))
    def test_zero_negative_or_excessive_timeout_falls_back(self, value, monkeypatch):
        monkeypatch.setenv("SYSWARDEN_TIMEOUT", value)
        assert client.get_timeout() == 5
