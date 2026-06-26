"""Unit tests for cloudflare/jobs/cloudflare_helpers.py (pure logic, no BunkerWeb deps)."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def helpers():
    path = REPO_ROOT / "cloudflare" / "jobs" / "cloudflare_helpers.py"
    spec = importlib.util.spec_from_file_location("cloudflare_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def now():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


# --- check_line -------------------------------------------------------------------


def test_check_line_accepts_ip_and_cidr(helpers):
    assert helpers.check_line(b"1.2.3.4") == (True, b"1.2.3.4")
    assert helpers.check_line(b"173.245.48.0/20") == (True, b"173.245.48.0/20")
    assert helpers.check_line(b"2400:cb00::/32") == (True, b"2400:cb00::/32")


def test_check_line_rejects_junk(helpers):
    assert helpers.check_line(b"not-an-ip") == (False, b"")
    assert helpers.check_line(b"# comment") == (False, b"")
    assert helpers.check_line(b"999.999.0.0/8") == (False, b"")


# --- parse_ban_key ----------------------------------------------------------------


def test_parse_ban_key_global(helpers):
    assert helpers.parse_ban_key("bans_ip_1.2.3.4") == "1.2.3.4"
    assert helpers.parse_ban_key(b"bans_ip_2001:db8::1") == "2001:db8::1"


def test_parse_ban_key_service(helpers):
    assert helpers.parse_ban_key("bans_service_www.example.com_ip_5.6.7.8") == "5.6.7.8"


def test_parse_ban_key_non_ban_key(helpers):
    assert helpers.parse_ban_key("sessions_abc") is None
    assert helpers.parse_ban_key("bans_ip_") is None


# --- get_env_secret (_FILE convention) --------------------------------------------


def test_get_env_secret_prefers_file_then_env(helpers, tmp_path, monkeypatch):
    secret = tmp_path / "token"
    secret.write_text("from-file\n")
    monkeypatch.setenv("X_CLOUDFLARE_API_TOKEN_FILE", str(secret))
    monkeypatch.setenv("X_CLOUDFLARE_API_TOKEN", "from-env")
    assert helpers.get_env_secret("X_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN") == "from-file"


def test_get_env_secret_falls_back_to_global_env(helpers, monkeypatch):
    monkeypatch.delenv("X_CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("X_CLOUDFLARE_API_TOKEN_FILE", raising=False)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "global-token")
    assert helpers.get_env_secret("X_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN") == "global-token"


def test_get_env_secret_default_when_unset(helpers, monkeypatch):
    for var in ("X", "Y", "X_FILE", "Y_FILE"):
        monkeypatch.delenv(var, raising=False)
    assert helpers.get_env_secret("X", "Y", default="") == ""


# --- request_type_for -------------------------------------------------------------


def test_request_type_for(helpers):
    assert helpers.request_type_for("ecdsa") == "origin-ecc"
    assert helpers.request_type_for("rsa") == "origin-rsa"
    assert helpers.request_type_for("anything-else") == "origin-rsa"


# --- build_csr_config -------------------------------------------------------------


def test_build_csr_config_contains_cn_and_sans(helpers):
    conf = helpers.build_csr_config("www.example.com", ["www.example.com", "example.com"])
    assert "CN                  = www.example.com" in conf
    assert "DNS.1 = www.example.com" in conf
    assert "DNS.2 = example.com" in conf
    assert "[alt_names]" in conf


def test_build_csr_config_is_deterministic(helpers):
    a = helpers.build_csr_config("a.example.com", ["a.example.com"])
    b = helpers.build_csr_config("a.example.com", ["a.example.com"])
    assert a == b


# --- select_zone_name -------------------------------------------------------------


def test_select_zone_name_strips_subdomain(helpers):
    assert helpers.select_zone_name(["www.example.com"]) == "example.com"
    assert helpers.select_zone_name(["example.com"]) == "example.com"


def test_select_zone_name_picks_shortest(helpers):
    # With multiple registrable domains the shortest wins (a documented heuristic).
    assert helpers.select_zone_name(["a.verylongdomain.com", "b.short.io"]) == "short.io"


def test_select_zone_name_cctld_limitation_documented(helpers):
    # Public-suffix-naive: a.co.uk collapses to co.uk (set CLOUDFLARE_ZONE_ID for ccTLDs).
    assert helpers.select_zone_name(["a.co.uk"]) == "co.uk"


def test_select_zone_name_empty(helpers):
    assert helpers.select_zone_name([]) == ""


# --- select_zone ------------------------------------------------------------------


def test_select_zone_picks_most_recent(helpers):
    zones = [
        {"id": "old", "modified_on": "2020-01-01T00:00:00Z"},
        {"id": "new", "modified_on": "2025-01-01T00:00:00Z"},
    ]
    assert helpers.select_zone(zones)["id"] == "new"


def test_select_zone_empty(helpers):
    assert helpers.select_zone([]) is None


# --- expiry parsing ---------------------------------------------------------------


def test_parse_expires_on_go_format(helpers):
    dt = helpers.parse_expires_on("2039-01-01 00:00:00 +0000 UTC")
    assert dt.year == 2039 and dt.tzinfo is not None


def test_parse_expires_on_rfc3339(helpers):
    dt = helpers.parse_expires_on("2039-01-01T00:00:00Z")
    assert dt.year == 2039 and dt.tzinfo is not None


def test_parse_expires_on_garbage_is_epoch(helpers):
    assert helpers.parse_expires_on("not-a-date").year == 1970


def test_parse_expires_on_none_is_epoch(helpers):
    # The Cloudflare SDK exposes expires_on as Optional[str]; None must not crash.
    assert helpers.parse_expires_on(None).year == 1970


def test_is_expired_none_is_true(helpers, now):
    assert helpers.is_expired(None, now) is True


def test_is_expired(helpers, now):
    assert helpers.is_expired("2020-01-01 00:00:00 +0000 UTC", now) is True
    assert helpers.is_expired("2099-01-01 00:00:00 +0000 UTC", now) is False


# --- hostnames_match / find_matching_cert -----------------------------------------


def test_hostnames_match_is_set_based(helpers):
    assert helpers.hostnames_match(["a.com", "b.com"], ["b.com", "a.com"]) is True
    assert helpers.hostnames_match(["a.com"], ["a.com", "b.com"]) is False


def test_find_matching_cert_match_valid(helpers, now):
    certs = [{"id": "c1", "hostnames": ["www.example.com"], "expires_on": "2099-01-01 00:00:00 +0000 UTC"}]
    cert_id, found, expired = helpers.find_matching_cert(certs, ["www.example.com"], now)
    assert (cert_id, found, expired) == ("c1", True, False)


def test_find_matching_cert_match_expired(helpers, now):
    certs = [{"id": "c1", "hostnames": ["www.example.com"], "expires_on": "2020-01-01 00:00:00 +0000 UTC"}]
    cert_id, found, expired = helpers.find_matching_cert(certs, ["www.example.com"], now)
    assert (cert_id, found, expired) == ("c1", True, True)


def test_find_matching_cert_no_match(helpers, now):
    certs = [{"id": "c1", "hostnames": ["other.example.com"], "expires_on": "2099-01-01 00:00:00 +0000 UTC"}]
    assert helpers.find_matching_cert(certs, ["www.example.com"], now) == (None, False, False)
