"""Unit tests for the SysWarden plugin's pure job helpers."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

HELPERS_PATH = Path(__file__).resolve().parent.parent / "syswarden" / "jobs" / "syswarden_helpers.py"


def _load_helpers():
    """Load the helpers by path: `syswarden/jobs` is not an importable package."""
    spec = spec_from_file_location("syswarden_helpers", HELPERS_PATH)
    assert spec and spec.loader, f"cannot load {HELPERS_PATH}"
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helpers = _load_helpers()


class TestParsePeers:
    def test_empty_input_yields_nothing(self):
        assert helpers.parse_peers("") == ([], [])
        assert helpers.parse_peers(None) == ([], [])

    def test_host_gets_the_default_port(self):
        urls, errors = helpers.parse_peers("syswarden.internal")
        assert urls == ["https://syswarden.internal:62026"]
        assert errors == []

    def test_explicit_port_wins(self):
        urls, _ = helpers.parse_peers("10.0.0.1:9443")
        assert urls == ["https://10.0.0.1:9443"]

    def test_bare_ipv6_keeps_its_colons_and_gets_bracketed(self):
        # The colons are the address, not a port separator.
        urls, errors = helpers.parse_peers("2001:db8::1")
        assert urls == ["https://[2001:db8::1]:62026"]
        assert errors == []

    def test_bracketed_ipv6_with_port(self):
        urls, _ = helpers.parse_peers("[2001:db8::1]:9443")
        assert urls == ["https://[2001:db8::1]:9443"]

    def test_several_peers_split_on_whitespace(self):
        urls, _ = helpers.parse_peers("  a.example  b.example:1234\t[::1]:62026 ")
        assert urls == ["https://a.example:62026", "https://b.example:1234", "https://[::1]:62026"]

    @pytest.mark.parametrize("entry", ("host:", "host:abc", "host:0", "host:70000", "[::1", "[::1]junk", ":62026"))
    def test_malformed_entries_are_reported_not_raised(self, entry):
        urls, errors = helpers.parse_peers(entry)
        assert urls == []
        assert len(errors) == 1
        assert entry in errors[0]

    def test_one_bad_entry_does_not_drop_the_good_ones(self):
        urls, errors = helpers.parse_peers("good.example host:abc other.example")
        assert urls == ["https://good.example:62026", "https://other.example:62026"]
        assert len(errors) == 1


class TestGetEnvSecret:
    def test_file_takes_precedence_over_raw_value(self, tmp_path, monkeypatch):
        secret_file = tmp_path / "token"
        secret_file.write_text("  from-file  ", encoding="utf-8")
        monkeypatch.setenv("SW_TOKEN_FILE", str(secret_file))
        monkeypatch.setenv("SW_TOKEN", "from-env")
        assert helpers.get_env_secret("SW_TOKEN") == "from-file"

    def test_falls_back_to_the_raw_value(self, monkeypatch):
        monkeypatch.delenv("SW_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SW_TOKEN", " from-env ")
        assert helpers.get_env_secret("SW_TOKEN") == "from-env"

    def test_unreadable_file_falls_through_instead_of_raising(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SW_TOKEN_FILE", str(tmp_path / "missing"))
        monkeypatch.setenv("SW_TOKEN", "from-env")
        assert helpers.get_env_secret("SW_TOKEN") == "from-env"

    def test_second_name_is_the_fallback(self, monkeypatch):
        monkeypatch.delenv("SW_TOKEN", raising=False)
        monkeypatch.delenv("SW_TOKEN_FILE", raising=False)
        monkeypatch.setenv("SW_OTHER", "other")
        assert helpers.get_env_secret("SW_TOKEN", "SW_OTHER") == "other"

    def test_default_when_nothing_is_set(self, monkeypatch):
        monkeypatch.delenv("SW_TOKEN", raising=False)
        monkeypatch.delenv("SW_TOKEN_FILE", raising=False)
        assert helpers.get_env_secret("SW_TOKEN", "", "fallback") == "fallback"


class TestParseBanKey:
    def test_global_ban_key(self):
        assert helpers.parse_ban_key("bans_ip_1.2.3.4") == {"ip": "1.2.3.4", "service": ""}

    def test_service_ban_key(self):
        assert helpers.parse_ban_key("bans_service_app.example.com_ip_1.2.3.4") == {
            "ip": "1.2.3.4",
            "service": "app.example.com",
        }

    def test_service_name_containing_the_separator(self):
        # rpartition: the LAST "_ip_" separates the address, so a service whose name
        # contains "_ip_" still parses.
        assert helpers.parse_ban_key("bans_service_weird_ip_svc_ip_10.0.0.9") == {
            "ip": "10.0.0.9",
            "service": "weird_ip_svc",
        }

    def test_bytes_keys_are_decoded(self):
        assert helpers.parse_ban_key(b"bans_ip_::1") == {"ip": "::1", "service": ""}

    @pytest.mark.parametrize("key", ("sessions_1.2.3.4", "bans_ip_", "", "bans_service_app_ip_"))
    def test_non_ban_keys_return_none(self, key):
        assert helpers.parse_ban_key(key) is None


class TestNormalizeBan:
    def test_api_record_keeps_scope_and_ttl(self):
        record = {"ip": "1.2.3.4", "service": "app", "ban_scope": "service", "exp": 3600, "permanent": False, "reason": "bad behavior"}
        assert helpers.normalize_ban(record) == {
            "ip": "1.2.3.4",
            "service": "app",
            "ban_scope": "service",
            "ttl": 3600,
            "reason": "bad behavior",
        }

    def test_permanent_ban_has_no_ttl(self):
        record = {"ip": "1.2.3.4", "exp": 42, "permanent": True}
        assert helpers.normalize_ban(record)["ttl"] is None

    def test_scope_is_derived_when_absent(self):
        assert helpers.normalize_ban({"ip": "1.2.3.4"})["ban_scope"] == "global"
        assert helpers.normalize_ban({"ip": "1.2.3.4", "service": "app"})["ban_scope"] == "service"

    def test_record_without_ip_is_dropped(self):
        assert helpers.normalize_ban({"service": "app"}) is None
        assert helpers.normalize_ban({"ip": "   "}) is None


class TestSelectBans:
    def test_deduplicates_on_ip_scope_service(self):
        records = [
            {"ip": "1.2.3.4", "service": "a", "ban_scope": "service"},
            {"ip": "1.2.3.4", "service": "a", "ban_scope": "service"},
            {"ip": "1.2.3.4"},
        ]
        assert set(helpers.select_bans(records)) == {"1.2.3.4"}

    def test_scope_filter_keeps_global_bans(self):
        records = [
            {"ip": "1.1.1.1", "service": "kept"},
            {"ip": "2.2.2.2", "service": "dropped"},
            {"ip": "3.3.3.3"},
        ]
        assert set(helpers.select_bans(records, scope_filter=["kept"])) == {"1.1.1.1", "3.3.3.3"}

    def test_empty_scope_filter_means_every_service(self):
        records = [{"ip": "1.1.1.1", "service": "a"}, {"ip": "2.2.2.2", "service": "b"}]
        assert set(helpers.select_bans(records, scope_filter=[])) == {"1.1.1.1", "2.2.2.2"}

    def test_min_ttl_drops_short_bans_but_never_permanent_ones(self):
        records = [
            {"ip": "1.1.1.1", "exp": 30},
            {"ip": "2.2.2.2", "exp": 3600},
            {"ip": "3.3.3.3", "permanent": True},
        ]
        assert set(helpers.select_bans(records, min_ttl=60)) == {"2.2.2.2", "3.3.3.3"}

    def test_no_records_yields_an_empty_mapping(self):
        assert helpers.select_bans([]) == {}

    def test_ttl_and_reason_travel_with_the_ip(self):
        records = [{"ip": "1.1.1.1", "exp": 900, "reason": "bad behavior"}]
        assert helpers.select_bans(records) == {"1.1.1.1": {"ttl": 900, "reason": "bad behavior"}}

    def test_the_longest_ban_wins_on_a_shared_ip(self):
        records = [
            {"ip": "1.1.1.1", "service": "short", "exp": 60},
            {"ip": "1.1.1.1", "service": "long", "exp": 3600},
        ]
        assert helpers.select_bans(records)["1.1.1.1"]["ttl"] == 3600

    def test_a_permanent_ban_is_never_shortened_by_a_dated_one(self):
        records = [
            {"ip": "1.1.1.1", "service": "perm", "permanent": True},
            {"ip": "1.1.1.1", "service": "short", "exp": 60},
        ]
        assert helpers.select_bans(records)["1.1.1.1"]["ttl"] is None


class TestExtractInstanceBans:
    def test_every_configured_instance_must_return_a_ban_list(self):
        responses = {"one": {"status": "success", "msg": [{"ip": "1.1.1.1"}]}}
        assert helpers.extract_instance_bans(responses, expected=1) == [{"ip": "1.1.1.1"}]
        assert helpers.extract_instance_bans(responses, expected=2) is None

    @pytest.mark.parametrize("response", ({"status": "success"}, {"msg": "not-a-list"}, "not-an-object"))
    def test_a_malformed_instance_response_is_incomplete(self, response):
        assert helpers.extract_instance_bans({"one": response}, expected=1) is None

    def test_the_older_data_field_is_still_accepted(self):
        assert helpers.extract_instance_bans({"one": {"data": [{"ip": "1.1.1.1"}]}}, expected=1) == [{"ip": "1.1.1.1"}]


class TestCapItems:
    def test_under_the_cap_is_sorted_and_untouched(self):
        kept, dropped = helpers.cap_items({"2.2.2.2", "1.1.1.1"}, 10)
        assert kept == ["1.1.1.1", "2.2.2.2"]
        assert dropped == 0

    def test_truncation_is_deterministic(self):
        first, dropped = helpers.cap_items(["9.9.9.9", "1.1.1.1", "5.5.5.5"], 2)
        second, _ = helpers.cap_items(["5.5.5.5", "9.9.9.9", "1.1.1.1"], 2)
        assert first == second == ["1.1.1.1", "5.5.5.5"]
        assert dropped == 1

    def test_zero_or_negative_cap_disables_truncation(self):
        kept, dropped = helpers.cap_items(["1.1.1.1", "2.2.2.2"], 0)
        assert kept == ["1.1.1.1", "2.2.2.2"]
        assert dropped == 0


class TestSupportsBanSync:
    def test_both_v403_capabilities_are_required(self):
        assert helpers.supports_ban_sync({"sync_ttl", "sync_provenance"})
        assert not helpers.supports_ban_sync({"sync_ttl"})
        assert not helpers.supports_ban_sync({"sync_provenance"})
        assert not helpers.supports_ban_sync(set())


class TestPlanPeer:
    def test_a_provenance_peer_is_diffed_against_its_own_ledger(self):
        assert helpers.plan_peer({"1.1.1.1", "2.2.2.2"}, set(), {"1.1.1.1", "9.9.9.9"}, set(), True) == (["2.2.2.2"], ["9.9.9.9"], [])

    def test_a_provenance_peer_never_touches_an_entry_it_does_not_own(self):
        # An operator's `syswarden block` sits in the static store, not in our ledger, and
        # our registry never claimed it. It must survive every pass untouched.
        assert helpers.plan_peer(set(), {"8.8.8.8"}, set(), set(), True) == ([], [], [])

    def test_a_provenance_peer_cleans_what_the_legacy_dialect_left_behind(self):
        # Pushed with {"ips"} before the peer understood provenance: still in its static
        # store, absent from its ledger, no longer banned. Only DELETE {"ips"} clears it.
        assert helpers.plan_peer(set(), {"1.1.1.1", "8.8.8.8"}, set(), {"1.1.1.1"}, True) == ([], [], ["1.1.1.1"])

    def test_a_still_banned_address_is_never_cleaned_as_stale(self):
        # GET /ha/sync returns the union of both stores, so a banned address appearing there
        # proves nothing about the static one. Cleanup waits until the ban is lifted.
        assert helpers.plan_peer({"1.1.1.1"}, {"1.1.1.1"}, {"1.1.1.1"}, {"1.1.1.1"}, True) == ([], [], [])

    def test_a_legacy_peer_is_diffed_against_its_static_blocklist(self):
        assert helpers.plan_peer({"1.1.1.1", "2.2.2.2"}, {"1.1.1.1", "9.9.9.9"}, set(), {"9.9.9.9"}, False) == (["2.2.2.2"], ["9.9.9.9"], [])

    def test_a_legacy_peer_only_removes_what_the_registry_claims(self):
        # 9.9.9.9 is on the peer but was never pushed by us: operator or real HA peer.
        assert helpers.plan_peer(set(), {"9.9.9.9"}, set(), set(), False) == ([], [], [])

    def test_a_legacy_peer_never_gets_a_stale_legacy_list(self):
        # It has no ledger, so its static store is the only store and to_remove covers it.
        _, _, stale = helpers.plan_peer(set(), {"1.1.1.1"}, set(), {"1.1.1.1"}, False)
        assert stale == []

    def test_the_addition_cap_drains_a_backlog_after_diffing(self):
        banned = {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
        to_add, to_remove, _ = helpers.plan_peer(banned, set(), {"1.1.1.1"}, set(), True)
        first, dropped = helpers.cap_items(to_add, 2)
        assert (first, dropped, to_remove) == (["2.2.2.2", "3.3.3.3"], 1, [])
        assert helpers.plan_peer(banned, set(), {"1.1.1.1", *first}, set(), True)[:2] == (["4.4.4.4"], [])


class TestNextRegistry:
    GRACE = helpers.SYSWARDEN_LEGACY_GRACE

    def call(self, owned, seen_remote=(), still_banned=(), now=1000.0, complete=True, pushed_ok=()):
        return helpers.next_registry(pushed_ok, owned, seen_remote, still_banned, now, complete)

    def test_a_successful_legacy_push_claims_the_address_with_no_clock(self):
        assert self.call({}, pushed_ok={"1.1.1.1"}) == {"1.1.1.1": None}

    def test_an_address_a_peer_still_holds_has_no_clock(self):
        assert self.call({"1.1.1.1": None}, seen_remote={"1.1.1.1"}) == {"1.1.1.1": None}

    def test_an_address_absent_everywhere_starts_the_clock_but_is_kept(self):
        assert self.call({"1.1.1.1": None}) == {"1.1.1.1": 1000.0}

    def test_the_claim_is_released_once_the_grace_window_elapsed(self):
        assert self.call({"1.1.1.1": 1000.0}, now=1000.0 + self.GRACE) == {}

    def test_one_second_short_of_the_window_keeps_the_claim(self):
        assert self.call({"1.1.1.1": 1000.0}, now=1000.0 + self.GRACE - 1) == {"1.1.1.1": 1000.0}

    def test_a_reappearance_restarts_the_window(self):
        # SysWarden's own ha-sync pushed the entry back from another peer.
        assert self.call({"1.1.1.1": 1000.0}, seen_remote={"1.1.1.1"}, now=1000.0 + self.GRACE) == {"1.1.1.1": None}

    def test_a_still_banned_address_never_runs_the_clock(self):
        assert self.call({"1.1.1.1": 1000.0}, still_banned={"1.1.1.1"}, now=1000.0 + self.GRACE) == {"1.1.1.1": None}

    def test_a_partial_view_resets_the_clock_rather_than_pausing_it(self):
        # Upstream is explicit: an hour of continuous absence must not span a period during
        # which the cluster view was incomplete. Pausing would let a stale start mature.
        assert self.call({"1.1.1.1": 1000.0}, now=1000.0 + self.GRACE, complete=False) == {"1.1.1.1": None}

    def test_a_partial_view_releases_nothing(self):
        assert self.call({"1.1.1.1": 1000.0}, now=1e9, complete=False) == {"1.1.1.1": None}

    def test_output_is_sorted(self):
        assert list(self.call({}, pushed_ok={"9.9.9.9", "1.1.1.1"})) == ["1.1.1.1", "9.9.9.9"]


class TestResurrected:
    def test_an_entry_whose_clock_was_running_and_is_back_is_reported(self):
        assert helpers.resurrected({"1.1.1.1": 1000.0}, {"1.1.1.1"}) == ["1.1.1.1"]

    def test_an_entry_never_seen_clean_is_not_a_resurrection(self):
        assert helpers.resurrected({"1.1.1.1": None}, {"1.1.1.1"}) == []

    def test_an_entry_no_peer_reports_is_not_a_resurrection(self):
        assert helpers.resurrected({"1.1.1.1": 1000.0}, set()) == []


class TestLoadRegistry:
    def test_the_current_layout_round_trips(self):
        assert helpers.load_registry({"membership": "abc", "claims": {"1.1.1.1": 12.0}}) == ({"1.1.1.1": 12.0}, "abc")

    def test_a_bare_list_from_the_first_versions_loads_with_no_clock(self):
        assert helpers.load_registry(["1.1.1.1", 7]) == ({"1.1.1.1": None}, "")

    def test_a_flat_mapping_from_the_grace_window_version_loads(self):
        # No membership recorded, which forces exactly one reset on the next pass.
        assert helpers.load_registry({"1.1.1.1": 12.0}) == ({"1.1.1.1": 12.0}, "")

    def test_garbage_is_dropped_rather_than_raising(self):
        assert helpers.load_registry({"claims": {"1.1.1.1": "soon", 7: 1.0, "2.2.2.2": None}, "membership": 9}) == ({"2.2.2.2": None}, "")

    def test_a_non_mapping_yields_an_empty_registry(self):
        assert helpers.load_registry("nope") == ({}, "")


class TestMembershipDigest:
    def test_order_and_duplicates_do_not_change_the_digest(self):
        assert helpers.membership_digest(["b", "a", "b"]) == helpers.membership_digest(["a", "b"])

    def test_adding_a_peer_changes_the_digest(self):
        # Which is what restarts every release window, as upstream requires.
        assert helpers.membership_digest(["a"]) != helpers.membership_digest(["a", "b"])


class TestChunked:
    def test_splits_into_batches(self):
        assert helpers.chunked(["a", "b", "c", "d", "e"], 2) == [["a", "b"], ["c", "d"], ["e"]]

    def test_exact_multiple_has_no_trailing_empty_batch(self):
        assert helpers.chunked(["a", "b"], 2) == [["a", "b"]]

    def test_empty_input_yields_no_batch(self):
        assert helpers.chunked([], 500) == []

    def test_non_positive_size_means_one_batch(self):
        assert helpers.chunked(["a", "b"], 0) == [["a", "b"]]


class TestCheckLine:
    @pytest.mark.parametrize("line", (b"1.2.3.4", b"10.0.0.0/8", b"::1", b"2001:db8::/32"))
    def test_accepts_valid_addresses_and_networks(self, line):
        assert helpers.check_line(line) == (True, line)

    @pytest.mark.parametrize("line", (b"", b"not-an-ip", b"1.2.3.4/33", b"999.1.1.1", b"<html>"))
    def test_rejects_anything_else(self, line):
        assert helpers.check_line(line) == (False, b"")


class TestSerializeAddresses:
    def test_output_is_sorted_unique_and_newline_terminated(self):
        assert helpers.serialize_addresses(["2.2.2.2", "1.1.1.1", "2.2.2.2"]) == (b"1.1.1.1\n2.2.2.2\n", 2, 0)

    def test_an_authoritative_empty_list_is_valid(self):
        assert helpers.serialize_addresses([]) == (b"", 0, 0)

    def test_invalid_entries_are_counted_without_entering_the_output(self):
        assert helpers.serialize_addresses(["1.1.1.1", "not-an-ip"]) == (b"1.1.1.1\n", 1, 1)


class TestExtractWhitelistIPs:
    def test_valid_empty_whitelist_is_distinct_from_a_missing_contract(self):
        assert helpers.extract_whitelist_ips({"whitelist": {"ips": None}}) == []
        assert helpers.extract_whitelist_ips({"whitelist": {"ips": []}}) == []
        assert helpers.extract_whitelist_ips({}) is None

    def test_malformed_entries_reject_the_snapshot(self):
        assert helpers.extract_whitelist_ips({"whitelist": {"ips": ["1.1.1.1", 42]}}) is None


class TestNormalizeFingerprint:
    def test_openssl_output_becomes_a_bare_digest(self):
        # This is what the README tells the operator to paste, so it has to survive.
        assert helpers.normalize_fingerprint("SHA256 Fingerprint=AB:CD:EF:01") == "abcdef01"

    def test_a_sha256_prefix_is_stripped(self):
        assert helpers.normalize_fingerprint("sha256:ABCDEF01") == "abcdef01"
        assert helpers.normalize_fingerprint("sha-256:ab:cd:ef:01") == "abcdef01"

    def test_an_empty_value_stays_empty(self):
        # tls_settings reads "" as "no pin configured", so this must not invent one.
        assert helpers.normalize_fingerprint("") == ""
        assert helpers.normalize_fingerprint(None) == ""


class TestParseTelemetry:
    def test_reads_the_documented_shape(self):
        payload = {
            "github_release": "v4.02.8",
            "system": {"hostname": "host-a", "os": "debian", "services": ["nginx"], "ports": [80]},
            "layer3": {"global_blocked": 5, "geoip_blocked": 2, "asn_blocked": 1, "l7_banned": 7},
            "waf": {"total_banned": 3, "total_detected": 9, "active_signatures": 42, "top_attackers": [{"ip": "1.2.3.4"}]},
            "whitelist": {"active_ips": 1, "ips": ["9.9.9.9"]},
        }
        parsed = helpers.parse_telemetry(payload, {"hostname": "host-a", "status": "ok", "version": "4.02.8"})
        assert parsed["hostname"] == "host-a"
        assert parsed["version"] == "4.02.8"
        assert parsed["status"] == "ok"
        assert parsed["global_blocked"] == 5
        assert parsed["waf_active_signatures"] == 42
        assert parsed["whitelist_ips"] == ["9.9.9.9"]

    def test_missing_sections_degrade_to_zeros(self):
        parsed = helpers.parse_telemetry({})
        assert parsed["hostname"] == ""
        assert parsed["global_blocked"] == 0
        assert parsed["whitelist_ips"] == []

    @pytest.mark.parametrize("payload", (None, [], "nope", 42))
    def test_a_non_dict_payload_does_not_raise(self, payload):
        assert helpers.parse_telemetry(payload)["hostname"] == ""

    def test_partial_sections_do_not_raise(self):
        parsed = helpers.parse_telemetry({"system": None, "waf": {"total_banned": 2}, "whitelist": {"ips": [1, "9.9.9.9"]}})
        assert parsed["waf_total_banned"] == 2
        assert parsed["whitelist_ips"] == ["9.9.9.9"]

    def test_version_falls_back_to_github_release(self):
        assert helpers.parse_telemetry({"github_release": "v4.02.8"})["version"] == "v4.02.8"


class TestClampTTL:
    def test_a_permanent_ban_takes_the_ceiling(self):
        # SysWarden has no permanent provenance-aware ban; the next pass adds it again
        # after this bounded entry expires if BunkerWeb still holds the ban.
        assert helpers.clamp_ttl(None) == helpers.SYSWARDEN_MAX_TTL

    def test_a_long_ban_is_capped(self):
        assert helpers.clamp_ttl(helpers.SYSWARDEN_MAX_TTL * 4) == helpers.SYSWARDEN_MAX_TTL

    def test_a_short_or_expired_ban_takes_the_floor(self):
        assert helpers.clamp_ttl(0) == helpers.SYSWARDEN_MIN_TTL
        assert helpers.clamp_ttl(-30) == helpers.SYSWARDEN_MIN_TTL

    def test_a_normal_ban_passes_through(self):
        assert helpers.clamp_ttl(3600) == 3600


class TestSanitizeReason:
    def test_control_characters_are_dropped(self):
        assert helpers.sanitize_reason("bad\nbehavior\x00") == "badbehavior"

    def test_an_empty_reason_falls_back(self):
        assert helpers.sanitize_reason("") == "BunkerWeb ban"
        assert helpers.sanitize_reason("   ") == "BunkerWeb ban"

    def test_truncation_counts_bytes_and_never_splits_a_character(self):
        # A 3-byte character on purpose: 512 is not a multiple of 3, so the cut lands
        # mid-character and the decode has to drop the partial one. A 2-byte character
        # would divide evenly and never exercise that.
        sanitized = helpers.sanitize_reason("€" * 400)
        assert len(sanitized.encode("utf-8")) <= helpers.SYSWARDEN_MAX_REASON_BYTES
        assert sanitized == "€" * 170


class TestValidSource:
    @pytest.mark.parametrize("source", ("cluster-a", "bunkerweb/site_1", "a" * 64))
    def test_valid_cluster_unique_source_is_accepted(self, source):
        assert helpers.valid_source(source)

    @pytest.mark.parametrize("source", ("", "bunker web", "!!!", "a" * 65, None))
    def test_empty_invalid_or_oversized_source_is_rejected(self, source):
        assert not helpers.valid_source(source)


class TestBuildBanBatch:
    def test_entries_carry_exactly_the_four_required_fields(self):
        batch = helpers.build_ban_batch({"1.1.1.1": {"ttl": 900, "reason": "bad behavior"}}, "cluster-a")
        assert batch == [{"ip": "1.1.1.1", "ttl": 900, "reason": "bad behavior", "source": "cluster-a"}]

    def test_output_is_sorted_and_reasons_are_defaulted(self):
        batch = helpers.build_ban_batch({"9.9.9.9": {"ttl": None, "reason": ""}, "1.1.1.1": {"ttl": 60, "reason": "x"}}, "cluster-a")
        assert [entry["ip"] for entry in batch] == ["1.1.1.1", "9.9.9.9"]
        assert batch[1] == {"ip": "9.9.9.9", "ttl": helpers.SYSWARDEN_MAX_TTL, "reason": "BunkerWeb ban", "source": "cluster-a"}

    def test_an_implicit_source_is_refused(self):
        with pytest.raises(ValueError):
            helpers.build_ban_batch({"1.1.1.1": {"ttl": 60}}, "")


class TestBuildUnbanBatch:
    def test_a_delete_entry_carries_only_ip_and_source(self):
        assert helpers.build_unban_batch(["2.2.2.2", "1.1.1.1"], "cluster-a") == [
            {"ip": "1.1.1.1", "source": "cluster-a"},
            {"ip": "2.2.2.2", "source": "cluster-a"},
        ]

    def test_an_implicit_source_is_refused(self):
        with pytest.raises(ValueError):
            helpers.build_unban_batch(["1.1.1.1"], "")


class TestProvenanceIPs:
    def test_only_our_own_source_is_claimed(self):
        bans = [
            {"ip": "1.1.1.1", "source": "bunkerweb", "peer_scope": "10.0.0.2/32"},
            {"ip": "2.2.2.2", "source": "crowdsec", "peer_scope": "10.0.0.3/32"},
        ]
        assert helpers.provenance_ips(bans, "bunkerweb") == {"1.1.1.1"}

    def test_malformed_entries_are_ignored(self):
        assert helpers.provenance_ips(["nope", {"source": "bunkerweb"}, {"ip": "  ", "source": "bunkerweb"}], "bunkerweb") == set()

    def test_an_empty_ledger_claims_nothing(self):
        assert helpers.provenance_ips([], "bunkerweb") == set()


class TestCanonicalAddress:
    def test_a_plain_address_passes_through(self):
        assert helpers.canonical_address("203.0.113.5") == "203.0.113.5"
        assert helpers.canonical_address(" 203.0.113.5 ") == "203.0.113.5"

    def test_ipv6_is_lowercased_and_compressed(self):
        # SysWarden stores the canonical form. Without this the next pass would see the
        # address as both "to add" and "to remove" and oscillate forever.
        assert helpers.canonical_address("2001:DB8::1") == "2001:db8::1"

    def test_a_network_is_masked_to_its_prefix(self):
        assert helpers.canonical_address("203.0.113.5/24") == "203.0.113.0/24"

    @pytest.mark.parametrize("value", ("::ffff:203.0.113.5", "fe80::1%eth0", "not-an-ip", "", "   ", "203.0.113.5.6"))
    def test_what_syswarden_would_refuse_is_dropped(self, value):
        # A single refused entry makes SysWarden reject the whole batch of up to 500
        # bans, so these must never reach the wire.
        assert helpers.canonical_address(value) == ""


class TestNormalizeBanExpiry:
    def test_a_redis_key_without_expiry_is_permanent(self):
        # Redis answers -1 for a key with no TTL.
        assert helpers.normalize_ban({"ip": "1.1.1.1", "exp": -1})["ttl"] is None

    @pytest.mark.parametrize("exp", (0, -2))
    def test_an_expired_or_vanished_ban_is_dropped(self, exp):
        # -2 is Redis for "the key went away between the scan and the read", 0 is the
        # instance API for an expired ban. Pushing either would ban an address BunkerWeb
        # no longer bans — permanently so on a peer without lifetimes.
        assert helpers.normalize_ban({"ip": "1.1.1.1", "exp": exp}) is None

    def test_a_permanent_ban_ignores_its_expiry_field(self):
        assert helpers.normalize_ban({"ip": "1.1.1.1", "exp": 0, "permanent": True})["ttl"] is None

    def test_an_address_syswarden_would_refuse_is_dropped(self):
        assert helpers.normalize_ban({"ip": "::ffff:203.0.113.5"}) is None

    def test_the_address_is_canonicalized(self):
        assert helpers.normalize_ban({"ip": "2001:DB8::1"})["ip"] == "2001:db8::1"


class TestWireConstants:
    def test_the_limits_match_the_ones_syswarden_enforces(self):
        # Pinned to literals on purpose: every other assertion in this file reads these
        # from the module, so a wrong value would agree with itself and still be refused
        # on the wire. Each mirrors a symbol in SysWarden's ha_api.go / firewall package.
        assert (
            helpers.SYSWARDEN_DEFAULT_PORT,  # [integrations.ha] peer_port default
            helpers.SYSWARDEN_MIN_TTL,  # firewall.MinimumBanTTL, 1 second
            helpers.SYSWARDEN_MAX_TTL,  # firewall.MaximumBanTTL, 30 days
            helpers.SYSWARDEN_MAX_REASON_BYTES,  # maxHAReasonBytes
            helpers.SYSWARDEN_MAX_SOURCE_BYTES,  # maxHASourceBytes
            helpers.SYSWARDEN_MAX_BANS_PER_REQUEST,  # maxHABansPerRequest
        ) == (62026, 1, 2592000, 512, 64, 500)


class TestCanonicalSet:
    def test_a_peer_spelling_is_brought_to_our_own(self):
        # Canonicalizing only our side would move the oscillation rather than fix it.
        assert helpers.canonical_set(["2001:DB8::1", "203.0.113.5"]) == {"2001:db8::1", "203.0.113.5"}

    def test_unparsable_entries_are_dropped(self):
        assert helpers.canonical_set(["nope", "", "203.0.113.5"]) == {"203.0.113.5"}


class TestProvenanceCanonicalization:
    def test_a_ledger_entry_matches_the_key_select_bans_produced(self):
        ours = helpers.provenance_ips([{"ip": "2001:DB8::1", "source": "cluster-a"}], "cluster-a")
        banned = set(helpers.select_bans([{"ip": "2001:db8::1"}]))
        # Same address, two spellings. If these differ, every pass pushes and deletes it.
        assert ours == banned
        assert helpers.plan_peer(banned, set(), ours, set(), True) == ([], [], [])
