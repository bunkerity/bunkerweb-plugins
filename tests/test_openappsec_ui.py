"""Pure unit tests for the open-appsec UI data and policy helpers."""

import importlib.util
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_PATH = REPO_ROOT / "openappsec" / "ui" / "openappsec_ui.py"
TEMPLATE_PATH = REPO_ROOT / "openappsec" / "ui" / "template.html"
SPEC = importlib.util.spec_from_file_location("openappsec_ui", UI_PATH)
openappsec_ui = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(openappsec_ui)


def _load_actions():
    actions_path = REPO_ROOT / "openappsec" / "ui" / "actions.py"
    actions_spec = importlib.util.spec_from_file_location("openappsec_actions_test", actions_path)
    actions = importlib.util.module_from_spec(actions_spec)
    actions_spec.loader.exec_module(actions)
    return actions


def _event(event_id, event_time, *, host="www.example.com", action="Prevent", incident="SQL injection", request_id="req-1"):
    return {
        "eventTime": event_time,
        "eventName": "Web Request",
        "eventSource": {"agentId": "agent-1", "issuingEngineVersion": "1.1.36-open-source"},
        "eventData": {
            "eventReferenceId": event_id,
            "sourceIP": "198.51.100.9",
            "httpSourceId": "198.51.100.7",
            "httpHostName": host,
            "httpMethod": "GET",
            "httpUriPath": "/blocked",
            "httpUriQuery": "id=/etc/passwd",
            "httpRequestHeaders": f"[host: {host}; x-request-id: {request_id};]",
            "securityAction": action,
            "waapOverride": "None",
            "waapIncidentType": incident,
            "matchedLocation": "url parameter",
            "matchedParameter": "id",
            "matchedSample": "x" * 130,
            "eventConfidence": "Very High",
            "waapFinalScore": 794,
            "practiceName": "local_policy/webapp-default-practice",
        },
    }


def _write_event_log(path, *objects):
    path.write_text("\n".join(json.dumps(item) for item in objects) + "\n", encoding="utf-8")


def _policy():
    return {
        "policies": {
            "default": {
                "mode": "prevent-learn",
                "triggers": ["default-trigger"],
                "practices": ["default-practice"],
                "custom-response": "default-response",
                "exceptions": [],
            },
            "specific-rules": [
                {
                    "host": "www.example.com",
                    "mode": "detect",
                    "triggers": [],
                    "practices": [],
                    "custom-response": "",
                    "exceptions": [],
                }
            ],
        },
        "exceptions": [],
    }


class _UIUtils:
    def __init__(self, metrics=None, canary=None):
        self.metrics = metrics or {}
        self.canary = canary or []
        self.ban_calls = []

    def get_ping(self, plugin):
        assert plugin == "openappsec"
        return {"status": "up"}

    def get_metrics(self, plugin):
        assert plugin == "openappsec"
        return self.metrics

    def get_data(self, endpoint):
        assert endpoint == "openappsec/canary"
        return self.canary

    def ban(self, ip, exp, reason, service, ban_scope):
        self.ban_calls.append((ip, exp, reason, service, ban_scope))
        return ""


class _DB:
    def __init__(self, global_config, full_config=None):
        self.global_config = global_config
        self.full_config = full_config if full_config is not None else global_config

    def get_config(self, global_only=False):
        return self.global_config if global_only else self.full_config


class _BrokenDB:
    def get_config(self, global_only=False):
        raise RuntimeError("database unavailable")


def test_read_events_projects_rotated_logs_and_filters_non_requests_and_canary(tmp_path):
    first = _event("event-1", "2026-09-22T09:44:53.729", request_id="req-1")
    second = _event("event-2", "2026-09-22T09:45:53.729", action="Detect", request_id="req-2")
    canary = _event("event-canary", "2026-09-22T09:46:53.729", host="canary.openappsec.bunkerweb.invalid")
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log1", first, {"eventName": "Policy Loaded"}, canary)
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log2.1", {"broken": True}, second)

    events, error = openappsec_ui.read_events(str(tmp_path))

    assert error is None
    assert [event["event_id"] for event in events] == ["event-2", "event-1"]
    assert events[0]["ip"] == "198.51.100.7"
    assert events[0]["request_id"] == "req-2"
    assert events[0]["url"] == "/blocked?id=/etc/passwd"
    assert len(events[0]["sample"]) == 120
    assert events[0]["agent_version"] == "1.1.36-open-source"


def test_pre_render_adds_openappsec_cards_data_and_request_id(tmp_path):
    event = _event("event-1", datetime.now(timezone.utc).isoformat())
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log1", event)
    policy_path = tmp_path / "policy.json"
    policy = _policy()
    policy["exceptions"] = [{"name": "bw-exc-1", "action": "skip", "url": ["/public"]}]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    metrics = {
        "counter_accepted": 7,
        "counter_denied": 2,
        "counter_skipped": 1,
        "counter_errors": 0,
        "table_denies": [
            {
                "date": 1727000000,
                "ip": "198.51.100.7",
                "server_name": "www.example.com",
                "method": "GET",
                "url": "/?id=/etc/passwd",
                "judge_status": "deny",
                "event_id": "event-1",
                "request_id": "req-1",
            }
        ],
    }
    utils = _UIUtils(metrics, [{"www.example.com": {"state": "enforcing", "latency_ms": 4, "checked_at": "2026-09-22T09:44:00"}}])
    db = _DB(
        {
            "OPENAPPSEC_EVENTS_DIR": str(tmp_path),
            "OPENAPPSEC_POLICY_PATH": str(policy_path),
            "SERVER_NAME": "www www2",
        },
        {
            "SERVER_NAME": "www www2",
            "www_SERVER_NAME": "www.example.com",
            "www2_SERVER_NAME": "www2.example.com",
        },
    )

    ret = _load_actions().pre_render(bw_instances_utils=utils, db=db)

    assert ret["ping_canary"]["value"] == "up"
    assert ret["top_recent_denies"]["data"]["request_id"] == ["req-1"]
    assert ret["top_recent_denies"]["types"] == {"0": "date"}
    assert ret["list_top_incidents"]["types"] == {"1": "num"}
    assert ret["data"]["events"][0]["event_id"] == "event-1"
    assert ret["data"]["exceptions"][0]["name"] == "bw-exc-1"
    assert [item["host"] for item in ret["data"]["services"]] == ["www.example.com", "www2.example.com"]
    assert [item["service"] for item in ret["data"]["services"]] == ["www", "www2"]
    assert ret["data"]["known_services"] == ["www", "www2"]
    assert ret["data"]["service_ids"] == ["www", "www2"]
    assert ret["data"]["hostnames"] == ["www.example.com", "www2.example.com"]
    assert ret["data"]["outcomes"]["denied"] == {"count": 2, "pct": 20.0}
    assert ret["data"]["top_paths"] == [{"path": "/blocked", "count": 1, "pct": 100.0}]
    assert ret["data"]["top_params"] == [{"param": "id", "location": "url parameter", "count": 1}]
    assert ret["data"]["url_path_logging"] is True
    assert ret["data"]["denies_recent"][0]["request_id"] == "req-1"
    assert ret["data"]["policy_editable"]["editable"] is True
    assert isinstance(ret["data"]["policy_mtime"], float)
    assert ret["info_policy"]["default_mode"] == "prevent-learn"
    assert ret["info_agent"]["events_24h"] == 1


def test_openappsec_ban_validates_and_forwards_only_safe_values(tmp_path):
    actions = _load_actions()
    utils = _UIUtils()
    db = _DB(
        {"OPENAPPSEC_POLICY_PATH": str(tmp_path / "policy.json"), "SERVER_NAME": "www"},
        {"SERVER_NAME": "www", "www_SERVER_NAME": "www.example.com"},
    )

    result = actions.openappsec(
        bw_instances_utils=utils,
        db=db,
        data={
            "action": "ban",
            "ip": "203.0.113.9",
            "exp": 3600,
            "event_id": "dead-beef",
            "service": "www",
            "ban_scope": "service",
        },
    )

    assert result["status"] == "ok"
    assert utils.ban_calls == [("203.0.113.9", 3600, "open-appsec event dead-beef", "www", "service")]

    result = actions.openappsec(
        bw_instances_utils=utils,
        db=db,
        data={"action": "ban", "ip": "not-an-ip", "exp": 1, "reason": "leak me"},
    )
    assert result["status"] == "ko"
    assert "not-an-ip" not in result["message"]
    assert "leak me" not in result["message"]


def test_policy_mutation_rejects_a_stale_policy_mtime(tmp_path):
    actions = _load_actions()
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
    db = _DB(
        {"OPENAPPSEC_POLICY_PATH": str(policy_path), "SERVER_NAME": "www"},
        {"SERVER_NAME": "www", "www_SERVER_NAME": "www.example.com"},
    )

    result = actions.openappsec(
        bw_instances_utils=_UIUtils(),
        db=db,
        data={"action": "set_default_mode", "mode": "detect", "policy_mtime": os.path.getmtime(policy_path) - 1},
    )

    assert result == {"status": "ko", "message": "policy changed since the page was loaded, reload and retry"}


@pytest.mark.parametrize("policy_mtime", [None, "not-a-number"])
def test_policy_mutation_rejects_missing_or_invalid_policy_mtime(tmp_path, policy_mtime):
    actions = _load_actions()
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
    db = _DB(
        {"OPENAPPSEC_POLICY_PATH": str(policy_path), "SERVER_NAME": "www"},
        {"SERVER_NAME": "www", "www_SERVER_NAME": "www.example.com"},
    )

    result = actions.openappsec(
        bw_instances_utils=_UIUtils(),
        db=db,
        data={"action": "set_default_mode", "mode": "detect", "policy_mtime": policy_mtime},
    )

    assert result == {"status": "ko", "message": "policy changed since the page was loaded, reload and retry"}


def test_policy_mutation_refuses_when_configuration_lookup_raises(tmp_path):
    actions = _load_actions()

    result = actions.openappsec(
        bw_instances_utils=_UIUtils(),
        db=_BrokenDB(),
        data={"action": "set_default_mode", "mode": "detect", "policy_mtime": 1.0},
    )

    assert result == {"status": "ko", "message": "configuration unavailable"}


def test_service_mode_action_rejects_a_host_outside_configured_services(tmp_path):
    actions = _load_actions()
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
    db = _DB(
        {"OPENAPPSEC_POLICY_PATH": str(policy_path), "SERVER_NAME": "www"},
        {"SERVER_NAME": "www", "www_SERVER_NAME": "www.example.com"},
    )

    result = actions.openappsec(
        bw_instances_utils=_UIUtils(),
        db=db,
        data={
            "action": "set_service_mode",
            "host": "valid-looking.example.com",
            "mode": "prevent",
            "policy_mtime": os.path.getmtime(policy_path),
        },
    )

    assert result == {"status": "ko", "message": "service host is not configured"}


def test_read_events_reports_missing_directory_without_leaking_a_path(tmp_path):
    missing = tmp_path / "missing"

    events, error = openappsec_ui.read_events(str(missing))

    assert events == []
    assert error == "events directory not found"
    assert str(missing) not in error


def test_read_events_drops_a_torn_tail_line_and_keeps_following_events(tmp_path):
    first = _event("event-1", "2026-09-22T09:44:53.729")
    second = _event("event-2", "2026-09-22T09:45:53.729")
    torn = b'{"eventName":"Web Request","eventData":{"broken":"' + b"x" * (openappsec_ui.EVENT_TAIL_BYTES + 1024)
    log = tmp_path / "cp-nano-http-transaction-handler.log"
    log.write_bytes(b"padding\n" + torn + b"\n" + json.dumps(first).encode() + b"\n" + json.dumps(second).encode() + b"\n")

    events, error = openappsec_ui.read_events(str(tmp_path))

    assert error is None
    assert [event["event_id"] for event in events] == ["event-2", "event-1"]


def test_read_events_filters_healthcheck_and_openappsec_user_agent_noise(tmp_path):
    healthcheck = _event("healthcheck", "2026-09-22T09:44:53.729", host="healthcheck.invalid")
    user_agent = _event("user-agent", "2026-09-22T09:45:53.729")
    user_agent["eventData"]["httpRequestHeaders"] = "[user-agent: bunkerweb-openappsec-probe; host: www.example.com;]"
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log", healthcheck, user_agent, _event("ordinary", "2026-09-22T09:44:53.729"))

    events, error = openappsec_ui.read_events(str(tmp_path), skip_hosts=("another.invalid",))

    assert error is None
    assert [event["event_id"] for event in events] == ["ordinary"]


def test_template_renders_error_and_scalar_exception_conditions():
    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    assert 'id="openappsec-alert"' in template
    assert "cards.get('error')" in template
    assert "values is string" in template
    assert 'values|join(", ")' in template


def test_template_uses_one_shared_ban_modal_and_service_ids():
    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    assert 'id="openappsec-ban-modal"' in template
    assert 'data-bs-target="#openappsec-ban-modal"' in template
    assert 'data-target="openappsec-ban-' not in template
    assert template.count('<form data-form="ban"') == 1
    assert 'ui_data.get("known_services", [])' in template
    assert template.count("policy_mtime: policyMtime") == 4


def test_agent_summary_counts_recent_actions_and_top_incidents():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = [
        {"time": now.isoformat(), "action": "Prevent", "incident": "SQL injection", "agent_version": "1.1", "agent_id": "a1"},
        {"time": (now - timedelta(hours=1)).isoformat(), "action": "Detect", "incident": "SQL injection", "agent_version": "1.1", "agent_id": "a1"},
        {"time": (now - timedelta(hours=2)).isoformat(), "action": "Prevent", "incident": "Path traversal", "agent_version": "1.1", "agent_id": "a1"},
        {"time": (now + timedelta(seconds=1)).isoformat(), "action": "Prevent", "agent_version": "future"},
        {"time": (now - timedelta(days=2)).isoformat(), "action": "Prevent", "incident": "Old event", "agent_version": "old", "agent_id": "old"},
    ]

    summary = openappsec_ui.agent_summary(events, now)

    assert summary["version"] == "1.1"
    assert summary["agent_id"] == "a1"
    assert summary["last_event"] == now.isoformat()
    assert summary["events_24h"] == 3
    assert summary["prevented_24h"] == 2
    assert summary["detected_24h"] == 1
    assert summary["top_incidents"][:2] == [("SQL injection", 2), ("Path traversal", 1)]


def test_list_exceptions_preserves_scalar_condition_values():
    result = openappsec_ui.list_exceptions({"exceptions": [{"name": "scalar", "action": "skip", "sourceIp": "1.2.3.4"}]})

    assert result == [{"name": "scalar", "action": "skip", "conditions": {"sourceIp": "1.2.3.4"}}]


def test_load_policy_accepts_json_and_explains_yaml_and_missing(tmp_path):
    json_path = tmp_path / "policy.json"
    json_path.write_text('{"policies": {"default": {"mode": "prevent"}}}', encoding="utf-8")
    yaml_path = tmp_path / "policy.yaml"
    yaml_path.write_text("policies:\n  default:\n    mode: prevent\n", encoding="utf-8")

    policy, error = openappsec_ui.load_policy(str(json_path))
    assert policy["policies"]["default"]["mode"] == "prevent"
    assert error is None

    policy, error = openappsec_ui.load_policy(str(yaml_path))
    assert policy is None
    assert error.startswith("policy is not in JSON syntax")
    assert str(yaml_path) not in error

    policy, error = openappsec_ui.load_policy(str(tmp_path / "absent.json"))
    assert policy is None
    assert error == "policy file not found"


def test_save_policy_keeps_previous_content_in_bak_and_replaces_atomically(tmp_path):
    path = tmp_path / "local_policy.yaml"
    path.write_text('{"old": true}\n', encoding="utf-8")

    openappsec_ui.save_policy(str(path), {"new": [1, 2]})

    assert json.loads(path.read_text(encoding="utf-8")) == {"new": [1, 2]}
    assert json.loads((tmp_path / "local_policy.yaml.bak").read_text(encoding="utf-8")) == {"old": True}
    assert not (tmp_path / "local_policy.yaml.tmp").exists()


def test_save_policy_preserves_original_file_mode(tmp_path):
    path = tmp_path / "local_policy.yaml"
    path.write_text('{"old": true}\n', encoding="utf-8")
    path.chmod(0o644)

    openappsec_ui.save_policy(str(path), {"new": True})

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644


def test_save_policy_rejects_a_symlink_target_outside_the_configured_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "local_policy.yaml"
    link = tmp_path / "local_policy.yaml"
    link.symlink_to(target)

    with pytest.raises(ValueError):
        openappsec_ui.save_policy(str(link), {"new": True})


def test_add_exception_validates_input_and_updates_all_policy_references():
    policy = _policy()

    name = openappsec_ui.add_exception(policy, "skip", {"sourceIp": ["203.0.113.9/32"], "url": ["/public"]}, "allow-public")

    assert name == "allow-public"
    assert policy["exceptions"] == [{"name": "allow-public", "action": "skip", "sourceIp": ["203.0.113.9/32"], "url": ["/public"]}]
    assert policy["policies"]["default"]["exceptions"] == ["allow-public"]
    assert policy["policies"]["specific-rules"][0]["exceptions"] == ["allow-public"]


@pytest.mark.parametrize(
    "action, conditions, name",
    [
        ("skip", {"sourceIp": ["not-an-ip"]}, None),
        ("skip", {"unknown": ["x"]}, None),
        ("skip", {}, None),
        ("skip", {"url": [""]}, None),
        ("skip", {"url": ["/x"]}, "bad name"),
    ],
)
def test_add_exception_rejects_invalid_input(action, conditions, name):
    with pytest.raises(ValueError):
        openappsec_ui.add_exception(_policy(), action, conditions, name)


def test_add_exception_rejects_duplicate_names():
    policy = _policy()
    openappsec_ui.add_exception(policy, "skip", {"url": ["/x"]}, "duplicate")

    with pytest.raises(ValueError):
        openappsec_ui.add_exception(policy, "drop", {"url": ["/y"]}, "duplicate")


def test_remove_exception_removes_definition_and_every_reference():
    policy = _policy()
    openappsec_ui.add_exception(policy, "skip", {"url": ["/x"]}, "remove-me")

    openappsec_ui.remove_exception(policy, "remove-me")

    assert policy["exceptions"] == []
    assert policy["policies"]["default"]["exceptions"] == []
    assert policy["policies"]["specific-rules"][0]["exceptions"] == []


def test_remove_exception_returns_cleanly_for_non_dict_policy():
    assert openappsec_ui.remove_exception(None, "missing") is None


def test_service_modes_and_inherit_and_upsert_copy_default_lists():
    policy = _policy()
    assert openappsec_ui.service_modes(policy, ["www.example.com", "new.example.com"]) == [
        {"host": "www.example.com", "mode": "detect", "effective_mode": "detect"},
        {"host": "new.example.com", "mode": "inherit", "effective_mode": "prevent-learn"},
    ]

    openappsec_ui.set_service_mode(policy, "www.example.com", "inherit")
    assert policy["policies"]["specific-rules"] == []

    openappsec_ui.set_service_mode(policy, "new.example.com", "prevent")
    rule = policy["policies"]["specific-rules"][0]
    assert rule["host"] == "new.example.com"
    assert rule["mode"] == "prevent"
    assert rule["triggers"] == ["default-trigger"]
    assert rule["practices"] == ["default-practice"]
    assert rule["triggers"] is not policy["policies"]["default"]["triggers"]
    rule["triggers"].append("local-trigger")
    assert policy["policies"]["default"]["triggers"] == ["default-trigger"]


def test_service_modes_match_port_rules_and_inherit_removes_duplicates():
    policy = _policy()
    policy["policies"]["specific-rules"] = [
        {"host": "www.example.com:8080", "mode": "detect", "triggers": [], "practices": [], "exceptions": []},
        {"host": "www.example.com:8080", "mode": "prevent", "triggers": [], "practices": [], "exceptions": []},
    ]

    assert openappsec_ui.service_modes(policy, ["www.example.com"]) == [{"host": "www.example.com", "mode": "detect", "effective_mode": "detect"}]

    openappsec_ui.set_service_mode(policy, "www.example.com", "prevent")
    assert len(policy["policies"]["specific-rules"]) == 1
    assert policy["policies"]["specific-rules"][0]["host"] == "www.example.com:8080"
    assert policy["policies"]["specific-rules"][0]["mode"] == "prevent"

    openappsec_ui.set_service_mode(policy, "www.example.com", "inherit")
    assert policy["policies"]["specific-rules"] == []


def test_service_mode_rejects_invalid_mode_and_host():
    with pytest.raises(ValueError):
        openappsec_ui.set_service_mode(_policy(), "www.example.com:bad", "prevent")
    with pytest.raises(ValueError):
        openappsec_ui.set_service_mode(_policy(), "www.example.com", "unknown")


def test_set_default_mode_rejects_inherit_and_updates_default():
    policy = _policy()
    openappsec_ui.set_default_mode(policy, "detect-learn")
    assert policy["policies"]["default"]["mode"] == "detect-learn"

    with pytest.raises(ValueError):
        openappsec_ui.set_default_mode(policy, "inherit")


def test_outcome_shares():
    assert openappsec_ui.outcome_shares({}) == {"total": 0, **{key: {"count": 0, "pct": 0.0} for key in ("accepted", "denied", "skipped", "errors")}}
    shares = openappsec_ui.outcome_shares({"accepted": 2, "denied": 1, "skipped": 0, "errors": 0})
    assert shares["total"] == 3
    assert shares["accepted"] == {"count": 2, "pct": 66.7}
    assert shares["denied"] == {"count": 1, "pct": 33.3}


def test_hour_buckets_and_heatmap_window():
    now = datetime(2026, 9, 22, 11, 30, tzinfo=timezone.utc)
    labels = openappsec_ui.hour_buckets(now)
    assert labels == [f"{hour:02}:30" for hour in list(range(11, 24)) + list(range(11))]
    events = [
        {"host": host, "time": time, "action": action}
        for host, time, action in [
            ("known", "2026-09-21T12:00:00.000", "Prevent"),
            ("unknown", "2026-09-22T11:30:00.000", "Detect"),
            ("known", "2026-09-21T11:30:00.000", "Prevent"),
            ("known", "2026-09-21T11:29:59.999", "Prevent"),
            ("known", "2026-09-22T11:30:00.001", "Prevent"),
            ("unknown", "bad", "Detect"),
        ]
    ]
    result = openappsec_ui.heatmap(events, ["empty", "known"], now)
    assert [row["host"] for row in result["rows"]] == ["known", "unknown"]
    assert [row["total"] for row in result["rows"]] == [2, 1]
    assert result["rows"][0]["cells"][0] == 2
    assert result["hidden_configured"] == 1
    assert result["columns"] == [2] + [0] * 22 + [1]
    assert result["max"] == 2
    assert result["prevent"] == 2
    assert result["detect"] == 1
    assert openappsec_ui.agent_summary(events, now)["events_24h"] == sum(result["columns"]) == 3
    assert openappsec_ui.heatmap([], [], now)["max"] == 0


def test_top_paths_and_params():
    events = [
        {"path": "/b", "param": "id", "location": "query"},
        {"path": "/a", "param": "id", "location": "body"},
        {"path": "/b", "param": "id", "location": "query"},
        {"path": ""},
    ]
    assert openappsec_ui.top_paths(events, 1) == [{"path": "/b", "count": 2, "pct": 66.7}]
    assert openappsec_ui.top_params(events, 1) == [{"param": "id", "location": "query", "count": 2}]
    assert openappsec_ui.top_paths([]) == openappsec_ui.top_params([]) == []


@pytest.mark.parametrize("path, uri, expected", [("/explicit", "/fallback?q=1", "/explicit"), (None, "/fallback?q=1", "/fallback"), (None, None, "")])
def test_read_events_projects_path_query(tmp_path, path, uri, expected):
    event = _event("a", "2026-09-22T11:00:00.000")
    event["eventData"].pop("httpUriPath")
    if path is not None:
        event["eventData"]["httpUriPath"] = path
    if uri is not None:
        event["eventData"]["httpUri"] = uri
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log", event)
    events, error = openappsec_ui.read_events(str(tmp_path))
    assert error is None
    assert events[0]["path"] == expected
    assert events[0]["query"] == "id=/etc/passwd"


def test_heatmap_bounds_unknown_hosts_and_preserves_totals():
    now = datetime(2026, 9, 22, 11, 30, tzinfo=timezone.utc)
    events = [{"host": f"unknown-{i:02}", "time": now.isoformat(), "action": "Detect"} for i in range(50)]
    events += [{"host": "unknown-49", "time": now.isoformat(), "action": "Prevent"}] * 3
    result = openappsec_ui.heatmap(events, ["configured"], now)
    assert result["hidden_configured"] == 1
    assert len(result["rows"]) == 13
    assert [row["host"] for row in result["rows"]] == ["unknown-49", *[f"unknown-{i:02}" for i in range(11)], "38 other hosts"]
    assert result["rows"][-1]["total"] == 38
    assert sum(result["columns"]) == sum(row["total"] for row in result["rows"]) == 53
    assert result["prevent"] == 3
    assert result["detect"] == 50


def test_top_rankings_break_ties_lexically():
    events = [
        {"path": path, "param": param, "location": location} for path, param, location in [("/b", "z", "query"), ("/a", "a", "query"), ("/c", "a", "body")]
    ]
    assert [item["path"] for item in openappsec_ui.top_paths(events)] == ["/a", "/b", "/c"]
    assert [(item["param"], item["location"]) for item in openappsec_ui.top_params(events)] == [("a", "body"), ("a", "query"), ("z", "query")]


@pytest.mark.parametrize("with_path, expected", [(0, False), (1, False), (2, True), (4, True)])
def test_pre_render_path_coverage(tmp_path, with_path, expected):
    events = [_event(str(i), datetime.now(timezone.utc).isoformat()) for i in range(4)]
    for event in events[with_path:]:
        event["eventData"].pop("httpUriPath")
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log", *events)
    ret = _load_actions().pre_render(bw_instances_utils=_UIUtils(), db=_DB({"OPENAPPSEC_EVENTS_DIR": str(tmp_path)}))
    assert ret["data"]["url_path_logging"] is expected
    assert ret["data"]["path_event_count"] == with_path
    assert ret["data"]["loaded_event_count"] == 4


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_pre_render_marks_a_read_only_policy_as_not_editable(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
    policy_path.chmod(0o444)
    ret = _load_actions().pre_render(bw_instances_utils=_UIUtils(), db=_DB({"OPENAPPSEC_POLICY_PATH": str(policy_path)}))
    assert ret["data"]["policy_editable"]["editable"] is False
    assert "not writable" in ret["data"]["policy_editable"]["reason"]


def test_render_smoke_100_events(tmp_path):
    jinja2 = pytest.importorskip("jinja2")
    now = datetime.now(timezone.utc).isoformat()
    events = [_event(f"event-{i}", now, host="www.example.com" if i % 2 else "api.example.com") for i in range(100)]
    events[0]["eventData"]["matchedSample"] = '<script>alert("sample")</script>'
    _write_event_log(tmp_path / "cp-nano-http-transaction-handler.log", *events)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy()))
    ret = _load_actions().pre_render(
        bw_instances_utils=_UIUtils(),
        db=_DB(
            {"OPENAPPSEC_EVENTS_DIR": str(tmp_path), "OPENAPPSEC_POLICY_PATH": str(policy_path), "SERVER_NAME": "www"},
            {"www_SERVER_NAME": "www.example.com api.example.com"},
        ),
    )
    template = TEMPLATE_PATH.read_text()
    rendered = (
        jinja2.Environment(autoescape=True).from_string(template).render(pre_render={"data": ret}, csrf_token=lambda: "test-csrf", script_nonce="test-nonce")
    )
    for tab in ("overview", "events", "policy"):
        assert f'id="oas-pane-{tab}"' in rendered
    assert rendered.count('<script nonce="test-nonce">') == rendered.count("<script") == 1
    assert "<script>alert" not in rendered
    assert len(ret["data"]["heatmap"]["rows"]) == 2
    size = len(rendered.encode())
    print(f"render smoke: {size} bytes, 100 events, 2 heatmap rows")
    assert size < 130_000  # Two-line timestamps and stress layout add markup to every event.
    assert template.count("policy_mtime: policyMtime") == 4
    assert "Mixed modes" in rendered
    assert str(policy_path) in rendered


def test_heatmap_caps_active_hosts_and_hides_idle_configured():
    now = datetime(2026, 9, 22, 11, 30, tzinfo=timezone.utc)
    configured = [f"configured-{i}" for i in range(40)]
    events = [{"host": f"unknown-{i}", "time": now.isoformat()} for i in range(50)]
    result = openappsec_ui.heatmap(events, configured, now)
    assert result["hidden_configured"] == 40
    assert not any(row["host"].startswith("configured") for row in result["rows"])
    for host in configured[:2]:
        events.append({"host": host, "time": now.isoformat()})
    result = openappsec_ui.heatmap(events, configured, now)
    assert len(result["rows"]) == 13
    assert [row["host"] for row in result["rows"][:2]] == configured[:2]
    assert result["rows"][-1]["host"] == "40 other hosts"
    for host in configured[2:]:
        events.append({"host": host, "time": now.isoformat()})
    result = openappsec_ui.heatmap(events, configured, now)
    assert [row["host"] for row in result["rows"][:12]] == configured[:12]
    assert result["rows"][-1]["host"] == "78 other hosts"
    assert sum(row["total"] for row in result["rows"]) == sum(result["columns"]) == 90


@pytest.mark.parametrize("service_count", [8, 9])
def test_render_stress_policy_and_idle_hosts(service_count):
    jinja2 = pytest.importorskip("jinja2")
    data = {
        "known_services": [f"svc{i}" for i in range(service_count)],
        "services": [{"service": "svc0", "host": "alias.example.com", "effective_mode": "detect", "mode": "inherit"}],
        "heatmap": {"hidden_configured": 40},
        "exceptions": [
            {
                "name": "long-exception",
                "action": "skip",
                "conditions": {"sourceIp": ["one", "two", "three", "four"], "url": "/scalar", "hostName": [], "paramName": ["id", "q"]},
            }
        ],
        "top_paths": [{"path": "<path&value>", "count": 1, "pct": 100}],
    }
    rendered = (
        jinja2.Environment(autoescape=True)
        .from_string(TEMPLATE_PATH.read_text())
        .render(pre_render={"data": {"data": data}}, csrf_token=lambda: "test", script_nonce="test")
    )
    rendered = re.sub(r"\s+>", ">", rendered)
    assert ('id="oas-service-filter"' in rendered) is (service_count > 8)
    assert ('class="oas-service-list"' in rendered) is (service_count > 8)
    assert 'data-service-hostnames="alias.example.com"' in rendered
    assert "40 configured hostnames had no events" in rendered
    assert 'title="one, two, three, four"' in rendered
    assert "+1 more" in rendered
    assert 'title="four"' not in rendered
    assert 'title="/scalar"' in rendered and ">/scalar</span" in rendered
    assert "hostName:" not in rendered
    assert "paramName: id, q" in " ".join(rendered.split())
    assert 'title="&lt;path&amp;value&gt;"' in rendered
