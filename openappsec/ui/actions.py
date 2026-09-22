import importlib.util
import ipaddress
import math
import os
import re
from datetime import datetime, timezone
from logging import getLogger
from traceback import format_exc

try:
    from openappsec_ui import (
        add_exception,
        agent_summary,
        top_params,
        top_paths,
        outcome_shares,
        heatmap,
        list_exceptions,
        load_policy,
        read_events,
        remove_exception,
        save_policy,
        service_modes,
        set_default_mode,
        set_service_mode,
    )
except ModuleNotFoundError:
    _ui_spec = importlib.util.spec_from_file_location("openappsec_ui", os.path.join(os.path.dirname(__file__), "openappsec_ui.py"))
    if _ui_spec is None or _ui_spec.loader is None:
        raise
    _ui_module = importlib.util.module_from_spec(_ui_spec)
    _ui_spec.loader.exec_module(_ui_module)
    add_exception = _ui_module.add_exception
    heatmap = _ui_module.heatmap
    outcome_shares = _ui_module.outcome_shares
    top_paths = _ui_module.top_paths
    top_params = _ui_module.top_params
    agent_summary = _ui_module.agent_summary
    list_exceptions = _ui_module.list_exceptions
    load_policy = _ui_module.load_policy
    read_events = _ui_module.read_events
    remove_exception = _ui_module.remove_exception
    save_policy = _ui_module.save_policy
    service_modes = _ui_module.service_modes
    set_default_mode = _ui_module.set_default_mode
    set_service_mode = _ui_module.set_service_mode


DEFAULT_EVENTS_DIR = "/var/log/openappsec"
DEFAULT_POLICY_PATH = "/etc/openappsec/local_policy.yaml"
EVENT_ID_RE = re.compile(r"^[0-9a-f-]{1,64}$")


def _iso(raw):
    """metrics.lua stores ctx.bw.start_time (epoch seconds); the top_ card wants ISO text."""
    try:
        return datetime.fromtimestamp(float(raw), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return str(raw or "")


def _denies(metrics):
    """Flatten every table_denies* metric (one per instance) into one list of events."""
    events = []
    for key, value in metrics.items():
        if key == "table_denies" or key.startswith("table_denies_"):
            if isinstance(value, list):
                events.extend(item for item in value if isinstance(item, dict))

    def timestamp(item):
        try:
            return float(item.get("date") or 0)
        except (TypeError, ValueError):
            return 0

    events.sort(key=timestamp, reverse=True)
    return events


def _configs(kwargs):
    global_config = {}
    full_config = {}
    db = kwargs.get("db")
    if db is None:
        return global_config, full_config, False
    try:
        configured = db.get_config(global_only=True)
        if isinstance(configured, dict):
            global_config = configured
    except BaseException:
        return {}, {}, True
    try:
        configured = db.get_config()
        if isinstance(configured, dict):
            full_config = configured
    except BaseException:
        return global_config, {}, True
    return global_config, full_config, False


def _service_ids(global_config):
    return list(dict.fromkeys(str(global_config.get("SERVER_NAME", "") or "").split()))


def _services(global_config, full_config):
    if not global_config or not full_config:
        return []
    services = []
    seen = set()
    for service in _service_ids(global_config):
        hosts = full_config.get(f"{service}_SERVER_NAME", "")
        if isinstance(hosts, str):
            for host in hosts.split():
                if (service, host) not in seen:
                    seen.add((service, host))
                    services.append({"service": service, "host": host})
    return services


def _canary(utils):
    payload = {}
    try:
        result = utils.get_data("openappsec/canary")
        items = result if isinstance(result, list) else [result]
        for item in items:
            if not isinstance(item, dict):
                continue
            for value in item.values():
                if isinstance(value, dict) and value.get("status") != "error":
                    payload = value
                    break
            if payload:
                break
    except BaseException:
        payload = {}
    state = str(payload.get("state", "unknown"))
    latency = payload.get("latency_ms", "-")
    checked = payload.get("checked_at", "-")
    if isinstance(checked, (int, float)):
        checked = _iso(checked)
    return state, latency, str(checked)


def _policy_view(path):
    policy, error = load_policy(path)
    if error:
        return {
            "policy": None,
            "editable": False,
            "reason": error,
            "exceptions": [],
            "services": [],
            "default_mode": "",
            "mtime": "",
            "policy_mtime": None,
        }
    policies = policy.get("policies", {}) if isinstance(policy, dict) else {}
    default = policies.get("default", {}) if isinstance(policies, dict) else {}
    rules = policies.get("specific-rules", []) if isinstance(policies, dict) else []
    try:
        policy_mtime = os.path.getmtime(path)
        mtime = _iso(policy_mtime)
    except (OSError, TypeError, ValueError):
        mtime = ""
        policy_mtime = None
    # save_policy() replaces the file atomically, so the directory must be writable too.
    writable = os.access(path, os.W_OK) and os.access(os.path.dirname(os.path.abspath(path)) or ".", os.W_OK)
    return {
        "policy": policy,
        "editable": writable,
        "reason": "" if writable else "policy file is not writable by the web UI",
        "exceptions": list_exceptions(policy),
        "services": [],
        "default_mode": str(default.get("mode", "") or ""),
        "host_rule_count": len(rules) if isinstance(rules, list) else 0,
        "mtime": mtime,
        "policy_mtime": policy_mtime,
    }


def pre_render(**kwargs):
    logger = getLogger("UI")
    ret = {
        "ping_status": {
            "title": "OPEN-APPSEC STATUS",
            "value": "error",
            "col-size": "col-12",
            "card-classes": "h-100",
        },
        "counter_accepted": {
            "value": 0,
            "title": "Requests",
            "subtitle": "Accepted",
            "subtitle_color": "success",
            "svg_color": "success",
            "col-size": "col-12 col-md-3",
        },
        "counter_denied": {
            "value": 0,
            "title": "Requests",
            "subtitle": "Denied",
            "subtitle_color": "danger",
            "svg_color": "danger",
            "col-size": "col-12 col-md-3",
        },
        "counter_skipped": {
            "value": 0,
            "title": "Requests",
            "subtitle": "Skipped (excluded)",
            "subtitle_color": "secondary",
            "svg_color": "secondary",
            "col-size": "col-12 col-md-3",
        },
        "counter_errors": {
            "value": 0,
            "title": "Judge errors",
            "subtitle": "Fail mode applied",
            "subtitle_color": "warning",
            "svg_color": "warning",
            "col-size": "col-12 col-md-3",
        },
        "top_recent_denies": {
            "data": {},
            "order": {"column": 0, "dir": "desc"},
            "types": {"0": "date"},
            "svg_color": "danger",
            "col-size": "col-12",
        },
    }
    try:
        ping_data = kwargs["bw_instances_utils"].get_ping("openappsec")
        ret["ping_status"]["value"] = ping_data["status"]
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get openappsec ping: {e}")
        # Never surface the raw exception (it may contain internal URLs / details).
        ret["error"] = "Could not retrieve the plugin status"

    denies_recent = []
    try:
        metrics = kwargs["bw_instances_utils"].get_metrics("openappsec")
        for name in ("accepted", "denied", "skipped", "errors"):
            ret[f"counter_{name}"]["value"] = int(metrics.get(f"counter_{name}", 0) or 0)
        data = {"date": [], "ip": [], "server_name": [], "method": [], "url": [], "judge_status": [], "event_id": [], "request_id": []}
        denies = _denies(metrics)
        denies_recent = [{**event, "date": _iso(event.get("date"))} for event in denies[:5]]
        for event in denies[:50]:
            data["date"].append(_iso(event.get("date")))
            for field in ("ip", "server_name", "method", "url", "judge_status", "event_id", "request_id"):
                data[field].append(str(event.get(field, "-") or "-"))
        ret["top_recent_denies"]["data"] = data
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get openappsec metrics: {e}")
        # The ping failure message, when there is one, is the more useful of the two.
        ret.setdefault("error", "Could not retrieve the plugin metrics")

    global_config, full_config, _ = _configs(kwargs)
    events_dir = global_config.get("OPENAPPSEC_EVENTS_DIR", DEFAULT_EVENTS_DIR)
    policy_path = global_config.get("OPENAPPSEC_POLICY_PATH", DEFAULT_POLICY_PATH)
    try:
        events, _ = read_events(events_dir, limit=200)
    except BaseException:
        events = []
    now = datetime.now(timezone.utc)
    summary = agent_summary(events, now)
    policy_view = _policy_view(policy_path)
    services = _services(global_config, full_config)
    hosts = [item["host"] for item in services]
    if policy_view["policy"] is not None:
        modes = service_modes(policy_view["policy"], hosts)
        policy_view["services"] = [{**service, **mode} for service, mode in zip(services, modes)]
    else:
        policy_view["services"] = [{**service, "mode": "inherit", "effective_mode": ""} for service in services]
    state, latency, checked = _canary(kwargs.get("bw_instances_utils"))

    ret["ping_canary"] = {
        "title": "ENFORCEMENT CANARY",
        "value": "up" if state == "enforcing" else "down",
        "subtitle": f"{state} · {latency} ms · checked {checked}",
        "col-size": "col-12 col-md-4",
        "card-classes": "h-100",
    }
    if policy_view["editable"]:
        policy_description = (
            f"{len(policy_view['exceptions'])} exceptions · {policy_view.get('host_rule_count', 0)} host rules · " f"modified {policy_view['mtime'] or '-'}"
        )
    else:
        policy_description = policy_view["reason"]
    ret["info_policy"] = {
        "title": "POLICY",
        "value": policy_view["default_mode"] if policy_view["editable"] else "read-only",
        "description": policy_description,
        "default_mode": policy_view["default_mode"],
        "exception_count": len(policy_view["exceptions"]),
        "host_rule_count": policy_view.get("host_rule_count", 0),
        "mtime": policy_view["mtime"],
        "reason": policy_view["reason"],
        "col-size": "col-12 col-md-4",
    }
    ret["info_agent"] = {
        "title": "AGENT",
        "value": summary["version"] or "unknown",
        "description": f"last {summary['last_event'] or '-'} · {summary['events_24h']} events / 24h",
        "version": summary["version"],
        "last_event": summary["last_event"],
        "events_24h": summary["events_24h"],
        "col-size": "col-12 col-md-4",
    }
    ret["list_top_incidents"] = {
        "data": {
            "incident": [item[0] for item in summary["top_incidents"]],
            "count": [item[1] for item in summary["top_incidents"]],
        },
        "types": {"1": "num"},
        "svg_color": "warning",
        "col-size": "col-12 col-md-6",
    }
    hostnames = list(dict.fromkeys(item["host"] for item in services))
    path_event_count = sum(bool(event.get("path")) for event in events)
    ret["data"] = {
        "outcomes": outcome_shares({name: ret[f"counter_{name}"]["value"] for name in ("accepted", "denied", "skipped", "errors")}),
        "heatmap": heatmap(events, hostnames, now),
        "top_paths": top_paths(events),
        "top_params": top_params(events),
        "hostnames": hostnames,
        "service_ids": _service_ids(global_config),
        "url_path_logging": bool(events) and path_event_count * 2 >= len(events),
        "path_event_count": path_event_count,
        "loaded_event_count": len(events),
        "policy_path": policy_path,
        "canary": {"state": state, "latency_ms": latency, "checked_at": checked},
        "denies_recent": denies_recent,
        "events": events[:100],
        "exceptions": policy_view["exceptions"],
        "services": policy_view["services"],
        "known_services": _service_ids(global_config),
        "policy_editable": {"editable": policy_view["editable"], "reason": policy_view["reason"]},
        "default_mode": policy_view["default_mode"],
        "policy_mtime": policy_view["policy_mtime"],
    }

    return ret


def openappsec(**kwargs):
    if not kwargs:
        return None
    data = kwargs.get("data")
    if not isinstance(data, dict):
        return {"status": "ko", "message": "invalid request data"}
    action = data.get("action")
    global_config, full_config, config_error = _configs(kwargs)
    policy_path = global_config.get("OPENAPPSEC_POLICY_PATH", DEFAULT_POLICY_PATH)
    known_services = _service_ids(global_config)
    known_hosts = {item["host"] for item in _services(global_config, full_config)}

    if action == "ban":
        ip = data.get("ip")
        try:
            if not isinstance(ip, str):
                raise ValueError
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "ko", "message": "invalid IP address"}
        exp = data.get("exp", 86400)
        try:
            if isinstance(exp, bool) or isinstance(exp, float) and not exp.is_integer():
                raise ValueError
            exp = int(exp)
        except (TypeError, ValueError, OverflowError):
            return {"status": "ko", "message": "invalid ban duration"}
        if not 60 <= exp <= 31536000:
            return {"status": "ko", "message": "ban duration must be between 60 and 31536000 seconds"}
        event_id = data.get("event_id", "")
        if event_id and (not isinstance(event_id, str) or not EVENT_ID_RE.fullmatch(event_id)):
            return {"status": "ko", "message": "invalid event id"}
        reason = data.get("reason")
        if reason is None:
            reason = f"open-appsec event {event_id or 'unknown'}"
        if not isinstance(reason, str) or not reason or len(reason) > 200:
            return {"status": "ko", "message": "invalid ban reason"}
        service = data.get("service", "")
        if not isinstance(service, str) or service not in known_services and service != "":
            return {"status": "ko", "message": "invalid service"}
        ban_scope = data.get("ban_scope", "global")
        if ban_scope not in ("global", "service"):
            return {"status": "ko", "message": "invalid ban scope"}
        if ban_scope == "service" and not service:
            return {"status": "ko", "message": "service is required for service scope"}
        try:
            failed = kwargs["bw_instances_utils"].ban(ip, exp, reason, service, ban_scope)
        except BaseException:
            return {"status": "ko", "message": "could not apply ban"}
        if failed:
            return {"status": "ko", "message": "could not apply ban on all instances"}
        return {"status": "ok", "message": "IP banned"}

    if action in ("add_exception", "remove_exception", "set_service_mode", "set_default_mode"):
        if config_error:
            return {"status": "ko", "message": "configuration unavailable"}
        try:
            expected_mtime = data["policy_mtime"]
            if isinstance(expected_mtime, bool):
                raise ValueError
            expected_mtime = float(expected_mtime)
            current_mtime = os.path.getmtime(policy_path)
            if not math.isfinite(expected_mtime) or abs(expected_mtime - current_mtime) > 1e-6:
                return {"status": "ko", "message": "policy changed since the page was loaded, reload and retry"}
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            return {"status": "ko", "message": "policy changed since the page was loaded, reload and retry"}
        policy, error = load_policy(policy_path)
        if error:
            return {"status": "ko", "message": error}
        try:
            if action == "add_exception":
                add_exception(policy, data.get("exception_action"), data.get("conditions"), data.get("name"))
                message = "exception added"
            elif action == "remove_exception":
                remove_exception(policy, data.get("name"))
                message = "exception removed"
            elif action == "set_service_mode":
                if data.get("host") not in known_hosts:
                    return {"status": "ko", "message": "service host is not configured"}
                set_service_mode(policy, data.get("host"), data.get("mode"))
                message = "service mode updated"
            else:
                set_default_mode(policy, data.get("mode"))
                message = "default mode updated"
            save_policy(policy_path, policy)
        except ValueError as error:
            return {"status": "ko", "message": str(error)}
        except OSError:
            return {"status": "ko", "message": "could not save policy"}
        except BaseException:
            return {"status": "ko", "message": "could not update policy"}
        return {"status": "ok", "message": message}

    return {"status": "ko", "message": "unknown action"}
