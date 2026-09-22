"""Stdlib-only data and policy helpers for the open-appsec UI."""

import datetime
import glob
import ipaddress
import json
import os
import re
import secrets
import stat
import tempfile
from collections import Counter
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

EVENT_TAIL_BYTES = 512 * 1024
DEFAULT_SKIP_HOSTS = ("canary.openappsec.bunkerweb.invalid",)
CONDITION_KEYS = ("sourceIp", "url", "hostName", "paramName", "paramValue", "protectionName", "countryCode")
EXCEPTION_ACTIONS = ("skip", "accept", "drop", "suppressLog")
SERVICE_MODES = ("prevent-learn", "detect-learn", "prevent", "detect", "inactive")
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VALUE_RE = re.compile(r'^[^\s"\\]{1,256}$')
HEADER_RE = re.compile(r"(?:^|[;\[])\s*([^:;\]]+)\s*:\s*([^;\]]+)", re.IGNORECASE)


def _string(value):
    return "" if value is None else str(value)


def _header_value(headers, name):
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == name:
                return _string(value).strip()
        return ""
    for match in HEADER_RE.finditer(_string(headers).strip("[]")):
        if match.group(1).strip().lower() == name:
            return match.group(2).strip()
    return ""


def _request_id(headers):
    return _header_value(headers, "x-request-id")


def _project_event(raw, skip_hosts):
    if not isinstance(raw, dict) or raw.get("eventName") != "Web Request":
        return None
    data = raw.get("eventData")
    source = raw.get("eventSource")
    if not isinstance(data, dict):
        return None
    if not isinstance(source, dict):
        source = {}
    host = _string(data.get("httpHostName"))
    headers = data.get("httpRequestHeaders")
    if host == "healthcheck.invalid" or host in (skip_hosts or ()):
        return None
    if _header_value(headers, "user-agent").lower().startswith("bunkerweb-openappsec-"):
        return None
    sample = _string(data.get("matchedSample"))
    uri_path = _string(data.get("httpUriPath"))
    if not uri_path:
        request_uri = _string(data.get("httpUri"))
        if request_uri.startswith(("/", "http://", "https://")):
            with suppress(ValueError):
                uri_path = urlsplit(request_uri).path
    uri_query = _string(data.get("httpUriQuery"))
    url = uri_path + (f"?{uri_query}" if uri_query else "")
    return {
        "time": _string(raw.get("eventTime")),
        "event_id": _string(data.get("eventReferenceId")),
        "ip": _string(data.get("httpSourceId") or data.get("sourceIP")),
        "host": host,
        "method": _string(data.get("httpMethod")),
        "url": url,
        "path": uri_path,
        "query": uri_query,
        "action": _string(data.get("securityAction")),
        "override": _string(data.get("waapOverride")),
        "incident": _string(data.get("waapIncidentType")),
        "location": _string(data.get("matchedLocation")),
        "param": _string(data.get("matchedParameter")),
        "sample": sample[:120],
        "confidence": _string(data.get("eventConfidence")),
        "score": data.get("waapFinalScore", ""),
        "request_id": _request_id(data.get("httpRequestHeaders")),
        "practice": _string(data.get("practiceName")),
        "agent_version": _string(source.get("issuingEngineVersion")),
        "agent_id": _string(source.get("agentId")),
    }


def read_events(events_dir, limit=200, skip_hosts=DEFAULT_SKIP_HOSTS):
    """Read recent request events from the agent's rotated JSON-lines logs."""
    if not events_dir or not os.path.isdir(events_dir):
        return [], "events directory not found"
    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 200

    events = []
    try:
        paths = glob.glob(os.path.join(events_dir, "cp-nano-http-transaction-handler.log*"))
        for path in paths:
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as handle:
                    if size > EVENT_TAIL_BYTES:
                        handle.seek(size - EVENT_TAIL_BYTES)
                    text = handle.read().decode("utf-8", errors="replace")
            except (OSError, UnicodeError):
                return [], "could not read event logs"
            for line in text.splitlines():
                try:
                    projected = _project_event(json.loads(line), skip_hosts)
                except (TypeError, ValueError):
                    continue
                if projected is not None:
                    events.append(projected)
    except (OSError, TypeError):
        return [], "could not read event logs"

    events.sort(key=lambda event: event.get("time", ""), reverse=True)
    return events[:limit], None


def _parse_event_time(value):
    text = _string(value)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def agent_summary(events, now_utc=None):
    """Summarize agent identity and the last 24 hours of projected events."""
    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(hours=24)
    latest = None
    latest_time = None
    recent = []
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        event_time = _parse_event_time(event.get("time"))
        if event_time is not None and event_time <= now and (latest_time is None or event_time > latest_time):
            latest = event
            latest_time = event_time
        if event_time is not None and cutoff <= event_time <= now:
            recent.append(event)

    incidents = {}
    for event in recent:
        incident = _string(event.get("incident"))
        if incident:
            incidents[incident] = incidents.get(incident, 0) + 1
    top_incidents = sorted(incidents.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        "version": _string(latest.get("agent_version")) if latest else "",
        "agent_id": _string(latest.get("agent_id")) if latest else "",
        "last_event": _string(latest.get("time")) if latest else "",
        "events_24h": len(recent),
        "prevented_24h": sum(1 for event in recent if event.get("action") == "Prevent"),
        "detected_24h": sum(1 for event in recent if event.get("action") == "Detect"),
        "top_incidents": top_incidents,
    }


def load_policy(path):
    if not isinstance(path, str) or not path:
        return None, "policy path is not configured"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
    except FileNotFoundError:
        return None, "policy file not found"
    except json.JSONDecodeError:
        return None, "policy is not in JSON syntax (the UI cannot edit YAML); rewrite it as JSON first"
    except OSError:
        return None, "could not read policy file"
    if not isinstance(policy, dict):
        return None, "policy must be a JSON object"
    return policy, None


def _safe_policy_path(path):
    if not isinstance(path, str) or not path:
        raise ValueError("policy path is not configured")
    absolute = os.path.abspath(path)
    configured_dir = os.path.dirname(absolute)
    if os.path.realpath(configured_dir) != configured_dir:
        raise ValueError("policy path must stay in its configured directory")
    target_dir = os.path.dirname(os.path.realpath(absolute))
    if target_dir != configured_dir:
        raise ValueError("policy path must stay in its configured directory")
    return absolute, configured_dir


def _safe_sidecar(path, configured_dir):
    if os.path.dirname(os.path.realpath(path)) != configured_dir:
        raise ValueError("policy sidecar must stay in its configured directory")


def save_policy(path, policy):
    """Write JSON atomically and retain the previous file as ``.bak``."""
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    absolute, configured_dir = _safe_policy_path(path)
    backup_path = absolute + ".bak"
    _safe_sidecar(backup_path, configured_dir)

    previous = None
    original_mode = None
    if os.path.isfile(absolute):
        try:
            original_mode = stat.S_IMODE(os.stat(absolute).st_mode)
            file_descriptor = os.open(absolute, os.O_RDONLY)
            try:
                chunks = []
                while True:
                    chunk = os.read(file_descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                previous = b"".join(chunks)
            finally:
                os.close(file_descriptor)
        except OSError as error:
            raise OSError("could not read existing policy") from error

    if previous is not None:
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix=os.path.basename(absolute) + ".bak.", dir=configured_dir, mode="wb", delete=False) as handle:
                temporary_path = handle.name
                handle.write(previous)
                handle.flush()
            os.replace(temporary_path, backup_path)
        finally:
            if temporary_path and os.path.lexists(temporary_path):
                Path(temporary_path).unlink()

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix=os.path.basename(absolute) + ".tmp.", dir=configured_dir, mode="w", encoding="utf-8", delete=False) as handle:
            temporary_path = handle.name
            json.dump(policy, handle, indent=2)
            handle.write("\n")
            handle.flush()
            if original_mode is not None:
                os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, absolute)
    finally:
        if temporary_path and os.path.lexists(temporary_path):
            Path(temporary_path).unlink()


def list_exceptions(policy):
    result = []
    exceptions = policy.get("exceptions", []) if isinstance(policy, dict) else []
    if not isinstance(exceptions, list):
        return result
    for item in exceptions:
        if not isinstance(item, dict):
            continue
        conditions = {}
        for key, value in item.items():
            if key in ("name", "action"):
                continue
            conditions[key] = value if isinstance(value, (list, str)) else _string(value)
        result.append({"name": _string(item.get("name")), "action": _string(item.get("action")), "conditions": conditions})
    return result


def _policy_containers(policy):
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    policies = policy.setdefault("policies", {})
    if not isinstance(policies, dict):
        raise ValueError("policy policies must be an object")
    default = policies.setdefault("default", {})
    if not isinstance(default, dict):
        raise ValueError("policy default must be an object")
    rules = policies.setdefault("specific-rules", [])
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise ValueError("policy specific rules must be a list")
    return policies, default, rules


def _reference_list(container, key):
    references = container.setdefault(key, [])
    if not isinstance(references, list):
        raise ValueError("policy exception references must be lists")
    return references


def _validate_conditions(conditions):
    if not isinstance(conditions, dict) or not conditions:
        raise ValueError("at least one exception condition is required")
    clean = {}
    for key, values in conditions.items():
        if key not in CONDITION_KEYS:
            raise ValueError("unsupported exception condition")
        if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
            raise ValueError("exception conditions must be non-empty lists of strings")
        clean_values = []
        for value in values:
            if key == "sourceIp":
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError as error:
                    raise ValueError("sourceIp contains an invalid network") from error
            elif not VALUE_RE.fullmatch(value):
                raise ValueError("exception condition contains an invalid value")
            clean_values.append(value)
        clean[key] = clean_values
    return clean


def _validated_name(name, existing):
    if name is None:
        while True:
            candidate = "bw-" + secrets.token_hex(4)
            if candidate not in existing:
                return candidate
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("exception name is invalid")
    if name in existing:
        raise ValueError("exception name already exists")
    return name


def add_exception(policy, action, conditions, name=None):
    if action not in EXCEPTION_ACTIONS:
        raise ValueError("exception action is invalid")
    clean_conditions = _validate_conditions(conditions)
    policies, default, rules = _policy_containers(policy)
    exceptions = policy.setdefault("exceptions", [])
    if not isinstance(exceptions, list) or any(not isinstance(item, dict) for item in exceptions):
        raise ValueError("policy exceptions must be a list")
    existing = {_string(item.get("name")) for item in exceptions}
    exception_name = _validated_name(name, existing)
    exceptions.append({"name": exception_name, "action": action, **clean_conditions})
    _reference_list(default, "exceptions").append(exception_name)
    for rule in rules:
        _reference_list(rule, "exceptions").append(exception_name)
    return exception_name


def remove_exception(policy, name):
    if not isinstance(policy, dict):
        return
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("exception name is invalid")
    exceptions = policy.get("exceptions", [])
    if isinstance(exceptions, list):
        policy["exceptions"] = [item for item in exceptions if not isinstance(item, dict) or item.get("name") != name]
    policies = policy.get("policies", {}) if isinstance(policy, dict) else {}
    if not isinstance(policies, dict):
        return
    containers = [policies.get("default", {})]
    rules = policies.get("specific-rules", [])
    if isinstance(rules, list):
        containers.extend(rules)
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get("exceptions", []), list):
            continue
        container["exceptions"] = [reference for reference in container.get("exceptions", []) if reference != name]


def _default_and_rules(policy):
    policies = policy.get("policies", {}) if isinstance(policy, dict) else {}
    if not isinstance(policies, dict):
        return {}, []
    default = policies.get("default", {})
    rules = policies.get("specific-rules", [])
    return default if isinstance(default, dict) else {}, rules if isinstance(rules, list) else []


def service_modes(policy, services):
    default, rules = _default_and_rules(policy)
    default_mode = _string(default.get("mode"))
    result = []
    for host in services if isinstance(services, list) else []:
        if not isinstance(host, str):
            continue
        host_base = host.split(":", 1)[0]
        rule = next(
            (item for item in rules if isinstance(item, dict) and _string(item.get("host")).split(":", 1)[0] == host_base),
            None,
        )
        mode = _string(rule.get("mode")) if rule else "inherit"
        if mode not in SERVICE_MODES:
            mode = "inherit"
        result.append({"host": host, "mode": mode, "effective_mode": mode if mode != "inherit" else default_mode})
    return result


def _validate_host(host):
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise ValueError("service host is invalid")


def _validate_mode(mode, allow_inherit):
    valid = SERVICE_MODES + (("inherit",) if allow_inherit else ())
    if mode not in valid:
        raise ValueError("service mode is invalid")


def set_service_mode(policy, host, mode):
    _validate_host(host)
    _validate_mode(mode, True)
    policies, default, rules = _policy_containers(policy)
    host_base = host.split(":", 1)[0]
    matching = [index for index, rule in enumerate(rules) if _string(rule.get("host")).split(":", 1)[0] == host_base]
    if mode == "inherit":
        policies["specific-rules"] = [rule for rule in rules if _string(rule.get("host")).split(":", 1)[0] != host_base]
        return

    rule = {
        "host": host,
        "mode": mode,
        "triggers": list(default.get("triggers", [])) if isinstance(default.get("triggers", []), list) else [],
        "practices": list(default.get("practices", [])) if isinstance(default.get("practices", []), list) else [],
        "custom-response": default.get("custom-response", ""),
        "exceptions": list(default.get("exceptions", [])) if isinstance(default.get("exceptions", []), list) else [],
    }
    if matching:
        first = matching[0]
        rule["host"] = _string(rules[first].get("host")) or host
        policies["specific-rules"] = [item for index, item in enumerate(rules) if index == first or _string(item.get("host")).split(":", 1)[0] != host_base]
        policies["specific-rules"][policies["specific-rules"].index(rules[first])] = rule
    else:
        rules.append(rule)


def set_default_mode(policy, mode):
    _validate_mode(mode, False)
    _, default, _ = _policy_containers(policy)
    default["mode"] = mode


def outcome_shares(counters):
    counts = {key: counters.get(key, 0) for key in ("accepted", "denied", "skipped", "errors")}
    total = sum(counts.values())
    return {"total": total, **{key: {"count": count, "pct": round(count * 100 / total, 1) if total else 0.0} for key, count in counts.items()}}


def hour_buckets(now_utc):
    """Start labels for 24 rolling one-hour bins, oldest first (UTC)."""
    now_utc = now_utc.astimezone(datetime.timezone.utc)
    return [(now_utc - datetime.timedelta(hours=offset)).strftime("%H:%M") for offset in range(24, 0, -1)]


def heatmap(events, hostnames, now_utc):
    """Count the rolling 24 hours; bound unconfigured Host-header rows."""
    now_utc = now_utc.astimezone(datetime.timezone.utc)
    start = now_utc - datetime.timedelta(hours=24)
    recent = []
    for event in events:
        timestamp = _parse_event_time(event.get("time"))
        if timestamp is not None and start <= timestamp <= now_utc:
            recent.append((event, min(23, int((timestamp - start).total_seconds() // 3600))))
    configured = dict.fromkeys(hostnames)
    counts = Counter(event.get("host", "") for event, _ in recent)
    active_configured = [host for host in configured if counts[host]]
    rank = {host: index for index, host in enumerate(configured)}
    # Busiest hosts first so the attackers never fold into "other hosts"; ties keep configured order.
    ranked = sorted(counts, key=lambda host: (-counts[host], rank.get(host, len(rank)), host))
    rows = {host: {"host": host, "cells": [0] * 24, "total": 0} for host in ranked[:12]}
    other = {"host": f"{len(counts) - len(rows)} other hosts", "cells": [0] * 24, "total": 0}
    columns = [0] * 24
    actions = Counter()
    for event, column in recent:
        row = rows.get(event.get("host", ""), other)
        row["cells"][column] += 1
        row["total"] += 1
        columns[column] += 1
        actions[event.get("action")] += 1
    result_rows = [*rows.values(), *([other] if other["total"] else [])]
    return {
        "hours": hour_buckets(now_utc),
        "start": start.isoformat(timespec="seconds"),
        "end": now_utc.isoformat(timespec="seconds"),
        "rows": result_rows,
        "hidden_configured": len(configured) - len(active_configured),
        "columns": columns,
        "max": max((max(row["cells"]) for row in result_rows), default=0),
        "prevent": actions["Prevent"],
        "detect": actions["Detect"],
    }


def top_paths(events, limit=5):
    counts = Counter(event["path"] for event in events if event.get("path"))
    total = sum(counts.values())
    return [
        {"path": path, "count": count, "pct": round(count * 100 / total, 1)}
        for path, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(0, limit)]
    ]


def top_params(events, limit=5):
    counts = Counter((event["param"], event.get("location", "")) for event in events if event.get("param"))
    return [
        {"param": param, "location": location, "count": count}
        for (param, location), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(0, limit)]
    ]
