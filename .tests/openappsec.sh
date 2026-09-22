#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting open-appsec tests ..."

remove_workdir() {
	if [ ! -d /tmp/bunkerweb-plugins ] ; then
		return 0
	fi
	if sudo -n rm -rf /tmp/bunkerweb-plugins 2>/dev/null ; then
		return 0
	fi
	if rm -rf /tmp/bunkerweb-plugins 2>/dev/null ; then
		return 0
	fi
	if docker run --rm --user 0:0 -v /tmp/bunkerweb-plugins:/mnt alpine rm -rf /mnt/openappsec >/dev/null 2>&1 ; then
		rm -rf /tmp/bunkerweb-plugins 2>/dev/null || true
	fi
}

# Create working directory (plugin data may be owned by uid 101 from a prior run, so
# prefer sudo when available — but fall back to a plain rm for sudo-less local runs).
remove_workdir
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/openappsec/bw-data/plugins
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/openappsec/appsec-logs
do_and_check_cmd cp -r ./openappsec /tmp/bunkerweb-plugins/openappsec/bw-data/plugins
# BunkerWeb runs as uid 101 and only needs to READ the mounted plugin. Prefer the
# canonical chown; fall back to world-readable when passwordless sudo isn't available.
if sudo -n chown -R 101:101 /tmp/bunkerweb-plugins/openappsec/bw-data 2>/dev/null ; then
	echo "ℹ️ chowned plugin data to 101:101"
else
	echo "ℹ️ sudo unavailable, making plugin data world-readable instead"
	do_and_check_cmd chmod -R a+rX /tmp/bunkerweb-plugins/openappsec/bw-data
fi
do_and_check_cmd cp -r ./openappsec/judge /tmp/bunkerweb-plugins/openappsec/judge
do_and_check_cmd cp -r ./.tests/openappsec/appsec-localconfig /tmp/bunkerweb-plugins/openappsec/appsec-localconfig
do_and_check_cmd chmod 0755 /tmp/bunkerweb-plugins/openappsec/appsec-logs
do_and_check_cmd chmod 0777 /tmp/bunkerweb-plugins/openappsec/appsec-localconfig

# Copy compose
do_and_check_cmd cp .tests/openappsec/docker-compose.yml /tmp/bunkerweb-plugins/openappsec

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/openappsec/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/openappsec/docker-compose.yml

# Every assertion is driven from a container on the service network rather than a
# published host port: the suite then needs nothing from the host, can run beside
# the other suites, and cannot fail on an "address already in use" that has nothing
# to do with open-appsec.
http_code() {
	docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" \
		-H "Host: www.example.com" "$@" 2>/dev/null
}

# The judge enforces with the agent's default policy first, then hot-loads
# local_policy.yaml (autoPolicyLoad) 20-40 s after start and answers 200 to everything
# for a few seconds while it does. A single probe therefore lands inside that window on
# a fast runner: retry an attack until BunkerWeb denies it, and let a benign request
# through on the first try.
expect_403() {
	local label="$1"
	shift
	local ret="" attempt=0
	while [ "$attempt" -lt 60 ] ; do
		ret="$(http_code "$@")"
		if [ "$ret" = "403" ] ; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 1
	done
	docker compose logs
	docker compose down -v
	echo "❌ Error did not receive 403 code for $label within 60s (last status: $ret)"
	exit 1
}

# Do the tests
cd /tmp/bunkerweb-plugins/openappsec/ || exit 1
cleanup() {
	docker compose --profile fake down -v >/dev/null 2>&1 || true
	remove_workdir
}
trap cleanup EXIT

wait_for_log() {
	local pattern="$1"
	local timeout="$2"
	local since="$3"
	local attempt=0
	while [ "$attempt" -lt "$timeout" ] ; do
		if docker compose logs --no-color --since "$since" bunkerweb 2>/dev/null | grep -Eq "$pattern" ; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 1
	done
	return 1
}

wait_for_canary_state() {
	local state="$1"
	local timeout="$2"
	local since="$3"
	local started
	started="$(date +%s)"
	if ! wait_for_log "open-appsec canary state=$state " "$timeout" "$since" ; then
		return 1
	fi
	echo "ℹ️ Canary state=$state after $(( $(date +%s) - started ))s"
}

wait_for_canary_samples() {
	local since="$1"
	local first_seen=0
	local count
	local now
	while true ; do
		count="$(docker compose logs --no-color --since "$since" bunkerweb 2>/dev/null | grep -Ec 'open-appsec canary state=(enforcing|not_enforcing|down)' || true)"
		if [ "$count" -ge 1 ] && [ "$first_seen" -eq 0 ] ; then
			first_seen="$(date +%s)"
			echo "ℹ️ First canary sample observed"
		fi
		if [ "$count" -ge 2 ] ; then
			now="$(date +%s)"
			echo "ℹ️ Canary interval observed: 2 samples within $(( now - first_seen ))s"
			return 0
		fi
		if [ "$first_seen" -ne 0 ] ; then
			now="$(date +%s)"
			if [ $(( now - first_seen )) -ge 25 ] ; then
				return 1
			fi
		fi
		sleep 1
	done
}

compose_start="$(date +%s)"
do_and_check_cmd docker compose up -d

# Wait until BW is started
echo "ℹ️ Waiting for BW ..."
success="ko"
retry=0
while [ $retry -lt 60 ] ; do
	ret="$(docker compose exec -T client curl -s -H "Host: www.example.com" http://bunkerweb:8080 2>/dev/null | grep -i "hello")"
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] && [ "$ret" != "" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 1
done

# We're done
if [ $retry -eq 60 ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error timeout after 60s"
	exit 1
fi
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error did not receive 200 code"
	exit 1
fi

# Wait until the judge enforces. nginx inside agent-unified answers as soon as it starts,
# but the open-appsec attachment only registers with the agent about 20 s later and fails
# open until then, so a 200 on a benign request proves nothing: poll a known-bad request
# straight at the judge until it comes back 403. The client is on bw-services and cannot
# reach the judge; the scheduler is on bw-universe and ships curl.
echo "ℹ️ Waiting for open-appsec judge to enforce ..."
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	ret="$(docker compose exec -T bw-scheduler curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" -H "X-Forwarded-For: 203.0.113.7" "http://bw-openappsec/?id=/etc/passwd" 2>/dev/null)"
	if [ "$ret" = "403" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 1
done
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error open-appsec judge did not enforce after 120s (last status: $ret)"
	exit 1
fi

echo "ℹ️ Waiting for the enforcement canary ..."
if ! wait_for_canary_state enforcing 90 "$compose_start" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: enforcement canary did not report enforcing after 90s"
	exit 1
fi
if ! wait_for_canary_samples "$compose_start" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: fewer than two canary samples were observed within 25s of the first sample"
	exit 1
fi

client_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose ps -q client)")"
if [ -z "$client_ip" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: could not determine the client container IP"
	exit 1
fi

# Payload in GET arg
echo "ℹ️ Testing with GET payload ..."
expect_403 "GET /etc/passwd" "http://bunkerweb:8080/?id=/etc/passwd"

# SQL-like GET arg
echo "ℹ️ Testing with SQL-like GET payload ..."
expect_403 "SQL-like GET payload" "http://bunkerweb:8080/?id=%27%20OR%201%3D1--"

# Payload in POST arg
echo "ℹ️ Testing with POST payload ..."
expect_403 "POST /etc/passwd" -X POST "http://bunkerweb:8080/" -d 'id=/etc/passwd'

echo "ℹ️ Waiting for the correlated open-appsec event ..."
success="ko"
retry=0
request_id=""
while [ "$retry" -lt 60 ] ; do
	for event_file in /tmp/bunkerweb-plugins/openappsec/appsec-logs/cp-nano-http-transaction-handler.log* ; do
		if [ ! -f "$event_file" ] ; then
			continue
		fi
		if grep -l '"eventName": "Web Request"' "$event_file" >/dev/null 2>&1 \
			&& grep -q '"securityAction": "Prevent"' "$event_file" \
			&& grep -Eq '"httpRequestHeaders": ".*x-request-id:' "$event_file" \
			&& grep -Fq "\"httpSourceId\": \"$client_ip\"" "$event_file" ; then
			request_id="$(grep '"eventName": "Web Request"' "$event_file" | grep '"securityAction": "Prevent"' | sed -n 's/.*x-request-id: \([[:alnum:]-]*\).*/\1/p' | head -n 1)"
			if [ -n "$request_id" ] ; then
				success="ok"
				break 2
			fi
		fi
	done
	retry=$((retry + 1))
	sleep 1
done
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: no correlated Prevent event found within 60s"
	exit 1
fi

if ! wait_for_log "open-appsec denied request \\[$request_id\\]" 30 "$compose_start" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: BunkerWeb deny log did not contain [$request_id]"
	exit 1
fi

# A benign request with a normal query arg must pass (no false positive -> 200).
echo "ℹ️ Testing that a benign GET request passes ..."
ret="$(http_code "http://bunkerweb:8080/?q=hello-world")"
if [ "$ret" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: benign GET request should pass (got $ret, expected 200)"
	exit 1
fi

# A benign POST must also pass. nginx-hello serves static files and answers a POST
# with 405, so the proof that open-appsec let it through is "anything but 403".
echo "ℹ️ Testing that a benign POST request passes ..."
ret="$(http_code -X POST "http://bunkerweb:8080/" -d 'q=hello-world')"
if [ "$ret" != "200" ] && [ "$ret" != "405" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: benign POST request should pass (got $ret, expected 200 or 405)"
	exit 1
fi

# Exclusions: a payload on an excluded path or method never reaches the judge.
echo "ℹ️ Testing URI and method exclusions ..."
ret="$(http_code "http://bunkerweb:8080/healthz?id=/etc/passwd")"
if [ "$ret" == "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: excluded URI should not be inspected (got 403)"
	exit 1
fi
ret="$(http_code -X OPTIONS "http://bunkerweb:8080/?id=/etc/passwd")"
if [ "$ret" == "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: excluded method should not be inspected (got 403)"
	exit 1
fi

echo "ℹ️ Testing canary detection of a dead judge ..."
judge_stop="$(date +%s)"
do_and_check_cmd docker compose stop bw-openappsec
if ! wait_for_canary_state down 30 "$judge_stop" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: enforcement canary did not report down after stopping the judge"
	exit 1
fi
judge_restart="$(date +%s)"
do_and_check_cmd docker compose rm -sf bw-openappsec
do_and_check_cmd docker compose up -d bw-openappsec
if ! wait_for_canary_state enforcing 90 "$judge_restart" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: enforcement canary did not recover after restarting the judge"
	exit 1
fi

policy_file="/tmp/bunkerweb-plugins/openappsec/appsec-localconfig/local_policy.yaml"
policy_backup="/tmp/bunkerweb-plugins/openappsec/local_policy.original.json"
do_and_check_cmd cp "$policy_file" "$policy_backup"
echo "ℹ️ Testing open-appsec policy hot reload ..."
do_and_check_cmd python3 - "$policy_file" "$client_ip" <<'PY'
import json
import os
import sys

path, client_ip = sys.argv[1:]
with open(path, encoding="utf-8") as policy_file:
    policy = json.load(policy_file)
policy.setdefault("exceptions", []).append({"name": "e2e-skip", "action": "skip", "sourceIp": [client_ip]})
policy.setdefault("policies", {}).setdefault("default", {}).setdefault("exceptions", []).append("e2e-skip")
temporary_path = path + ".tmp"
with open(temporary_path, "w", encoding="utf-8") as policy_file:
    json.dump(policy, policy_file, indent=2)
    policy_file.write("\n")
os.replace(temporary_path, path)
PY
apply_status=0
apply_output="$(docker compose exec -T bw-openappsec open-appsec-ctl --apply-policy 2>&1)" || apply_status="$?"
echo "$apply_output"
if [ "$apply_status" -ne 0 ] && ! printf '%s\n' "$apply_output" | grep -q 'New policy applied\.' ; then
	echo "❌ Error: open-appsec policy apply failed"
	exit 1
fi
success="ko"
retry=0
while [ "$retry" -lt 90 ] ; do
	ret="$(http_code "http://bunkerweb:8080/?id=/etc/passwd")"
	if [ "$ret" = "200" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 1
done
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: open-appsec policy hot reload did not allow the client IP"
	exit 1
fi
echo "ℹ️ Confirming the exception remains active during the reload window ..."
sleep 10
ret="$(http_code "http://bunkerweb:8080/?id=/etc/passwd")"
if [ "$ret" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: open-appsec policy exception did not remain active after 10s (got $ret)"
	exit 1
fi
do_and_check_cmd cp "$policy_backup" "$policy_file"
success="ko"
retry=0
while [ "$retry" -lt 90 ] ; do
	ret="$(http_code "http://bunkerweb:8080/?id=/etc/passwd")"
	if [ "$ret" = "403" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 1
done
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: open-appsec policy restore did not deny the client IP"
	exit 1
fi

echo "ℹ️ Testing CANARY_FAIL with a non-enforcing judge ..."
fake_start="$(date +%s)"
do_and_check_cmd docker compose stop bw-openappsec
do_and_check_cmd docker compose rm -sf bw-openappsec
do_and_check_cmd docker compose --profile fake up -d bw-openappsec-fake
if ! wait_for_canary_state not_enforcing 30 "$fake_start" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: enforcement canary did not report not_enforcing for the fake judge"
	exit 1
fi
ret="$(docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" -H "Host: www2.example.com" "http://bunkerweb:8080/?q=hello-world" 2>/dev/null)"
if [ "$ret" != "500" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: CANARY_FAIL closed service should return 500 (got $ret)"
	exit 1
fi
ret="$(http_code "http://bunkerweb:8080/?q=hello-world")"
if [ "$ret" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: CANARY_FAIL open service should return 200 (got $ret)"
	exit 1
fi
ret="$(http_code "http://bunkerweb:8080/healthz?id=/etc/passwd")"
if [ "$ret" = "500" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: excluded healthz URI on the open service should not return 500"
	exit 1
fi
ret="$(docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" -H "Host: www2.example.com" "http://bunkerweb:8080/healthz?id=/etc/passwd" 2>/dev/null)"
if [ "$ret" = "500" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: excluded healthz URI on the closed service should not return 500"
	exit 1
fi
do_and_check_cmd docker compose --profile fake rm -sf bw-openappsec-fake
judge_restart="$(date +%s)"
do_and_check_cmd docker compose up -d bw-openappsec
if ! wait_for_canary_state enforcing 90 "$judge_restart" ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: enforcement canary did not recover after removing the fake judge"
	exit 1
fi

# The default mode fails open when the judge is unavailable: the *malicious* request must
# now pass, which is what tells fail-open apart from "the plugin was never consulted".
echo "ℹ️ Testing fail-open behaviour ..."
do_and_check_cmd docker compose stop bw-openappsec
ret="$(http_code "http://bunkerweb:8080/?id=/etc/passwd")"
if [ "$ret" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: fail-open request should pass (got $ret, expected 200)"
	exit 1
fi

# www2 is configured with OPENAPPSEC_FAIL_MODE=closed: same dead judge, must be a 500.
echo "ℹ️ Testing fail-closed behaviour ..."
ret="$(docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" -H "Host: www2.example.com" "http://bunkerweb:8080/?q=hello-world" 2>/dev/null)"
if [ "$ret" != "500" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: fail-closed request should be denied (got $ret, expected 500)"
	exit 1
fi

# We're done
if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ open-appsec tests done"
