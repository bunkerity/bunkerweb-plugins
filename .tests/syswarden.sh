#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting SysWarden tests ..."

WORKDIR=/tmp/bunkerweb-plugins/syswarden

fail() {
	echo "❌ $1"
	# Some failures happen before the cd, and compose only knows the project from there.
	cd "$WORKDIR" 2>/dev/null || { exit 1 ; }
	docker compose logs
	docker compose down -v
	exit 1
}

# Create working directory (plugin data may be owned by uid 101 from a prior run, so
# prefer sudo when available — but fall back to a plain rm for sudo-less local runs).
if [ -d "$WORKDIR" ] ; then
	sudo -n rm -rf "$WORKDIR" 2>/dev/null || do_and_check_cmd rm -rf "$WORKDIR"
fi
do_and_check_cmd mkdir -p "$WORKDIR/bw-data/plugins"
do_and_check_cmd cp -r ./syswarden "$WORKDIR/bw-data/plugins/syswarden"
# BunkerWeb runs as uid 101 and only needs to READ the mounted plugin (:ro). Prefer the
# canonical chown; fall back to world-readable when passwordless sudo isn't available.
if sudo -n chown -R 101:101 "$WORKDIR/bw-data" 2>/dev/null ; then
	echo "ℹ️ chowned plugin data to 101:101"
else
	echo "ℹ️ sudo unavailable, making plugin data world-readable instead"
	do_and_check_cmd chmod -R a+rX "$WORKDIR/bw-data"
fi

# Copy compose + mock
do_and_check_cmd cp -r .tests/syswarden/. "$WORKDIR/"

# Point the compose at the locally pulled :tests images
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" "$WORKDIR/docker-compose.yml"
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" "$WORKDIR/docker-compose.yml"

# SysWarden self-signs its HA certificate per host, so certificate pinning is the posture
# operators actually use — and the one under test here. Generate the identity, then hand
# its SHA-256 to the scheduler exactly the way the README tells an operator to.
do_and_check_cmd mkdir -p "$WORKDIR/certs"
do_and_check_cmd openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
	-keyout "$WORKDIR/certs/server.key" -out "$WORKDIR/certs/server.crt" \
	-subj "/CN=sw-mock" -addext "subjectAltName=DNS:sw-mock,DNS:sw-mock-legacy"
do_and_check_cmd chmod a+r "$WORKDIR/certs/server.key" "$WORKDIR/certs/server.crt"
FINGERPRINT="$(openssl x509 -in "$WORKDIR/certs/server.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
[ -n "$FINGERPRINT" ] || fail "could not read the mock certificate fingerprint"
echo "SYSWARDEN_SSL_FINGERPRINT=$FINGERPRINT" > "$WORKDIR/.env"
echo "ℹ️ Pinning the mock certificate: $FINGERPRINT"

cd "$WORKDIR" || exit 1
# Use fail() (not do_and_check_cmd) so a failed bring-up is also torn down with down -v.
docker compose up --build -d || fail "docker compose up failed"

http_code() {
	docker compose exec -T "$1" curl -s -o /dev/null -w "%{http_code}" \
		-H "Host: www.example.com" "http://bunkerweb:8080${2:-/}" 2>/dev/null
}

# Predicate form of http_code, so wait_for re-evaluates it on every poll rather than
# comparing one value captured before the loop started.
answers() {
	[ "$(http_code "$1" "$3")" = "$2" ]
}

# Wait for a condition, polling once a second. wait_for <polls> <description> <command...>
# The bound is a poll count, not wall clock: each poll also pays for a `docker compose
# exec` or `logs` round-trip, so real elapsed time runs well past the number given.
wait_for() {
	local timeout="$1" description="$2"
	shift 2
	local retry=0
	while [ "$retry" -lt "$timeout" ] ; do
		if "$@" >/dev/null 2>&1 ; then
			return 0
		fi
		retry=$((retry + 1))
		sleep 1
	done
	fail "timed out after ${timeout} polls waiting for: $description"
}

mock_logs() {
	docker compose logs "${1:-sw-mock}" 2>/dev/null
}
legacy_logs() {
	mock_logs sw-mock-legacy
}

mock_saw() {
	mock_logs | grep -F "$1" >/dev/null
}
mock_saw_legacy() {
	legacy_logs | grep -F "$1" >/dev/null
}

# Assert on ONE entry of a logged batch rather than on the whole line: the mock logs a
# batch as a single JSON line, so a plain grep can be satisfied by a neighbouring entry.
entry_for() {
	docker compose exec -T bw-scheduler python3 -c '
import json, sys
line, address = sys.argv[1], sys.argv[2]
payload = json.loads(line[line.index("{"):])
for entry in payload.get("bans", []):
    if entry.get("ip") == address:
        print(json.dumps(entry, sort_keys=True))
        break
' "$1" "$2" 2>/dev/null
}

# --- Pull direction ------------------------------------------------------------------
# The download job runs at scheduler start. A client inside the range the mock serves must
# end up denied at Layer 7, which proves the whole chain: job -> job cache -> scheduler
# ships it to the instance -> nginx reload -> syswarden.lua matcher.
echo "ℹ️ Waiting for the pulled blocklist to deny at Layer 7 ..."
wait_for 240 "pulled-client to be denied" answers pulled-client 403
echo "✅ A client inside SysWarden's blocklist is denied at Layer 7 (403)"

# Named address, not just the plugin's wording: this ties the deny to the client that was
# supposed to be denied, so another client's verdict cannot satisfy it.
docker compose logs bunkerweb 2>/dev/null | grep -F "203.0.113.10 is in the SysWarden blocklist" >/dev/null \
	|| fail "the deny is not attributable to the syswarden plugin"
echo "✅ The deny verdict is attributable to the syswarden plugin"

# The same address in both lists must be allowed: the whitelist is the operator's explicit
# override and it is pulled from /ha/telemetry, not from the blocklist.
code="$(http_code allowed-client)"
[ "$code" = "200" ] || fail "a whitelisted client should reach the upstream (got $code)"
docker compose logs bunkerweb 2>/dev/null | grep -F "203.0.113.20 is in the SysWarden whitelist" >/dev/null \
	|| fail "no whitelist log for the client present in both lists"
echo "✅ The whitelist wins over the blocklist (200)"

# --- Push direction ------------------------------------------------------------------
# Get evil-client banned by bad-behavior, then let the minute-ly job propagate it.
echo "ℹ️ Getting evil-client banned by bad-behavior ..."
for _ in 1 2 3 4 5 ; do
	http_code evil-client /this-page-does-not-exist >/dev/null
done
wait_for 60 "bad-behavior to ban evil-client" answers evil-client 403
echo "✅ evil-client is banned by BunkerWeb (403)"

echo "ℹ️ Waiting for the ban to reach the SysWarden peer ..."
wait_for 180 "the ban push to reach the mock" mock_saw '"ip": "192.0.2.10"'
echo "✅ The BunkerWeb ban reached SysWarden's HA API"

# The payload shape is the contract: an expiring ban carries a lifetime, the reason and the
# provenance tag. Asserting on the body the mock logged, not on what the job says it did.
pushed="$(mock_logs | grep -F 'MOCK BODY POST /ha/sync' | grep -F '192.0.2.10' | tail -n 1)"
[ -n "$pushed" ] || fail "no POST /ha/sync body carrying the banned address"
entry="$(entry_for "$pushed" 192.0.2.10)"
[ -n "$entry" ] || fail "no ban entry for the banned address in: $pushed"
echo "$entry" | grep -F '"source": "e2e-cluster"' >/dev/null || fail "the pushed ban carries no explicit cluster provenance tag: $entry"
echo "$entry" | grep -F '"ttl":' >/dev/null || fail "the pushed ban carries no lifetime: $entry"
echo "$entry" | grep -F '"reason":' >/dev/null || fail "the pushed ban carries no reason: $entry"
echo "✅ The ban was pushed with a lifetime, a reason and the explicit cluster provenance tag"

# The other half of the contract: capabilities decide per peer, not a global switch. The
# only published SysWarden generation understands nothing but {"ips"}, so a pass that
# speaks provenance to everyone would leave it unprotected. This is the assertion a
# v4.03-only plugin cannot pass.
wait_for 180 "the ban push to reach the older peer" mock_saw_legacy '192.0.2.10'
legacy_pushed="$(legacy_logs | grep -F 'MOCK BODY POST /ha/sync' | grep -F '192.0.2.10' | tail -n 1)"
[ -n "$legacy_pushed" ] || fail "the older peer never received the ban"
echo "$legacy_pushed" | grep -F '"ips"' >/dev/null \
	|| fail "the older peer did not get the legacy payload: $legacy_pushed"
echo "$legacy_pushed" | grep -F '"bans"' >/dev/null \
	&& fail "the older peer got a provenance payload it cannot parse: $legacy_pushed"
echo "✅ The same pass spoke the legacy payload to the older peer"

# --- Unban ---------------------------------------------------------------------------
# A ban that simply runs out needs no DELETE on a peer that tracks expiry: the lifetime the
# plugin pushed is the ban's own remaining time, so the peer drops it by itself. The case
# that does need a DELETE is an operator lifting a ban early, so that is what is tested.
echo "ℹ️ Unbanning evil-client from BunkerWeb ..."
unban_output="$(docker compose exec -T bw-scheduler bwcli unban 192.0.2.10 2>&1)" \
	|| fail "bwcli unban failed: $unban_output"
wait_for 60 "BunkerWeb to serve evil-client again" answers evil-client 200
echo "✅ evil-client is unbanned in BunkerWeb (200)"

echo "ℹ️ Waiting for the removal to reach the peer ..."
wait_for 180 "the unban to reach the current peer" mock_saw 'MOCK BODY DELETE /ha/sync'
removed="$(mock_logs | grep -F 'MOCK BODY DELETE /ha/sync' | tail -n 1)"
entry="$(entry_for "$removed" 192.0.2.10)"
[ -n "$entry" ] || fail "the delete does not carry the lifted ban: $removed"
echo "$entry" | grep -F '"source": "e2e-cluster"' >/dev/null || fail "the delete carries no explicit cluster provenance tag: $entry"
echo "$entry" | grep -F '"ttl"' >/dev/null && fail "a delete must carry only ip and source: $entry"
echo "✅ The current peer got a provenance-keyed delete (ip and source only)"

# The older peer has no ledger, so its own removal must ride the legacy dialect, keyed on
# the durable registry rather than on anything the peer reports.
wait_for 180 "the unban to reach the older peer" mock_saw_legacy 'MOCK BODY DELETE /ha/sync'
legacy_removed="$(legacy_logs | grep -F 'MOCK BODY DELETE /ha/sync' | grep -F '192.0.2.10' | tail -n 1)"
[ -n "$legacy_removed" ] || fail "the older peer never got the compensating delete"
echo "$legacy_removed" | grep -F '"ips"' >/dev/null \
	|| fail "the older peer got a non-legacy delete: $legacy_removed"
echo "✅ The older peer got the legacy compensating delete"

# --- Ownership -----------------------------------------------------------------------
# Provenance-only mutation must never send the shared-static-store body at all.
mock_logs | grep -F 'MOCK BODY POST /ha/sync' | grep -F '"ips"' >/dev/null \
	&& fail "the provenance peer got a legacy push; per-peer capability detection is broken"
for peer in sw-mock sw-mock-legacy; do
	mock_logs "$peer" | grep -F 'MOCK BODY DELETE /ha/sync' | grep -F '198.51.100.77' >/dev/null \
		&& fail "the plugin tried to delete the operator entry on $peer"
	# Read from the scheduler: it is the container the peers' IP allowlist accepts, so this
	# doubles as a check that the allowlist did not lock the plugin out. stderr is kept, so a
	# TLS or name-resolution failure cannot read as "the operator entry was deleted".
	still_there="$(docker compose exec -T bw-scheduler python3 -c '
import json, ssl, sys, urllib.request
# The mock certificate carries both peer names as SANs, so this verifies for real.
context = ssl.create_default_context(cafile="/certs/server.crt")
request = urllib.request.Request(f"https://{sys.argv[1]}:62026/ha/sync")
request.add_header("Authorization", "Bearer e2e-syswarden-token")
with urllib.request.urlopen(request, timeout=10, context=context) as answer:
    print(json.dumps(json.load(answer).get("ips") or []))
' "$peer" 2>&1)"
	echo "$still_there" | grep -F '198.51.100.77' >/dev/null \
		|| fail "the operator entry is no longer readable in $peer's blocklist: $still_there"
done
echo "✅ The operator entry is untouched and still enforced on both peers"

# --- Telemetry -----------------------------------------------------------------------
mock_saw "GET /ha/status" || fail "the telemetry job never polled /ha/status"
mock_saw "GET /ha/telemetry" || fail "the telemetry job never polled /ha/telemetry"
echo "✅ The telemetry job polled status and telemetry"

# --- Nothing broke -------------------------------------------------------------------
docker compose logs bw-scheduler 2>/dev/null | grep -F "Exception while running syswarden" >/dev/null \
	&& fail "a syswarden job raised an exception"
for peer in sw-mock sw-mock-legacy; do
	mock_logs "$peer" | grep -F "MOCK REFUSED" >/dev/null \
		&& fail "$peer refused a request the plugin sent"
done
echo "✅ No job raised, and no peer refused a payload"

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ SysWarden tests done"
