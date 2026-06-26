#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Cloudflare tests ..."

WORKDIR=/tmp/bunkerweb-plugins/cloudflare

fail() {
	echo "❌ $1"
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
do_and_check_cmd cp -r ./cloudflare "$WORKDIR/bw-data/plugins/cloudflare"
# BunkerWeb runs as uid 101 and only needs to READ the mounted plugin (:ro). Prefer the
# canonical chown; fall back to world-readable when passwordless sudo isn't available.
if sudo -n chown -R 101:101 "$WORKDIR/bw-data" 2>/dev/null ; then
	echo "ℹ️ chowned plugin data to 101:101"
else
	echo "ℹ️ sudo unavailable, making plugin data world-readable instead"
	do_and_check_cmd chmod -R a+rX "$WORKDIR/bw-data"
fi

# Copy compose + mocks
do_and_check_cmd cp -r .tests/cloudflare/. "$WORKDIR/"

# Point the compose at the locally pulled :tests images
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" "$WORKDIR/docker-compose.yml"
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" "$WORKDIR/docker-compose.yml"

cd "$WORKDIR" || exit 1
# Use fail() (not do_and_check_cmd) so a failed bring-up is also torn down with down -v.
docker compose up --build -d || fail "docker compose up failed"

# Cloudflare proxies to the origin over HTTPS, so the functional checks use :8443. (Once
# the origin cert is in place BunkerWeb redirects HTTP->HTTPS, which would mask the deny
# verdict on :8080.) --connect-to keeps SNI=www.example.com while dialing the container.
https_code() {
	docker compose exec -T "$1" curl -sk -o /dev/null -w "%{http_code}" \
		--connect-to www.example.com:8443:bunkerweb:8443 https://www.example.com:8443/ 2>/dev/null
}

# Readiness: wait until the untrusted client is DENIED over HTTPS. The plugin fails open
# while the trusted-IP list is empty (BunkerWeb's loading page + the window before
# cf-trusted-ips-download.py runs), so a 403 here means the list AND the origin cert have
# been downloaded, synced to BunkerWeb and reloaded — fully ready.
echo "ℹ️ Waiting for the cloudflare plugin to enforce deny over HTTPS ..."
success="ko"
retry=0
while [ $retry -lt 180 ] ; do
	if [ "$(https_code evil-client)" = "403" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 1
done
[ "$success" = "ok" ] || fail "untrusted client never got denied — trusted IP list / origin cert not ready"
echo "✅ Untrusted client (192.0.2.10) is denied (403)"

# A Cloudflare-range client must reach the upstream (200) — proving the trusted path and
# that the list really contains 173.245.48.0/20. (BunkerWeb is fully loaded by now, per
# the deny above, so a 200 is the upstream, not the "Generating..." loading page.)
echo "ℹ️ Testing that a Cloudflare-range client reaches the upstream ..."
code="$(https_code cf-client)"
[ "$code" = "200" ] || fail "Cloudflare-range client (173.245.48.2) should reach the upstream (got $code)"
echo "✅ Cloudflare-range client (173.245.48.2) reaches the upstream (200)"

# Provenance: confirm the verdicts came from THIS plugin.
docker compose logs bunkerweb 2>/dev/null | grep -F "192.0.2.10 is not trusted" >/dev/null || fail "no cloudflare 'not trusted' log for the untrusted client"
docker compose logs bunkerweb 2>/dev/null | grep -F "173.245.48.2 is trusted" >/dev/null || fail "no cloudflare 'is trusted' log for the Cloudflare-range client"
echo "✅ Deny/allow verdicts are attributable to the cloudflare plugin"

# Feature 1: the trusted-IP download job ran and hit the mock.
docker compose logs bw-scheduler 2>/dev/null | grep -E "Downloaded [0-9]+ trusted ipv4" >/dev/null || fail "trusted-IP download job did not report success"
docker compose logs cfips-mock 2>/dev/null | grep -F "GET /ips-v4/" >/dev/null || fail "the IP-list mock was never queried"
echo "✅ Trusted-IP download job ran against the mock"

# Feature 3: the origin-cert job generated a cert via the mock CF API ...
docker compose logs bw-scheduler 2>/dev/null | grep -F "Successfully generated origin certificate" >/dev/null || fail "origin certificate was never generated"
docker compose logs cf-api-mock 2>/dev/null | grep -F "POST /certificates" >/dev/null || fail "the mock CF API was never asked to sign a certificate"
echo "✅ Origin certificate generated via the mock CF API"

# ... and BunkerWeb serves it over SNI. Redirect curl's verbose output inside the
# container (sh -c '... 2>&1') so the TLS lines survive `docker compose exec -T`.
echo "ℹ️ Checking the served origin certificate ..."
out="$(docker compose exec -T cf-client sh -c 'curl -ksv --connect-to www.example.com:8443:bunkerweb:8443 https://www.example.com:8443/ 2>&1' 2>/dev/null)"
echo "$out" | grep -qE "subject:.*CN ?= ?www\.example\.com" || fail "served certificate subject is not CN=www.example.com (got: $(echo "$out" | grep -i subject | tr -d '\r'))"
echo "$out" | grep -q "Mock Cloudflare Origin CA" || fail "served certificate is not issued by the mock Origin CA"
echo "✅ BunkerWeb serves the Cloudflare origin certificate over SNI"

# Feature F1: the Authenticated Origin Pull CA was downloaded.
docker compose logs bw-scheduler 2>/dev/null | grep -F "Authenticated Origin Pull CA" >/dev/null || fail "AOP CA download job did not report success"
echo "✅ Authenticated Origin Pull CA downloaded"

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ Cloudflare tests done"
