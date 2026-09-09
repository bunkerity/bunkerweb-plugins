#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Authentik tests ..."

# Create working directory (plugin data may be owned by uid 101 from a prior run, so
# prefer sudo when available — but fall back to a plain rm for sudo-less local runs).
if [ -d /tmp/bunkerweb-plugins ] ; then
	sudo -n rm -rf /tmp/bunkerweb-plugins 2>/dev/null || do_and_check_cmd rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/authentik/bw-data/plugins
do_and_check_cmd cp -r ./authentik /tmp/bunkerweb-plugins/authentik/bw-data/plugins
# BunkerWeb runs as uid 101 and only needs to READ the mounted plugin. Prefer the
# canonical chown; fall back to world-readable when passwordless sudo isn't available.
if sudo -n chown -R 101:101 /tmp/bunkerweb-plugins/authentik/bw-data 2>/dev/null ; then
	echo "ℹ️ chowned plugin data to 101:101"
else
	echo "ℹ️ sudo unavailable, making plugin data world-readable instead"
	do_and_check_cmd chmod -R a+rX /tmp/bunkerweb-plugins/authentik/bw-data
fi

# Copy compose + mock outpost config
do_and_check_cmd cp .tests/authentik/docker-compose.yml /tmp/bunkerweb-plugins/authentik
do_and_check_cmd cp .tests/authentik/mock-outpost.conf /tmp/bunkerweb-plugins/authentik

# Identity for the TLS outpost vhost (issue #220). Self-signed is enough: the site
# under test runs with AUTHENTIK_SSL_VERIFY=no so the assertion is about SNI alone.
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/authentik/certs
do_and_check_cmd openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
	-keyout /tmp/bunkerweb-plugins/authentik/certs/server.key \
	-out /tmp/bunkerweb-plugins/authentik/certs/server.crt \
	-subj "/CN=tls-outpost" -addext "subjectAltName=DNS:tls-outpost"
do_and_check_cmd chmod a+r /tmp/bunkerweb-plugins/authentik/certs/server.key /tmp/bunkerweb-plugins/authentik/certs/server.crt

# Edit compose to use the locally built :tests images
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/authentik/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/authentik/docker-compose.yml

# Do the tests
cd /tmp/bunkerweb-plugins/authentik || exit 1
echo "ℹ️ Running compose ..."
do_and_check_cmd docker compose up --build -d

# Wait until the plugin is LIVE: while BunkerWeb is still applying config it serves a
# 200 "Generating..." page and the plugin is inactive. An unauthenticated request only
# becomes a 302 (gated) once config is applied -> use that as the readiness signal.
echo "ℹ️ Waiting for BW (plugin live) ..."
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	code="$(docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" -H "Host: app.example.com" http://bunkerweb:8080 2>/dev/null)"
	if [ "$code" = "302" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 2
done
if [ "$success" = "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: BunkerWeb / authentik plugin never became active"
	exit 1
fi

fail=0

# T1: unauthenticated -> 302 to the outpost sign-in
echo "ℹ️ T1: unauthenticated request is redirected to the outpost ..."
loc="$(docker compose exec -T client curl -s -D - -o /dev/null -H "Host: app.example.com" http://bunkerweb:8080 | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
if echo "$loc" | grep -q "/outpost.goauthentik.io/start?rd=" ; then
	echo "✔️ T1 ok ($loc)"
else
	echo "❌ T1 failed (Location: $loc)" ; fail=1
fi

# T2: authenticated -> 200 and identity header forwarded upstream (PASS=yes)
echo "ℹ️ T2: authenticated request reaches upstream with identity header ..."
body="$(docker compose exec -T client curl -s -H "Host: app.example.com" -b "mock_session=valid" http://bunkerweb:8080)"
if echo "$body" | grep -qi '"x-authentik-username": *"alice"' ; then
	echo "✔️ T2 ok"
else
	echo "❌ T2 failed" ; fail=1
fi

# T3: spoofed X-authentik-* are stripped (security); only Authentik's values survive
echo "ℹ️ T3: spoofed identity headers are stripped ..."
body="$(docker compose exec -T client curl -s -H "Host: app.example.com" -b "mock_session=valid" -H "X-authentik-username: hacker" -H "X-authentik-uid: 0" http://bunkerweb:8080)"
if echo "$body" | grep -qi '"x-authentik-username": *"alice"' \
	&& ! echo "$body" | grep -qi '"x-authentik-username": *"hacker"' \
	&& ! echo "$body" | grep -qi '"x-authentik-uid"' ; then
	echo "✔️ T3 ok (spoof stripped)"
else
	echo "❌ T3 failed (spoof not stripped)" ; fail=1
fi

# T4: PASS=no site strips spoofed identity headers and forwards none
echo "ℹ️ T4: PASS=no site forwards no identity header ..."
body="$(docker compose exec -T client curl -s -H "Host: noheaders.example.com" -b "mock_session=valid" -H "X-authentik-username: hacker" http://bunkerweb:8080)"
if ! echo "$body" | grep -qi "x-authentik-username" ; then
	echo "✔️ T4 ok"
else
	echo "❌ T4 failed (identity header reached upstream)" ; fail=1
fi

# T5: outpost path is proxied (not gated)
echo "ℹ️ T5: outpost path is proxied to the outpost ..."
body="$(docker compose exec -T client curl -s -H "Host: app.example.com" http://bunkerweb:8080/outpost.goauthentik.io/start)"
if echo "$body" | grep -q "MOCK AUTHENTIK OUTPOST" ; then
	echo "✔️ T5 ok"
else
	echo "❌ T5 failed" ; fail=1
fi

# T6: trailing-slash AUTHENTIK_URL still proxies the outpost (rstrip fix)
echo "ℹ️ T6: trailing-slash AUTHENTIK_URL still proxies ..."
body="$(docker compose exec -T client curl -s -H "Host: noheaders.example.com" http://bunkerweb:8080/outpost.goauthentik.io/start)"
if echo "$body" | grep -q "MOCK AUTHENTIK OUTPOST" ; then
	echo "✔️ T6 ok"
else
	echo "❌ T6 failed (trailing-slash URL broke the outpost proxy)" ; fail=1
fi

# T7: HTTPS outpost behind an SNI-only front is reachable (issue #220). Without
# `proxy_ssl_server_name on` the handshake is rejected and nginx answers 502.
echo "ℹ️ T7: HTTPS outpost behind an SNI-only front is proxied ..."
body="$(docker compose exec -T client curl -s -H "Host: tls.example.com" http://bunkerweb:8080/outpost.goauthentik.io/start)"
if echo "$body" | grep -q "MOCK AUTHENTIK OUTPOST" ; then
	echo "✔️ T7 ok"
else
	echo "❌ T7 failed (SNI not sent to the outpost: $body)" ; fail=1
fi

# T8: the gated site behind that same HTTPS outpost still redirects (Lua path).
echo "ℹ️ T8: TLS outpost site redirects unauthenticated requests ..."
loc="$(docker compose exec -T client curl -s -D - -o /dev/null -H "Host: tls.example.com" http://bunkerweb:8080 | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
if echo "$loc" | grep -q "/outpost.goauthentik.io/start?rd=" ; then
	echo "✔️ T8 ok ($loc)"
else
	echo "❌ T8 failed (Location: $loc)" ; fail=1
fi

if [ "$fail" -ne 0 ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Authentik tests failed"
	exit 1
fi

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi

docker compose down -v
echo "✔️ Authentik tests succeeded"
