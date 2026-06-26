#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Authentik tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/authentik/bw-data/plugins
do_and_check_cmd cp -r ./authentik /tmp/bunkerweb-plugins/authentik/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/authentik/bw-data

# Copy compose + mock outpost config
do_and_check_cmd cp .tests/authentik/docker-compose.yml /tmp/bunkerweb-plugins/authentik
do_and_check_cmd cp .tests/authentik/mock-outpost.conf /tmp/bunkerweb-plugins/authentik

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
	code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: app.example.com" http://localhost 2>/dev/null)"
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
loc="$(curl -s -D - -o /dev/null -H "Host: app.example.com" http://localhost | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
if echo "$loc" | grep -q "/outpost.goauthentik.io/start?rd=" ; then
	echo "✔️ T1 ok ($loc)"
else
	echo "❌ T1 failed (Location: $loc)" ; fail=1
fi

# T2: authenticated -> 200 and identity header forwarded upstream (PASS=yes)
echo "ℹ️ T2: authenticated request reaches upstream with identity header ..."
body="$(curl -s -H "Host: app.example.com" -b "mock_session=valid" http://localhost)"
if echo "$body" | grep -qi '"x-authentik-username": *"alice"' ; then
	echo "✔️ T2 ok"
else
	echo "❌ T2 failed" ; fail=1
fi

# T3: spoofed X-authentik-* are stripped (security); only Authentik's values survive
echo "ℹ️ T3: spoofed identity headers are stripped ..."
body="$(curl -s -H "Host: app.example.com" -b "mock_session=valid" -H "X-authentik-username: hacker" -H "X-authentik-uid: 0" http://localhost)"
if echo "$body" | grep -qi '"x-authentik-username": *"alice"' \
	&& ! echo "$body" | grep -qi '"x-authentik-username": *"hacker"' \
	&& ! echo "$body" | grep -qi '"x-authentik-uid"' ; then
	echo "✔️ T3 ok (spoof stripped)"
else
	echo "❌ T3 failed (spoof not stripped)" ; fail=1
fi

# T4: PASS=no site strips spoofed identity headers and forwards none
echo "ℹ️ T4: PASS=no site forwards no identity header ..."
body="$(curl -s -H "Host: noheaders.example.com" -b "mock_session=valid" -H "X-authentik-username: hacker" http://localhost)"
if ! echo "$body" | grep -qi "x-authentik-username" ; then
	echo "✔️ T4 ok"
else
	echo "❌ T4 failed (identity header reached upstream)" ; fail=1
fi

# T5: outpost path is proxied (not gated)
echo "ℹ️ T5: outpost path is proxied to the outpost ..."
body="$(curl -s -H "Host: app.example.com" http://localhost/outpost.goauthentik.io/start)"
if echo "$body" | grep -q "MOCK AUTHENTIK OUTPOST" ; then
	echo "✔️ T5 ok"
else
	echo "❌ T5 failed" ; fail=1
fi

# T6: trailing-slash AUTHENTIK_URL still proxies the outpost (rstrip fix)
echo "ℹ️ T6: trailing-slash AUTHENTIK_URL still proxies ..."
body="$(curl -s -H "Host: noheaders.example.com" http://localhost/outpost.goauthentik.io/start)"
if echo "$body" | grep -q "MOCK AUTHENTIK OUTPOST" ; then
	echo "✔️ T6 ok"
else
	echo "❌ T6 failed (trailing-slash URL broke the outpost proxy)" ; fail=1
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
