#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Notifier (discord/slack/webhook) tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/notifier/bw-data/plugins

# Copy all three notifier plugins
do_and_check_cmd cp -r ./discord /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd cp -r ./slack /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd cp -r ./webhook /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/notifier/bw-data

# Copy compose
do_and_check_cmd cp .tests/notifier/docker-compose.yml /tmp/bunkerweb-plugins/notifier

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/notifier/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/notifier/docker-compose.yml

# Do the tests
cd /tmp/bunkerweb-plugins/notifier || exit 1
echo "ℹ️ Running compose ..."
do_and_check_cmd docker compose up --build -d

# Wait until BW is started (any vhost reverse-proxies to hello). This is a
# 3-site multisite stack, so allow the same generous budget as authentik (240s).
echo "ℹ️ Waiting for BW ..."
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -H "Host: discord.example.com" http://localhost | grep -i "hello")"
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] && [ "$ret" != "" ] ; then
		success="ok"
		break
	fi
	retry=$((retry + 1))
	sleep 2
done

if [ "$success" = "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: BunkerWeb never became ready"
	exit 1
fi

# For each plugin: provoke a deny (403), then assert its async POST reached the
# mock. The POST is fired from ngx.timer.at AFTER the 403 is returned, so we poll
# the mock logs instead of inspecting the curl response.
fail=0
for plugin in discord slack webhook ; do
	site="${plugin}.example.com"
	echo "ℹ️ [$plugin] provoking deny on http://$site/blocked ..."

	code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $site" http://localhost/blocked)"
	if [ "$code" != "403" ] ; then
		echo "❌ [$plugin] expected 403 on /blocked, got $code"
		fail=1
		continue
	fi
	echo "✔️ [$plugin] got 403 (deny triggered)"

	found="ko"
	retry=0
	while [ $retry -lt 60 ] ; do
		if docker compose logs mock 2>/dev/null | grep -F "/$plugin" >/dev/null 2>&1 ; then
			found="ok"
			break
		fi
		retry=$((retry + 1))
		sleep 1
	done

	if [ "$found" = "ok" ] ; then
		echo "✔️ [$plugin] async POST received by mock (path /$plugin)"
	else
		echo "❌ [$plugin] mock never received the POST (timeout 60s)"
		fail=1
	fi
done

# Cross-check that the denied-request payload (not a /ping test) was sent.
if ! docker compose logs mock 2>/dev/null | grep -F "Denied request for IP" >/dev/null 2>&1 ; then
	echo "❌ mock logs never contained a denied-request payload"
	fail=1
fi

if [ "$fail" -ne 0 ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Notifier tests failed"
	exit 1
fi

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ Notifier tests done"
