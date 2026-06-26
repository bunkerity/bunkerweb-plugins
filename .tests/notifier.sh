#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Notifier (discord/slack/webhook/matrix) tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/notifier/bw-data/plugins

# Copy all four notifier plugins
do_and_check_cmd cp -r ./discord /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd cp -r ./slack /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd cp -r ./webhook /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd cp -r ./matrix /tmp/bunkerweb-plugins/notifier/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/notifier/bw-data

# Copy compose + the rate-limit mock config
do_and_check_cmd cp .tests/notifier/docker-compose.yml /tmp/bunkerweb-plugins/notifier
do_and_check_cmd cp .tests/notifier/ratelimit.conf /tmp/bunkerweb-plugins/notifier

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

fail=0

# Negative control: a request that is NOT denied must NOT notify. Hit a benign
# URL (proxied to hello, 200) and confirm no POST reaches the mock. Runs BEFORE
# any deny so the echo mock log is still empty of notifier POSTs.
echo "ℹ️ Negative test: a non-denied request must not notify ..."
code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: slack.example.com" http://localhost/)"
if [ "$code" != "200" ] ; then
	echo "❌ benign request to slack vhost expected 200, got $code"
	fail=1
fi
sleep 3
if docker compose logs mock 2>/dev/null | grep -qF "/slack" ; then
	echo "❌ benign request triggered a notifier POST"
	fail=1
else
	echo "✔️ benign request did not notify"
fi

# discord/slack/webhook log() fire on a DENIED request, then POST asynchronously
# from ngx.timer.at AFTER the 403 is returned — so we poll the mock logs.

# slack/webhook post to the echo mock; assert path + payload-shape key.
check_echo_notifier() {
	# $1=plugin  $2=path needle  $3=payload-shape needle
	local plugin="$1" path="$2" shape="$3" site found="ko" code r=0
	site="${plugin}.example.com"
	echo "ℹ️ [$plugin] provoking deny on http://$site/blocked ..."
	# Send a credential header: the notifier must redact it (see redact_header in
	# each plugin's *_helpers.lua) before forwarding the request to the sink.
	code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $site" -H "Cookie: redactme-supersecret" http://localhost/blocked)"
	if [ "$code" != "403" ] ; then
		echo "❌ [$plugin] expected 403 on /blocked, got $code"
		fail=1
		return
	fi
	while [ $r -lt 60 ] ; do
		if docker compose logs mock 2>/dev/null | grep -qF "$path" ; then
			found="ok"
			break
		fi
		r=$((r + 1))
		sleep 1
	done
	if [ "$found" != "ok" ] ; then
		echo "❌ [$plugin] mock never received the POST ($path)"
		fail=1
		return
	fi
	echo "✔️ [$plugin] async POST received ($path)"
	if docker compose logs mock 2>/dev/null | grep -qF "$shape" ; then
		echo "✔️ [$plugin] payload shape ok ($shape)"
	else
		echo "❌ [$plugin] payload missing expected key $shape"
		fail=1
	fi
}

check_echo_notifier slack /slack '"text"'
check_echo_notifier webhook /webhook '"content"'
# matrix posts a PUT to the Matrix "send message" endpoint on the same echo mock.
# Assert the room-send path was hit and the org.matrix.custom.html payload shape.
check_echo_notifier matrix "/_matrix/client" '"formatted_body"'

# discord posts to the rate-limit mock (429 + Retry-After, then 200). With
# DISCORD_RETRY_IF_LIMITED=yes the plugin retries once, so the mock should see
# two requests to /discord.
echo "ℹ️ [discord] provoking deny (retry path) ..."
code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: discord.example.com" -H "Cookie: redactme-supersecret" http://localhost/blocked)"
if [ "$code" != "403" ] ; then
	echo "❌ [discord] expected 403 on /blocked, got $code"
	fail=1
fi
n=0
retry=0
while [ $retry -lt 60 ] ; do
	n="$(docker compose logs ratelimit 2>/dev/null | grep -c "uri=/discord")"
	if [ "$n" -ge 2 ] ; then
		break
	fi
	retry=$((retry + 1))
	sleep 1
done
if [ "$n" -ge 2 ] ; then
	echo "✔️ [discord] retry fired after 429 ($n requests to /discord)"
else
	echo "❌ [discord] retry did not fire (only $n request(s) to /discord)"
	fail=1
fi
if docker compose logs ratelimit 2>/dev/null | grep -qF '"username"' \
	&& docker compose logs ratelimit 2>/dev/null | grep -qF "Denied request for IP" ; then
	echo "✔️ [discord] payload shape ok (username/embeds, denied payload)"
else
	echo "❌ [discord] payload shape or denied-content missing"
	fail=1
fi

# discord posts to the ratelimit sink (not the echo mock), so assert its
# header redaction separately: the Cookie sent on the deny must be [REDACTED].
if docker compose logs ratelimit 2>/dev/null | grep -qF "redactme-supersecret" ; then
	echo "❌ [discord] sensitive header value leaked to the notifier payload"
	fail=1
elif docker compose logs ratelimit 2>/dev/null | grep -qF "[REDACTED]" ; then
	echo "✔️ [discord] sensitive header redacted in the notifier payload"
else
	echo "❌ [discord] expected [REDACTED] marker missing from the notifier payload"
	fail=1
fi

# Cross-check the denied payload reached the echo mock (slack/webhook).
if ! docker compose logs mock 2>/dev/null | grep -qF "Denied request for IP" ; then
	echo "❌ echo mock never received a denied-request payload"
	fail=1
fi

# Sensitive-header redaction: the Cookie value sent on the denied requests must
# never reach the notification sink — it is replaced by [REDACTED]. This guards
# the redact_header() logic shared by all notifier plugins (slack/webhook/matrix
# post their header table to the echo mock).
if docker compose logs mock 2>/dev/null | grep -qF "redactme-supersecret" ; then
	echo "❌ sensitive header value leaked to the notifier payload"
	fail=1
elif docker compose logs mock 2>/dev/null | grep -qF "[REDACTED]" ; then
	echo "✔️ sensitive header redacted in the notifier payload"
else
	echo "❌ expected [REDACTED] marker missing from the notifier payload"
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
