#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting Coraza tests ..."

# Create working directory (plugin data may be owned by uid 101 from a prior run, so
# prefer sudo when available — but fall back to a plain rm for sudo-less local runs).
if [ -d /tmp/bunkerweb-plugins ] ; then
	sudo -n rm -rf /tmp/bunkerweb-plugins 2>/dev/null || do_and_check_cmd rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/coraza/bw-data/plugins
do_and_check_cmd cp -r ./coraza /tmp/bunkerweb-plugins/coraza/bw-data/plugins
# BunkerWeb runs as uid 101 and only needs to READ the mounted plugin. Prefer the
# canonical chown; fall back to world-readable when passwordless sudo isn't available.
if sudo -n chown -R 101:101 /tmp/bunkerweb-plugins/coraza/bw-data 2>/dev/null ; then
	echo "ℹ️ chowned plugin data to 101:101"
else
	echo "ℹ️ sudo unavailable, making plugin data world-readable instead"
	do_and_check_cmd chmod -R a+rX /tmp/bunkerweb-plugins/coraza/bw-data
fi
do_and_check_cmd cp -r ./coraza/api /tmp/bunkerweb-plugins/coraza

# Copy compose
do_and_check_cmd cp .tests/coraza/docker-compose.yml /tmp/bunkerweb-plugins/coraza

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/coraza/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/coraza/docker-compose.yml

# Every assertion is driven from a container on the service network rather than a
# published host port: the suite then needs nothing from the host, can run beside the
# other suites, and cannot fail on an "address already in use" that has nothing to do
# with Coraza.
http_code() {
	docker compose exec -T client curl -s -o /dev/null -w "%{http_code}" \
		-H "Host: www.example.com" "$@" 2>/dev/null
}

# Do the tests
cd /tmp/bunkerweb-plugins/coraza/ || exit 1
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

# Payload in GET arg
echo "ℹ️ Testing with GET payload ..."
success="ko"
ret="$(http_code "http://bunkerweb:8080/?id=/etc/passwd")"
# shellcheck disable=SC2181
if [ $? -eq 0 ] && [ "$ret" -eq 403 ] ; then
	success="ok"
fi
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error did not receive 403 code"
	exit 1
fi

# Payload in POST arg
echo "ℹ️ Testing with POST payload ..."
success="ko"
ret="$(http_code -X POST "http://bunkerweb:8080/" -d 'id=/etc/passwd')"
# shellcheck disable=SC2181
if [ $? -eq 0 ] && [ "$ret" -eq 403 ] ; then
	success="ok"
fi
if [ "$success" == "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error did not receive 403 code"
	exit 1
fi

# Scanner User-Agent (CRS 913xxx, request-headers phase): a different rule family
# than the LFI args above, widening coverage to header inspection.
echo "ℹ️ Testing with a scanner User-Agent ..."
ret="$(http_code -H "User-Agent: sqlmap/1.4.7" "http://bunkerweb:8080/")"
if [ "$ret" != "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: scanner User-Agent should be blocked (got $ret, expected 403)"
	exit 1
fi

# A benign request with a normal query arg must pass (no false positive -> 200).
echo "ℹ️ Testing that a benign request passes ..."
ret="$(http_code "http://bunkerweb:8080/?q=hello-world")"
if [ "$ret" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: benign request should pass (got $ret, expected 200)"
	exit 1
fi

# We're done
if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ Coraza tests done"
