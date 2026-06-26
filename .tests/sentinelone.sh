#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting SentinelOne tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/sentinelone/bw-data/plugins
do_and_check_cmd cp -r ./sentinelone /tmp/bunkerweb-plugins/sentinelone/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/sentinelone/bw-data

# Copy compose + mock SentinelOne API config
do_and_check_cmd cp .tests/sentinelone/docker-compose.yml /tmp/bunkerweb-plugins/sentinelone
do_and_check_cmd cp .tests/sentinelone/s1-mock.conf /tmp/bunkerweb-plugins/sentinelone

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/sentinelone/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/sentinelone/docker-compose.yml

# The compose points the plugin at a local mock SentinelOne API, so no real tenant
# or token is needed. To exercise a real tenant locally instead, edit
# docker-compose.yml and set SENTINELONE_API_URL=https://<console>/web/api/v2.1 +
# a real SENTINELONE_API_TOKEN.

# Download EICAR file
do_and_check_cmd wget -O /tmp/bunkerweb-plugins/sentinelone/eicar.com https://secure.eicar.org/eicar.com

# Compute the EICAR SHA1 the plugin will look up, and bake it into the mock so the
# mock's "malicious" reputation location matches exactly what resty.sha1 produces
# over the uploaded bytes (no hardcoded-hash drift).
EICAR_SHA1="$(sha1sum /tmp/bunkerweb-plugins/sentinelone/eicar.com | cut -d' ' -f1)"
if [ -z "$EICAR_SHA1" ] ; then
	echo "❌ Error: could not compute the EICAR SHA1"
	exit 1
fi
echo "ℹ️ EICAR SHA1 is $EICAR_SHA1"
do_and_check_cmd sed -i "s@__EICAR_SHA1__@${EICAR_SHA1}@g" /tmp/bunkerweb-plugins/sentinelone/s1-mock.conf

# Do the tests
cd /tmp/bunkerweb-plugins/sentinelone || exit 1
do_and_check_cmd docker compose up --build -d

# Wait until BW is started
echo "ℹ️ Waiting for BW ..."
success="ko"
retry=0
while [ $retry -lt 60 ] ; do
	ret="$(curl -s -H "Host: www.example.com" http://localhost | grep -i "hello")"
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

# Now check if BunkerWeb is giving a 403 for the EICAR upload
echo "ℹ️ Testing BW ..."
success="ko"
retry=0
while [ $retry -lt 60 ] ; do
	ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/sentinelone/eicar.com" http://localhost)"
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] && [ "$ret" -eq 403 ] ; then
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
	echo "❌ Error did not receive 403 code"
	exit 1
fi

# Assert the plugin actually queried the mock API for the EICAR hash reputation
# (proves the 403 came from SentinelOne, not some other deny).
echo "ℹ️ Checking the mock SentinelOne API was queried ..."
if ! docker compose logs mock 2>/dev/null | grep -F "/web/api/v2.1/hashes/${EICAR_SHA1}/reputation" >/dev/null 2>&1 ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: plugin never queried the mock API for the EICAR hash reputation"
	exit 1
fi

# A clean file must NOT be denied (mock returns 404 = unknown hash = clean).
# The hello upstream only accepts GET, so the clean multipart POST reaches it and
# comes back 405 (method). Accept any 2xx or non-403 4xx, but fail on 403 (denied)
# and on 5xx/000 (a crash or fail-closed regression must not hide behind "not 403").
echo "ℹ️ Testing that a clean file is not blocked ..."
printf 'just a clean file\n' > /tmp/bunkerweb-plugins/sentinelone/clean.txt
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/sentinelone/clean.txt" http://localhost)"
case "$code" in
403) clean_err="should not be denied by SentinelOne" ;;
000 | 5??) clean_err="caused an upstream error/crash" ;;
*) clean_err="" ;;
esac
if [ -n "$clean_err" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: clean file $clean_err (got $code)"
	exit 1
fi

# A malicious IP must be denied (real-ip trusts the X-Forwarded-For we send). The
# mock returns a matching IOC for 1.2.3.4.
echo "ℹ️ Testing that a malicious IP is denied ..."
code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" -H "X-Forwarded-For: 1.2.3.4" http://localhost/)"
if [ "$code" != "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: malicious IP should be denied (got $code, expected 403)"
	exit 1
fi

# Error paths: a SentinelOne API failure must FAIL OPEN — the request is allowed
# through, never denied (403) and never leaked as a server error (5xx) to the
# client. 5.5.5.5 -> mock returns 500 ; 6.6.6.6 -> mock returns unparsable JSON.
for bad_ip in 5.5.5.5 6.6.6.6 ; do
	echo "ℹ️ Testing fail-open when the API errors for $bad_ip ..."
	code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" -H "X-Forwarded-For: $bad_ip" http://localhost/)"
	if [ "$code" != "200" ] ; then
		docker compose logs
		docker compose down -v
		echo "❌ Error: API failure for $bad_ip should fail open (got $code, expected 200)"
		exit 1
	fi
done

# HTTP/2: the file-scan path uses resty.upload (the raw request socket), which is
# unavailable over HTTP/2 and would crash with a 500. Over a real negotiated HTTP/2
# connection EICAR must still be denied (403) via the buffered fallback. We assert
# %{http_version}=2 so the test can't pass on a silent HTTP/1.1 fallback, and retry
# to let the self-signed cert / TLS listener warm up.
echo "ℹ️ Testing EICAR over HTTP/2 is denied ..."
success="ko"
h2ok="ko"
retry=0
while [ $retry -lt 30 ] ; do
	out="$(curl -s -k --http2 --resolve www.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{http_version}" -X POST -F "file=@/tmp/bunkerweb-plugins/sentinelone/eicar.com" https://www.example.com/)"
	h2_code="${out% *}"
	h2_ver="${out#* }"
	if [ "$h2_ver" = "2" ] ; then
		h2ok="ok"
		if [ "$h2_code" = "403" ] ; then
			success="ok"
			break
		fi
	fi
	retry=$((retry + 1))
	sleep 1
done
if [ "$h2ok" = "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: never negotiated an HTTP/2 connection (TLS/HTTP2 not enabled?)"
	exit 1
fi
if [ "$success" = "ko" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: EICAR over HTTP/2 should be denied (last code $h2_code, expected 403)"
	exit 1
fi

# A FRESH clean file over HTTP/2 (distinct content, never sent over HTTP/1.x, so it
# can't be a cache hit) must not be denied or crash. This proves the buffered path
# does a real cache-miss scan end-to-end: read body -> parse multipart -> SHA-1 ->
# reputation lookup (mock 404 = clean) -> allow.
echo "ℹ️ Testing a fresh clean file over HTTP/2 is not blocked ..."
printf 'fresh clean file over http2\n' > /tmp/bunkerweb-plugins/sentinelone/h2clean.txt
out="$(curl -s -k --http2 --resolve www.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{http_version}" -X POST -F "file=@/tmp/bunkerweb-plugins/sentinelone/h2clean.txt" https://www.example.com/)"
h2_code="${out% *}"
h2_ver="${out#* }"
if [ "$h2_ver" != "2" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: fresh clean file did not negotiate HTTP/2 (got version '$h2_ver')"
	exit 1
fi
case "$h2_code" in
403) clean_err="should not be denied by SentinelOne over HTTP/2" ;;
000 | 5??) clean_err="caused an upstream error/crash over HTTP/2" ;;
*) clean_err="" ;;
esac
if [ -n "$clean_err" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: clean file $clean_err (got $h2_code)"
	exit 1
fi

# A large (256 KB) clean file over HTTP/2 forces the body to spill to nginx's
# client-body temp file (exercising the get_body_file read) and a large multipart
# parse + SHA-1. The mock returns 404 (clean), so it must not be denied/crash.
echo "ℹ️ Testing a large clean file over HTTP/2 (temp-file spill) ..."
dd if=/dev/zero bs=4096 count=64 2>/dev/null | tr '\0' 'A' > /tmp/bunkerweb-plugins/sentinelone/h2big.txt
out="$(curl -s -k --http2 --resolve www.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{http_version}" -X POST -F "file=@/tmp/bunkerweb-plugins/sentinelone/h2big.txt" https://www.example.com/)"
h2_code="${out% *}"
h2_ver="${out#* }"
if [ "$h2_ver" != "2" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: large clean file did not negotiate HTTP/2 (got version '$h2_ver')"
	exit 1
fi
case "$h2_code" in
403) big_err="large clean file should not be denied by SentinelOne over HTTP/2" ;;
000 | 5??) big_err="large clean file caused an upstream error/crash over HTTP/2" ;;
*) big_err="" ;;
esac
if [ -n "$big_err" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: $big_err (got $h2_code)"
	exit 1
fi

# HTTP/3 (best-effort): only when this curl was built with HTTP/3 support. It hits
# the same buffered Lua path as HTTP/2, just over QUIC. Non-fatal if h3 can't be
# negotiated (CI curl/runner often lacks it - Ubuntu's curl is built without HTTP/3,
# and there is no official curl image that ships it); fatal only if h3 IS negotiated
# yet EICAR slips through (a real regression).
if curl --version 2>/dev/null | grep -qi "HTTP3" ; then
	echo "ℹ️ Testing EICAR over HTTP/3 is denied (best-effort) ..."
	out="$(curl -s -k --http3 --resolve www.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{http_version}" -X POST -F "file=@/tmp/bunkerweb-plugins/sentinelone/eicar.com" https://www.example.com/ 2>/dev/null || true)"
	h3_code="${out% *}"
	h3_ver="${out#* }"
	if [ "$h3_ver" = "3" ] && [ "$h3_code" != "403" ] ; then
		docker compose logs
		docker compose down -v
		echo "❌ Error: EICAR over HTTP/3 should be denied (got $h3_code)"
		exit 1
	fi
	if [ "$h3_ver" != "3" ] ; then
		echo "⚠️ Skipped HTTP/3 assertion (best-effort): could not negotiate h3 (curl reported version '$h3_ver')"
	fi
else
	echo "⚠️ Skipped HTTP/3 test (best-effort): curl has no HTTP/3 support"
fi

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ SentinelOne tests done"
