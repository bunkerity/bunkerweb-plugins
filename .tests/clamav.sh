#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting ClamAV tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/clamav/bw-data/plugins
do_and_check_cmd cp -r ./clamav /tmp/bunkerweb-plugins/clamav/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/clamav/bw-data

# Copy compose
do_and_check_cmd cp .tests/clamav/docker-compose.yml /tmp/bunkerweb-plugins/clamav

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/clamav/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/clamav/docker-compose.yml

# Download EICAR file
do_and_check_cmd wget -O /tmp/bunkerweb-plugins/clamav/eicar.com https://secure.eicar.org/eicar.com

# Do the tests
cd /tmp/bunkerweb-plugins/clamav || exit 1
echo "ℹ️ Running compose ..."
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

# Now check if BunkerWeb is giving a 403
echo "ℹ️ Testing BW ..."
success="ko"
retry=0
while [ $retry -lt 60 ] ; do
	ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/clamav/eicar.com" http://localhost)"
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

# A clean file must NOT be denied by ClamAV. The hello upstream only accepts GET,
# so a clean multipart POST reaches it and comes back 405 (method). Accept any 2xx
# or non-403 4xx, but fail on 403 (denied) and on 5xx/000 (a crash or fail-closed
# regression must not hide behind "not 403").
echo "ℹ️ Testing that a clean file is not blocked ..."
printf 'just a clean file\n' > /tmp/bunkerweb-plugins/clamav/clean.txt
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/clamav/clean.txt" http://localhost)"
case "$code" in
403) clean_err="should not be denied by ClamAV" ;;
000 | 5??) clean_err="caused an upstream error/crash" ;;
*) clean_err="" ;;
esac
if [ -n "$clean_err" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: clean file $clean_err (got $code)"
	exit 1
fi

# Upload EICAR a second time: it must still be denied. This re-hits the same
# SHA-512, exercising the result cache (is_in_cache) rather than a fresh scan.
echo "ℹ️ Testing repeated EICAR is still denied (cache path) ..."
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/clamav/eicar.com" http://localhost)"
if [ "$code" != "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: repeated EICAR should stay denied (got $code, expected 403)"
	exit 1
fi

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ ClamAV tests done"
