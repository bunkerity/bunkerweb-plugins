#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting VirusTotal tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/virustotal/bw-data/plugins
do_and_check_cmd cp -r ./virustotal /tmp/bunkerweb-plugins/virustotal/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/virustotal/bw-data

# Copy compose + mock VT API config
do_and_check_cmd cp .tests/virustotal/docker-compose.yml /tmp/bunkerweb-plugins/virustotal
do_and_check_cmd cp .tests/virustotal/vt-mock.conf /tmp/bunkerweb-plugins/virustotal

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml

# The compose points the plugin at a local mock VT API, so no real key is needed.
# To exercise the real API locally instead, edit docker-compose.yml and set
# VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3 + a real VIRUSTOTAL_API_KEY.

# Download EICAR file
do_and_check_cmd wget -O /tmp/bunkerweb-plugins/virustotal/eicar.com https://secure.eicar.org/eicar.com

# Do the tests
cd /tmp/bunkerweb-plugins/virustotal || exit 1
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
	ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/virustotal/eicar.com" http://localhost)"
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

# Assert the plugin actually queried the mock VT API for the EICAR hash
# (proves the 403 came from VirusTotal, not some other deny).
echo "ℹ️ Checking the mock VT API was queried ..."
if ! docker compose logs mock 2>/dev/null | grep -F "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" >/dev/null 2>&1 ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: plugin never queried the mock VT API for the EICAR hash"
	exit 1
fi

# A clean file must pass through (mock returns 404 = not found on VT = clean)
echo "ℹ️ Testing that a clean file passes ..."
printf 'just a clean file\n' > /tmp/bunkerweb-plugins/virustotal/clean.txt
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/virustotal/clean.txt" http://localhost)"
if [ "$code" != "200" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: clean file should pass (got $code, expected 200)"
	exit 1
fi

# A malicious IP must be denied (real-ip trusts the X-Forwarded-For we send)
echo "ℹ️ Testing that a malicious IP is denied ..."
code="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" -H "X-Forwarded-For: 1.2.3.4" http://localhost/)"
if [ "$code" != "403" ] ; then
	docker compose logs
	docker compose down -v
	echo "❌ Error: malicious IP should be denied (got $code, expected 403)"
	exit 1
fi

if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ VirusTotal tests done"
