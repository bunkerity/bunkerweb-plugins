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

# Copy compose
do_and_check_cmd cp .tests/virustotal/docker-compose.yml /tmp/bunkerweb-plugins/virustotal

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml
do_and_check_cmd sed -i "s@%VTKEY%@${VIRUSTOTAL_API_KEY}@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml

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
if [ "$1" = "verbose" ] ; then
	docker compose logs
fi
docker compose down -v

echo "ℹ️ VirusTotal tests done"
