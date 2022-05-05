#!/bin/bash

. ./tests/utils.sh

echo "ℹ️ Starting ClamAV tests ..."

# Create working directory
if [ ! -d /tmp/bunkerweb-plugins/clamav ] ; then
	do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/clamav
fi
if [ ! -d /tmp/bunkerweb-plugins/clamav/bw-data/plugins ] ; then
	do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/clamav/bw-data/plugins
fi
if [ -d /tmp/bunkerweb-plugins/clamav/bw-data/plugins/clamav ] ; then
	do_and_check_cmd rm -rf /tmp/bunkerweb-plugins/clamav/bw-data/plugins/clamav
fi
do_and_check_cmd cp -r ./clamav /tmp/bunkerweb-plugins/clamav/bw-data/plugins
do_and_check_cmd sudo chmod -R 777 /tmp/bunkerweb-plugins/clamav/bw-data

# Copy compose
if [ -f /tmp/bunkerweb-plugins/clamav/docker-compose.yml ] ; then
	do_and_check_cmd rm -f /tmp/bunkerweb-plugins/clamav/docker-compose.yml
fi
do_and_check_cmd cp ./clamav/docker-compose.yml /tmp/bunkerweb-plugins/clamav

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*$@bunkerity/bunkerweb:${BW_TAG}@g" /tmp/bunkerweb-plugins/clamav/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-clamav$@bunkerity/bunkerweb-clamav:${BW_TAG}@g" /tmp/bunkerweb-plugins/clamav/docker-compose.yml

# Download EICAR file
if [ -f /tmp/bunkerweb-plugins/clamav/eicar.com ] ; then
	do_and_check_cmd rm -f /tmp/bunkerweb-plugins/clamav/eicar.com
fi
do_and_check_cmd wget -O /tmp/bunkerweb-plugins/clamav/eicar.com https://secure.eicar.org/eicar.com



# Do the tests
current_dir="${PWD}"
cd /tmp/bunkerweb-plugins/clamav/
do_and_check_cmd docker-compose up -d

# Check that API is working
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-clamav/eicar.com" http://localhost:8000/check)"
	check="$(echo "$ret" | grep "\"success\":true")"
	if [ $? -eq 0 ] && [ "$check" != "" ] ; then
		check="$(echo "$ret" | grep "\"detected\":true")"
		if [ "$check" != "" ] ; then
			success="ok"
		fi
		break
	fi
	retry=$(($retry + 1))
	sleep 1
done
if [ $retry -eq 120 ] ; then
	echo "❌ Error timeout after 120s"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
if [ "$success" == "ko" ] ; then
	echo "❌ Error EICAR not detected"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi

# Now check if BunkerWeb is giving a 403
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/clamav/eicar.com" http://localhost)"
	if [ $? -eq 0 ] && [ $ret -eq 403 ] ; then
		success="ok"
		break
	fi
	retry=$(($retry + 1))
	sleep 1
done

# We're done
if [ $retry -eq 120 ] ; then
	echo "❌ Error timeout after 120s"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
if [ "$success" == "ko" ] ; then
	echo "❌ Error did not receive 403 code"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
docker-compose down -v
cd "$current_dir"

echo "ℹ️ ClamAV tests done"