#!/bin/bash

function do_and_check_cmd() {
	if [ "$CHANGE_DIR" != "" ] ; then
		cd "$CHANGE_DIR"
	fi
	output=$("$@" 2>&1)
	ret="$?"
	if [ $ret -ne 0 ] ; then
		echo "❌ Error from command : $*"
		echo "$output"
		exit $ret
	fi
	#echo $output
	return 0
}

echo "ℹ️ Starting ClamAV API tests ..."

# Create working directory
if [ ! -d /tmp/bunkerweb-clamav ] ; then
	do_and_check_cmd mkdir /tmp/bunkerweb-clamav
fi

# Download EICAR
if [ -f /tmp/bunkerweb-clamav/eicar.com ] ; then
	do_and_check_cmd rm -f /tmp/bunkerweb-clamav/eicar.com
fi
do_and_check_cmd wget -O /tmp/bunkerweb-clamav/eicar.com https://secure.eicar.org/eicar.com

# Copy compose
do_and_check_cmd cp ./tests/docker-compose.test.yml /tmp/bunkerweb-clamav/docker-compose.yml

# Do the test
current_dir="${PWD}"
cd /tmp/bunkerweb-clamav/
do_and_check_cmd docker-compose up -d
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

# We're done
if [ $retry -eq 120 ] ; then
	echo "❌ Error timeout after 120s"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
if [ "$success" == "ko" ] ; then
	echo "❌ Error did not find virus"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
docker-compose down -v
cd "$current_dir"

echo "ℹ️ ClamAV API tests done"