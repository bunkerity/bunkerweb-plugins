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

if [ "$VIRUSTOTAL_API_KEY" == "" ] ; then
	echo "❌ Error VIRUSTOTAL_API_KEY is not set"
	exit 1
fi

echo "ℹ️ Starting VirusTotal API tests ..."

# Create working directory
if [ ! -d /tmp/bunkerweb-virustotal ] ; then
	do_and_check_cmd mkdir /tmp/bunkerweb-virustotal
fi

# Download EICAR
if [ -f /tmp/bunkerweb-virustotal/eicar.com ] ; then
	do_and_check_cmd rm -f /tmp/bunkerweb-virustotal/eicar.com
fi
do_and_check_cmd wget -O /tmp/bunkerweb-virustotal/eicar.com https://secure.eicar.org/eicar.com

# Copy compose
do_and_check_cmd cp ./tests/docker-compose.test.yml /tmp/bunkerweb-virustotal/docker-compose.yml
do_and_check_cmd sed -i "s@%VTKEY%@${VIRUSTOTAL_API_KEY}@g" /tmp/bunkerweb-virustotal/docker-compose.yml

# Do the test
current_dir="${PWD}"
cd /tmp/bunkerweb-virustotal/
do_and_check_cmd docker-compose up -d
success="ko"
retry=0
echo "ℹ️ Testing the file upload..."
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-virustotal/eicar.com" http://localhost:8000/check)"
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
	echo "❌ Error did not find virus"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi

echo "ℹ️ File upload test done"

retry=0
echo "ℹ️ Testing the IP upload..."
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -X POST -H "Host: www.example.com" -H "Content-Type: application/json" -d '{"ip": "0.0.0.0"}' http://localhost:8000/check_ip)"
	check="$(echo "$ret" | grep "\"success\":true")"
	if [ $? -eq 0 ] && [ "$check" != "" ] ; then
		check="$(echo "$ret" | grep "\"detected\":false")"
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
	echo "❌ Error when checking IP"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi

echo "ℹ️ IP upload test done"

# We're done
docker-compose down -v
cd "$current_dir"

echo "ℹ️ VirusTotal API tests done"