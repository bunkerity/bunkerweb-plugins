#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Starting CrowdSec $1 tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/crowdsec/bw-data/plugins
do_and_check_cmd cp -r ./crowdsec /tmp/bunkerweb-plugins/crowdsec/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/crowdsec/bw-data

# Copy compose
do_and_check_cmd cp .tests/crowdsec/docker-compose.yml /tmp/bunkerweb-plugins/crowdsec

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/crowdsec/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/crowdsec/docker-compose.yml
if [ $1 == "appsec" ] ; then
	do_and_check_cmd sed -i "s@CROWDSEC_MODE=.*\$@CROWDSEC_MODE=live@g" /tmp/bunkerweb-plugins/crowdsec/docker-compose.yml
	do_and_check_cmd sed -i "s@CROWDSEC_APPSEC_URL=.*\$@CROWDSEC_APPSEC_URL=http://crowdsec:7422@g" /tmp/bunkerweb-plugins/crowdsec/docker-compose.yml
else
	do_and_check_cmd sed -i "s@CROWDSEC_MODE=.*\$@CROWDSEC_MODE=$1@g" /tmp/bunkerweb-plugins/crowdsec/docker-compose.yml
	
fi

# Copy configs
do_and_check_cmd cp .tests/crowdsec/acquis.yaml /tmp/bunkerweb-plugins/crowdsec
do_and_check_cmd cp .tests/crowdsec/appsec.yaml /tmp/bunkerweb-plugins/crowdsec
do_and_check_cmd cp .tests/crowdsec/syslog-ng.conf /tmp/bunkerweb-plugins/crowdsec

# Do the tests
cd /tmp/bunkerweb-plugins/crowdsec/ || exit 1
do_and_check_cmd docker-compose up -d

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
	docker-compose logs
	docker-compose down -v
	echo "❌ Error timeout after 60s"
	exit 1
fi
if [ "$success" == "ko" ] ; then
	docker-compose logs
	docker-compose down -v
	echo "❌ Error did not receive 200 code"
	exit 1
fi


if [ "$1" != "appsec" ] ; then
	# Run basic attack with dirb
	echo "ℹ️ Executing dirb ..."
	do_and_check_cmd sudo apt install -y dirb
	dirb http://localhost -H "Host: www.example.com" -H "User-Agent: LegitOne" -f > /dev/null 2>&1

	# Wait if are in stream mode
	if [ "$1" == "stream" ] ; then
		sleep 20
	fi

	# Expect a 403
	echo "ℹ️ Checking CS ..."
	success="ko"
	ret="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" http://localhost)"
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] && [ "$ret" -eq 403 ] ; then
		success="ok"
	fi
else
	# Send an obvious pattern
	echo "ℹ️ Sending malicious pattern"
	success="ko"
	ret="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" http://localhost/?id=/etc/passwd)"
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] && [ "$ret" -eq 403 ] ; then
		success="ok"
	fi
fi

# We're done
if [ "$success" == "ko" ] ; then
	docker-compose logs
	docker-compose down -v
	echo "❌ Error did not receive 403 code"
	exit 1
fi
if [ "$1" = "verbose" ] ; then
	docker-compose logs
fi
docker-compose down -v

echo "ℹ️ CrowdSec tests done"
