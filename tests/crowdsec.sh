#!/bin/bash

. ./tests/utils.sh

echo "ℹ️ Starting CrowdSec tests ..."

# Create working directory
if [ ! -d /tmp/bunkerweb-virustotal/virustotal ] ; then
	do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/virustotal
fi
if [ ! -d /tmp/bunkerweb-plugins/virustotal/bw-data/plugins ] ; then
	do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/virustotal/bw-data/plugins
fi
if [ -d /tmp/bunkerweb-plugins/virustotal/bw-data/plugins/virustotal ] ; then
	do_and_check_cmd rm -rf /tmp/bunkerweb-plugins/virustotal/bw-data/plugins/virustotal
fi
do_and_check_cmd cp -r ./virustotal /tmp/bunkerweb-plugins/virustotal/bw-data/plugins
do_and_check_cmd sudo chmod -R 777 /tmp/bunkerweb-plugins/virustotal/bw-data

# Copy compose
if [ -f /tmp/bunkerweb-plugins/virustotal/docker-compose.yml ] ; then
	do_and_check_cmd rm -f /tmp/bunkerweb-plugins/virustotal/docker-compose.yml
fi
do_and_check_cmd cp ./virustotal/docker-compose.yml /tmp/bunkerweb-plugins/virustotal

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerity/bunkerweb:${BW_TAG}@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml
do_and_check_cmd sed -i "s@%VTKEY%@${VIRUSTOTAL_API_KEY}@g" /tmp/bunkerweb-plugins/virustotal/docker-compose.yml

# Copy configs
do_and_check_cmd cp ./crowdsec/acquis.yml /tmp/bunkerweb-plugins/crowdsec
do_and_check_cmd cp ./crowdsec/syslog-ng.conf /tmp/bunkerweb-plugins/crowdsec

# Wait until BW is started
success="ko"
retry=0
while [ $retry -lt 120 ] ; do
	ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/virustotal/eicar.com" http://localhost)"
	if [ $? -eq 0 ] && [ $ret -eq 200 ] ; then
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
	echo "❌ Error did not receive 200 code"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi

# Run basic attack with dirb
do_and_check_cmd sudo apt install -y dirb
dirb -H "Host: www.example.com" -H "Header: LegitOne" http://localhost

# Expect a 403
success="ko"
ret="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Host: www.example.com" -F "file=@/tmp/bunkerweb-plugins/virustotal/eicar.com" http://localhost)"
if [ $? -eq 0 ] && [ $ret -eq 403 ] ; then
	success="ok"
	break
fi

# We're done
if [ "$success" == "ko" ] ; then
	echo "❌ Error did not receive 403 code"
	docker-compose logs
	docker-compose down -v
	cd "$current_dir"
	exit 1
fi
docker-compose down -v
cd "$current_dir"

echo "ℹ️ CrowdSec tests done"