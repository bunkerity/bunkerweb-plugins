#!/bin/bash

. .tests/utils.sh

echo "ℹ️ Starting Coraza tests ..."

# Create working directory
if [ -d /tmp/bunkerweb-plugins ] ; then
	do_and_check_cmd sudo rm -rf /tmp/bunkerweb-plugins
fi
do_and_check_cmd mkdir -p /tmp/bunkerweb-plugins/coraza/bw-data/plugins
do_and_check_cmd cp -r ./coraza /tmp/bunkerweb-plugins/coraza/bw-data/plugins
do_and_check_cmd sudo chown -R 101:101 /tmp/bunkerweb-plugins/coraza/bw-data

# Copy compose
do_and_check_cmd cp .tests/coraza/docker-compose.yml /tmp/bunkerweb-plugins/coraza

# Edit compose
do_and_check_cmd sed -i "s@bunkerity/bunkerweb:.*\$@bunkerweb:tests@g" /tmp/bunkerweb-plugins/coraza/docker-compose.yml
do_and_check_cmd sed -i "s@bunkerity/bunkerweb-scheduler:.*\$@bunkerweb-scheduler:tests@g" /tmp/bunkerweb-plugins/coraza/docker-compose.yml

# Do the tests
cd /tmp/bunkerweb-plugins/coraza/
do_and_check_cmd docker-compose up -d

# Wait until BW is started
echo "ℹ️ Waiting for BW ..."
success="ko"
retry=0
while [ $retry -lt 60 ] ; do
	ret="$(curl -s -H "Host: www.example.com" http://localhost | grep -i "hello")"
	if [ $? -eq 0 ] && [ "$ret" != "" ] ; then
		success="ok"
		break
	fi
	retry=$(($retry + 1))
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

# Payload in GET arg
echo "ℹ️ Testing with GET payload ..."
success="ko"
ret="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" http://localhost/?id=/etc/passwd)"
if [ $? -eq 0 ] && [ $ret -eq 403 ] ; then
	success="ok"
fi
if [ "$success" == "ko" ] ; then
	docker-compose logs
	docker-compose down -v
	echo "❌ Error did not receive 403 code"
	exit 1
fi

# Payload in GET arg
echo "ℹ️ Testing with GET payload ..."
success="ko"
ret="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: www.example.com" http://localhost/ -d "id=/etc/passwd")"
if [ $? -eq 0 ] && [ $ret -eq 403 ] ; then
	success="ok"
fi
if [ "$success" == "ko" ] ; then
	docker-compose logs
	docker-compose down -v
	echo "❌ Error did not receive 403 code"
	exit 1
fi

# We're done
if [ "$1" = "verbose" ] ; then
	docker-compose logs
fi
docker-compose down -v

echo "ℹ️ Coraza tests done"