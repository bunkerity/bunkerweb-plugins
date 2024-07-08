#!/bin/bash

if [ ! -f /var/run/coraza/coraza.pid ] ; then
	exit 1
fi

check="$(curl -s -H "Host: healthcheck.bw-coraza.io" http://127.0.0.1:8080/ping 2>&1)"
# shellcheck disable=SC2181
if [ $? -ne 0 ] || [ "$check" != '{"pong":"ok"}' ] ; then
	exit 1
fi

exit 0
