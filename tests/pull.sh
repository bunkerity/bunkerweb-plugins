#!/bin/bash

. ./tests/utils.sh

echo "ℹ️ Pulling images with tag ${BW_TAG} ..."

echo "ℹ️ Pulling BunkerWeb ..."
do_and_check_cmd docker pull "bunkerity/bunkerweb:${BW_TAG}"

echo "ℹ️ Pulling ClamAV ..."
do_and_check_cmd docker pull "bunkerity/bunkerweb-clamav:${BW_TAG}"
do_and_check_cmd docker pull "clamav/clamav:0.104"

echo "ℹ️ Pulling VirusTotal ..."
#do_and_check_cmd docker pull "bunkerity/bunkerweb-virustotal:${BW_TAG}"

echo "ℹ️ Images pulled"