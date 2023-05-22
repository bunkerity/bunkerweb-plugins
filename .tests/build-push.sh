#!/bin/bash

. .tests/utils.sh

echo "ℹ️ Build bunkerweb-clamav ..."
CHANGE_DIR="./clamav/api" do_and_check_cmd docker build -t bunkerity/bunkerweb-clamav:latest .

echo "ℹ️ Build bunkerweb-virustotal ..."
CHANGE_DIR="./virustotal/api" do_and_check_cmd docker build -t bunkerity/bunkerweb-virustotal:latest .

echo "ℹ️ Push bunkerweb-clamav ..."
do_and_check_cmd docker push bunkerity/bunkerweb-clamav:latest

echo "ℹ️ Push bunkerweb-virustotal ..."
do_and_check_cmd docker push bunkerity/bunkerweb-virustotal:latest