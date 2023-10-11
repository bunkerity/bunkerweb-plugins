#!/bin/bash

# shellcheck disable=SC1091
. .tests/utils.sh

echo "ℹ️ Pulling images ..."
do_and_check_cmd docker pull "bunkerity/bunkerweb:$1"
do_and_check_cmd docker pull "bunkerity/bunkerweb-scheduler:$1"

echo "ℹ️ Tagging images ..."
do_and_check_cmd docker tag "bunkerity/bunkerweb:$1" "bunkerweb:tests"
do_and_check_cmd docker tag "bunkerity/bunkerweb-scheduler:$1" "bunkerweb-scheduler:tests"
