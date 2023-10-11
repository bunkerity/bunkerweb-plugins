#!/bin/bash

. .tests/utils.sh

echo "ℹ️ Build bunkerweb-coraza ..."
CHANGE_DIR="./coraza/api" do_and_check_cmd docker build -t bunkerweb-coraza .

echo "ℹ️ Tag bunkerweb-coraza ..."
do_and_check_cmd docker image tag bunkerweb-coraza bunkerity/bunkerweb-coraza:latest
do_and_check_cmd docker image tag bunkerweb-coraza "bunkerity/bunkerweb-coraza:$1"

echo "ℹ️ Push bunkerweb-coraza ..."
do_and_check_cmd docker image push --all-tags bunkerity/bunkerweb-coraza
