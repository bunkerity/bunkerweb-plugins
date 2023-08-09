#!/bin/bash

. .tests/utils.sh

echo "ℹ️ Build bunkerweb-coraza ..."
CHANGE_DIR="./coraza/api" do_and_check_cmd docker build -t bunkerity/bunkerweb-coraza:latest .

echo "ℹ️ Push bunkerweb-coraza ..."
do_and_check_cmd docker push bunkerity/bunkerweb-coraza:latest