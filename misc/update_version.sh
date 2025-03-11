#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

dir=$(pwd)

# If the dir ends with "misc", go up one level
if [[ $dir == *"misc" ]]; then
    dir=$(dirname "$dir")
fi

echo "Updating version of plugins to \"$1\""

find . -type f -name "plugin.json" -exec sed -i 's@"version": "[0-9].*"@"version": "'"$1"'"@' {} \;
sed -i 's@"bunkerweb_plugins\-[0-9].*\-blue"@"bunkerweb_plugins-'"$1"'-blue@' README.md
