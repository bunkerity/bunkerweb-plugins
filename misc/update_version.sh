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
# Anchor on the shields.io URL path (/badge/), not a leading quote — the badge
# is inside src="…/badge/bunkerweb_plugins-<ver>-blue", so the old `"bunkerweb…`
# pattern never matched and the badge silently went stale. Covers the root
# README and every plugin README (each carries the same badge); the sed is a
# no-op on READMEs that don't have the badge.
find . -type f -name "README.md" -exec sed -i 's@/badge/bunkerweb_plugins-[0-9][0-9.]*-blue@/badge/bunkerweb_plugins-'"$1"'-blue@' {} \;
