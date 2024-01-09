#!/bin/bash
set -e 

# Script to update version json on release
# Version json is stored in S3 and is used to determine the latest version of the runtime for each major
# The json is structured as follows:
# {
# 			"latest": "2.0.4",
# 			"versions": {
# 				"0": { "latest": "0.0.4", "deprecationDate": "1697719181"},
# 				"1": { "latest": "1.0.4" },
# 				"2": { "latest": "2.0.4" }
# 			}
# 		}
# The top level latest version is used to determine the latest version of the runtime overall

if [ -z "$1" ]; then
    echo "Runtime version is null. Exiting..."
    exit 1
fi

release_version="$1"

major_version=$(echo "$release_version" | cut -d '.' -f 1)

echo "Release major version: $major_version"

version_json=$(curl -s "https://${CAGE_BUILD_ASSETS_HOSTNAME:-enclave-build-assets.evervault.com}/runtime/versions")
echo "Version response: $version_json"

if [ $? -eq 0 ]; then
  highest_major_version=$(echo "$version_json" | jq '.versions | keys_unsorted[] | tonumber' | sort -nr | head -1)
  echo Highest current major version: $highest_major_version
  if [ "$major_version" -ge "$highest_major_version" ]; then
    #update overall latest version if release is current major
    version_json=$(echo "$version_json" | jq --arg release_version "$release_version" '.latest = $release_version')
  else
    echo "Major version is less than current highest, not updating top level latest version"
  fi

  version_json=$(echo "$version_json" | jq --arg major_version "$major_version" --arg new_version "$release_version" '.versions[$major_version].latest = $new_version')
  echo "Updated versions: $version_json"
  echo "$version_json" > ./scripts/versions
else
  echo "Couldn't get versions from S3 $version_json"
fi