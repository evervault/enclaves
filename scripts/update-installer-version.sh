#!/bin/bash
set -e 

if [ -z "$1" ]; then
    echo "Installer version is null. Exiting..."
    exit 1
fi

release_version="$1"
installer_hash="$2"
stage="$3"

echo installer_hash $installer_hash

major_version=$(echo "$release_version" | cut -d '.' -f 1)


echo "Release major version: $major_version"

if [ stage="staging" ]; then
  domain="evervault.io"
else
  domain="evervault.com"
fi

version_json=$(curl -s "https://enclave-build-assets.$domain/runtime/versions")
echo "Version response: $version_json"


if [ $? -eq 0 ]; then
  version_json=$(echo "$version_json" | jq --arg major_version "$major_version" --arg installer_hash "$installer_hash" '.versions[$major_version].installer = $installer_hash')
  echo "Updated versions: $version_json"
  echo "$version_json" > ./scripts/versions
else
  echo "Couldn't get versions from S3 $version_json"
fi