#!/bin/bash

TAG=$1

# Extract the version from the sidecar Cargo.toml file
VERSION=$(grep '^version\s*=\s*"' bolt-sidecar/Cargo.toml | awk -F '"' '{print $2}')

# Trim the initial "v" from TAG if present
TRIMMED_TAG=${TAG#v}

if [ "$VERSION" != "$TRIMMED_TAG" ]; then
    echo "Version mismatch: Sidecar Cargo.toml version is $VERSION but tag is $TRIMMED_TAG"
    exit 1
fi
