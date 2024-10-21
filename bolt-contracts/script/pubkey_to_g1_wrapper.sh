#!/bin/bash

# Notes on cross-compiling the binaries:
#
# Linux for arm64:
# - sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
# - GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -o pubkey_to_g1-linux-arm64
#
# MacOS for amd64:
# - GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o pubkey_to_g1-darwin-amd64


arch=$(uname -i 2>/dev/null) || arch=$(uname -p) 
if [[ $OSTYPE == linux* ]]; then
    if [[ $arch == x86_64 ]]; then
        ./script/pubkey_to_g1-linux-amd64 "$1"
    elif [[ $arch == aarch64 ]]; then
        ./script/pubkey_to_g1-linux-arm64 "$1"
    else
        exit 1
    fi
elif [[ $OSTYPE == darwin* ]]; then
    if [[ $arch == arm* ]]; then
        ./script/pubkey_to_g1-darwin-arm64 "$1"
    elif [[ $arch == x86_64 ]]; then
        ./script/pubkey_to_g1-darwin-amd64 "$1"
    else 
        exit 1
    fi
else
    exit 1
fi