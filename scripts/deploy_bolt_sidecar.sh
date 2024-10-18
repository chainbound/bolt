#!/bin/bash

# This script is used to deploy the bolt_sidecar binary as a service on 
# our remote dev server. Requirements:
# - Access to Chainbound's Tailnet dev server "remotebeast"
# - A .env.dev file in the bolt_sidecar directory, filled with the necessary vars
#   and configured with the right chain configuration

set -e

# check that the first argument is one of the supported chains: "helder" & "holesky"
if [ "$1" != "helder" ] && [ "$1" != "holesky" ]; then
    echo "Invalid chain argument. Supported chains: helder, holesky"
    exit 1
fi

# check if ".env.$1.dev" exists. if not, exit with error
test -f "./bolt-sidecar/.env.$1.dev" || (echo "No .env.$1.dev file found. Exiting." && exit 1)

# copy the files to the remote dev server 
rsync -av --exclude target --exclude .git ./bolt-sidecar/ shared@remotebeast:/home/shared/$1/bolt_sidecar
rsync -av ./scripts/bolt_sidecar_$1.service shared@remotebeast:/home/shared/$1/bolt_sidecar/bolt_sidecar_$1.service

# build the project on the remote dev server
ssh shared@remotebeast "cd ~/$1/bolt_sidecar && CC=clang ~/.cargo/bin/cargo build --release"
ssh shared@remotebeast "mv ~/$1/bolt_sidecar/target/release/bolt-sidecar /usr/local/bin/bolt-sidecar-$1 || true"
ssh shared@remotebeast "cp -f ~/$1/bolt_sidecar/bolt_sidecar_$1.service /etc/systemd/system/bolt_sidecar_$1.service"
ssh shared@remotebeast "sudo systemctl daemon-reload && sudo systemctl enable bolt_sidecar_$1"
ssh shared@remotebeast "sudo systemctl restart bolt_sidecar_$1"

echo "Deployed bolt_sidecar_$1 successfully"
