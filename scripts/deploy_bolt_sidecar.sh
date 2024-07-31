#!/bin/bash

# This script is used to deploy the bolt_sidecar binary as a service on 
# our remote dev server. Requirements:
# - Access to Chainbound's Tailnet dev server "remotebeast"
# - A .env.dev file in the bolt_sidecar directory, filled with the necessary vars

set -e

# check if ".env.dev" exists. if not, exit with error
test -f ./bolt-sidecar/.env.dev || (echo "No .env.dev file found. Exiting." && exit 1)

# copy the files to the remote dev server 
rsync -av --exclude target --exclude .git ./bolt-sidecar/ shared@remotebeast:/home/shared/bolt_sidecar
rsync -av ./scripts/bolt_sidecar.service shared@remotebeast:/home/shared/bolt_sidecar/bolt_sidecar.service

# build the project on the remote dev server
ssh shared@remotebeast "cd ~/bolt_sidecar && CC=clang ~/.cargo/bin/cargo build --release"
ssh shared@remotebeast "mv ~/bolt_sidecar/target/release/bolt-sidecar /usr/local/bin/bolt-sidecar || true"
ssh shared@remotebeast "cp -f ~/bolt_sidecar/bolt_sidecar.service /etc/systemd/system/bolt_sidecar.service"
ssh shared@remotebeast "sudo systemctl daemon-reload && sudo systemctl enable bolt_sidecar"
ssh shared@remotebeast "sudo systemctl restart bolt_sidecar"

echo "Deployed bolt_sidecar successfully"
