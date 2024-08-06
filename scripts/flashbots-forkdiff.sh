#!/bin/bash

set -e

# take the repo name as the first argument
REPO_NAME=$1
# take the tag as the second argument
GIT_TAG=$2

OUT_DIR=$(pwd)/forkdiff

# the repo name must be one of the supported packages
if [ "$REPO_NAME" != "mev-boost-relay" ] && [ "$REPO_NAME" != "mev-boost" ] && [ "$REPO_NAME" != "builder" ]; then
    echo "Usage: $0 <mev-boost-relay|mev-boost|builder>"
    exit 1
fi

# create the outdir if it doesn't exist
mkdir -p $OUT_DIR || true

# create a temporary dir to hold just the package alone, 
# without the monorepo path structure in the way
mkdir -p /tmp/bolt-forkdiff/$REPO_NAME
cp -r ./$REPO_NAME/* /tmp/bolt-forkdiff/$REPO_NAME/

(
    cd /tmp/bolt-forkdiff/$REPO_NAME

    git init
    git add .
    git commit -m "Snapshot of $REPO_NAME from bolt monorepo"

    git remote add origin https://github.com/flashbots/$REPO_NAME.git
    git fetch origin

    git diff origin/$GIT_TAG > $OUT_DIR/$REPO_NAME.diff
)

rm -rf /tmp/bolt-forkdiff/$REPO_NAME
