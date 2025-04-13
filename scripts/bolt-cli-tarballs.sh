#!/usr/bin/env bash
set -eo pipefail

# Use this script to create tarballs for bolt-cli to be uploaded to each Github release.
# This is intended to be run locally, and assuming you have cross installed.
#
# Note: this will only work when run on MacOS as `cross` does not distribute SDKs for
# MacOS due to licensing issues.

# Target tuples for cross compilation.
# each tuple is in the format of "target-triple", "short-name".
TARGETS=(
    "aarch64-apple-darwin" "arm64-darwin" # ARM apple chips (M-series)
    # Intel Mac builds are currently broken
    # "x86_64-apple-darwin" "amd64-darwin"      # Intel apple chips
    "aarch64-unknown-linux-gnu" "arm64-linux" # ARM linux chips
    "x86_64-unknown-linux-gnu" "amd64-linux"  # x86 linux chips
)

PROFILE="release"

# Check if cross is installed
if ! command -v cross &>/dev/null; then
    echo "cross is not installed. Install it by running 'cargo install cross'"
    exit 1
fi

(
    cd bolt-cli || exit 1
    mkdir -p dist

    # Iterate over TARGETS in pairs
    for ((i = 0; i < ${#TARGETS[@]}; i += 2)); do
        target="${TARGETS[i]}"
        short_name="${TARGETS[i + 1]}"

        echo "Building for $target ($short_name)"

        mkdir -p "dist/$short_name"
        cross build --release --target "$target"
        cp "target/$target/$PROFILE/bolt" "dist/$short_name/bolt"
        tar -czf "dist/bolt-cli-$short_name.tar.gz" -C "dist/$short_name" bolt

        echo "Done building for $target ($short_name)"
    done

    echo "Done building all targets."
    echo "You can find the tarballs in bolt-cli/dist/"
)

exit 0
