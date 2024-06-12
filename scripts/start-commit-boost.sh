# 1. check if folder ./commit-boost-client exists
# 2. if not, clone the commit-boost-client repository there
# 3. after that, build and run the commit-boost-client binary 

# check if folder ./commit-boost-client exists
if [ ! -d "./commit-boost-client" ]; then
  # if not, clone the commit-boost-client repository there
  git clone https://github.com/Commit-Boost/commit-boost-client.git
fi

# build and run the commit-boost-client binary
cd commit-boost-client
cargo build --release
./target/release/commit-boost-client start ./bolt-sidecar/bolt.config.toml

