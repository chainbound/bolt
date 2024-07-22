# default recipe to display help information
default:
  @just --list --unsorted

# run the web demo locally
demo:
	chmod +x ./scripts/start-demo.sh
	./scripts/start-demo.sh

# spin up the bolt devnet
up:
	chmod +x ./scripts/start-devnet.sh
	./scripts/start-devnet.sh

# turn down the bolt devnet and remove the enclave
down:
	kurtosis enclave rm -f bolt-devnet

# remove all kurtosis data and stop the engine
clean:
	kurtosis clean --all
	kurtosis engine stop

# restart the bolt devnet with updated docker images
restart:
	@just down
	@just build-images
	@just up

# show the running containers and port mappings for the bolt devnet
inspect:
	kurtosis enclave inspect bolt-devnet

# show the logs for the bolt devnet relay
relay-logs:
    @id=$(docker ps -n 100 | grep mev-relay-api | awk -F' ' '{print $1}') && \
    docker logs -f $id

# show the logs for the bolt devnet builder
builder-logs:
    @id=$(docker ps -n 100 | grep bolt-builder | awk -F' ' '{print $1}') && \
    docker logs -f $id

# show the logs for the bolt devnet mev-boost sidecar
boost-logs:
    @id=$(docker ps -n 100 | grep bolt-mev-boost | awk -F' ' '{print $1}') && \
    docker logs -f $id

# show the logs for the bolt devnet bolt-sidecar
sidecar-logs:
    @id=$(docker ps -n 100 | grep sidecar | awk -F' ' '{print $1}') && \
    docker logs -f $id

# show the logs for the bolt devnet for beacon node
beacon-dump:
    @id=$(docker ps -n 100 | grep 'cl-1-lighthouse-geth' | awk -F' ' '{print $1}') && \
    docker logs $id 2>&1 | tee beacon_dump.log

# show the logs for the bolt devnet relay
relay-dump:
    @id=$(docker ps -n 100 | grep mev-relay-api | awk -F' ' '{print $1}') && \
    docker logs $id 2>&1 | tee relay_dump.log

# show the logs for the bolt devnet builder
builder-dump:
    @id=$(docker ps -n 100 | grep bolt-builder | awk -F' ' '{print $1}') && \
    docker logs $id 2>&1 | tee builder_dump.log

# show the logs for the bolt devnet mev-boost sidecar
boost-dump:
    @id=$(docker ps -n 100 | grep bolt-mev-boost | awk -F' ' '{print $1}') && \
    docker logs $id 2>&1 | tee boost_dump.log

# show the logs for the bolt devnet bolt-sidecar
sidecar-dump:
    @id=$(docker ps -n 100 | grep sidecar | awk -F' ' '{print $1}') && \
    docker logs $id 2>&1 | tee sidecar_dump.log


# show the logs for the bolt devnet builder
kill-builder:
    @id=$(docker ps -n 100 | grep bolt-builder | awk -F' ' '{print $1}') && \
    docker stop $id

# show the dora explorer in the browser. NOTE: works only for Linux and MacOS at the moment
dora:
  @url=$(just inspect | grep 'dora\s*http' | awk -F'-> ' '{print $2}' | awk '{print $1}') && \
  if [ "$(uname)" = "Darwin" ]; then \
    open "$url"; \
  else \
    xdg-open "$url"; \
  fi

# manually send a preconfirmation to the bolt devnet
send-preconf:
	cd bolt-spammer && RUST_LOG=info cargo run -- \
		--provider-url $(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
		--beacon-client-url $(kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
		--bolt-sidecar-url http://$(kurtosis port print bolt-devnet mev-sidecar-api api)  \
		--private-key 53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710 \
		--slot head

# manually send a blob preconfirmation to the bolt devnet
send-blob-preconf:
	cd bolt-spammer && RUST_LOG=info cargo run -- \
		--provider-url $(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
		--beacon-client-url $(kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
		--bolt-sidecar-url http://$(kurtosis port print bolt-devnet mev-sidecar-api api)  \
		--private-key 53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710 \
		--slot head \
		--blob

# build all the docker images locally
build-images:
	@just _build-builder
	@just _build-relay
	@just _build-sidecar
	@just _build-mevboost

# build the docker image for the bolt builder
_build-builder:
	cd builder && docker buildx build -t ghcr.io/chainbound/bolt-builder:0.1.0 . --load

# build the docker image for the bolt relay
_build-relay:
	cd mev-boost-relay && docker buildx build -t ghcr.io/chainbound/bolt-relay:0.1.0 . --load

# build the docker image for the bolt sidecar
_build-sidecar:
	cd bolt-sidecar && docker buildx build -t ghcr.io/chainbound/bolt-sidecar:0.1.0 . --load

# build the docker image for the bolt mev-boost sidecar
_build-mevboost:
	cd mev-boost && docker buildx build -t ghcr.io/chainbound/bolt-mev-boost:0.1.0 . --load

# build and push the docker images to the github container registry with the provided tag
release tag:
    docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/chainbound/bolt-sidecar:${tag} --push .
    docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/chainbound/bolt-relay:${tag} --push .
    docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/chainbound/bolt-builder:${tag} --push .
    docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/chainbound/bolt-mev-boost:${tag} --push .
