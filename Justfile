# default recipe to display help information
default:
  @just --list --unsorted

# run the web demo locally
demo:
	chmod +x ./scripts/start-demo.sh
	./scripts/start-demo.sh

# spin up the bolt devnet
up:
	kurtosis run --enclave bolt-devnet github.com/chainbound/ethereum-package --args-file ./scripts/kurtosis_config.yaml

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
  docker logs -f `docker ps --format "{{{{.ID}}\t{{{{.Names}}" | grep "mev-relay-api" | awk '{print $$1}'`

# show the logs for the bolt devnet builder
builder-logs:
	docker logs -f `docker ps --format "{{{{.ID}}\t{{{{.Names}}" | grep "el-2-geth-builder-lighthouse" | awk '{print $$1}'`

# show the logs for the bolt devnet mev-boost sidecar
boost-logs:
	docker logs -f `docker ps --format "{{{{.ID}}\t{{{{.Names}}" | grep "mev-boost-1-lighthouse-geth" | awk '{print $$1}'`

# show the logs for the bolt devnet bolt-sidecar
sidecar-logs:
	docker logs -f `docker ps --format "{{{{.ID}}\t{{{{.Names}}" | grep "mev-sidecar-api" | awk '{print $$1}'`

# manually send a preconfirmation to the bolt devnet
send-preconf:
	cd bolt-spammer && RUST_LOG=info cargo run -- \
		--provider-url $(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
		--beacon-client-url $(kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
		--bolt-sidecar-url http://$(kurtosis port print bolt-devnet mev-sidecar-api api)  \
		--private-key bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31 \
		--slot head

# build all the docker images locally
build-images:
	@just _build-builder
	@just _build-relay
	@just _build-sidecar
	@just _build-mevboost

# build the docker image for the bolt builder
_build-builder:
	cd builder && docker build -t ghcr.io/chainbound/bolt-builder:0.1.0 .

# build the docker image for the bolt relay
_build-relay:
	cd mev-boost-relay && docker build -t ghcr.io/chainbound/bolt-relay:0.1.0 .

# build the docker image for the bolt sidecar
_build-sidecar:
	cd bolt-sidecar && docker build -t ghcr.io/chainbound/bolt-sidecar:0.1.0 .

# build the docker image for the bolt mev-boost sidecar
_build-mevboost:
	cd mev-boost && docker build -t ghcr.io/chainbound/bolt-mev-boost:0.1.0 .

# push all the docker images to the private github container registry
_push-images:
	docker push ghcr.io/chainbound/bolt-builder:0.1.0
	docker push ghcr.io/chainbound/bolt-relay:0.1.0
	docker push ghcr.io/chainbound/bolt-sidecar:0.1.0
	docker push ghcr.io/chainbound/bolt-mev-boost:0.1.0
