up:
	kurtosis run --enclave bolt-devnet github.com/chainbound/ethereum-package --args-file kurtosis_config.yaml

down:
	kurtosis enclave rm -f bolt-devnet

restart:
	make down
	make build-images
	make up

inspect:
	kurtosis enclave inspect bolt-devnet

relay-logs:
	docker logs -f $(shell docker ps --format "{{.ID}}\t{{.Names}}" | grep "mev-relay-api" | awk '{print $$1}')

builder-logs:
	docker logs -f $(shell docker ps --format "{{.ID}}\t{{.Names}}" | grep "el-2-geth-builder-lighthouse" | awk '{print $$1}')

boost-logs:
	docker logs -f $(shell docker ps --format "{{.ID}}\t{{.Names}}" | grep "mev-boost-1-lighthouse-geth" | awk '{print $$1}')

sidecar-logs:
	docker logs -f $(shell docker ps --format "{{.ID}}\t{{.Names}}" | grep "mev-sidecar-api" | awk '{print $$1}')

send-preconf:
	cd bolt-spammer && RUST_LOG=info cargo run -- \
		--provider-url $(shell kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
		--beacon-client-url $(shell kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
		--bolt-sidecar-url http://$(shell kurtosis port print bolt-devnet mev-sidecar-api api)  \
		--private-key bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31 \
		--slot head

clean:
	kurtosis clean --all
	kurtosis engine stop

build-images:
	make build-builder
	make build-relay
	make build-sidecar
	make build-mevboost

push-images:
	docker push ghcr.io/chainbound/bolt-builder:0.1.0
	docker push ghcr.io/chainbound/bolt-relay:0.1.0
	docker push ghcr.io/chainbound/bolt-sidecar:0.1.0
	docker push ghcr.io/chainbound/bolt-mev-boost:0.1.0

build-builder:
	cd builder && docker build -t ghcr.io/chainbound/bolt-builder:0.1.0 .

build-relay:
	cd mev-boost-relay && docker build -t ghcr.io/chainbound/bolt-relay:0.1.0 .

build-sidecar:
	cd bolt-sidecar && docker build -t ghcr.io/chainbound/bolt-sidecar:0.1.0 .

build-mevboost:
	cd mev-boost && docker build -t ghcr.io/chainbound/bolt-mev-boost:0.1.0 .
