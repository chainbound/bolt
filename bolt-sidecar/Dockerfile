FROM rust:slim-bullseye AS compiler

RUN cargo install cargo-chef

WORKDIR /app

FROM compiler AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM compiler AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
WORKDIR /usr/local/bin
COPY --from=builder /app/target/release/bolt-sidecar /
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

CMD ["/bolt-sidecar"]
