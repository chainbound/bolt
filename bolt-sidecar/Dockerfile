# Stage 1: Base compiler image with necessary dependencies
FROM rust:1.81.0-slim-bullseye AS base

# Install cargo-chef for dependency caching
RUN cargo install cargo-chef

# Set the working directory to /app
WORKDIR /app

# Stage 2: Planner (generating the recipe)
FROM base AS planner

# Copy only Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Prepare the recipe for caching dependencies (Cargo.toml/Cargo.lock)
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder with necessary dependencies for OpenSSL
FROM base AS builder

# Install required dependencies for building Rust projects (OpenSSL, pkg-config)
RUN apt-get update && apt-get install -y \
  pkg-config \
  libssl-dev \
  build-essential

# Copy the generated recipe from the planner stage
COPY --from=planner /app/recipe.json recipe.json

# Cache the dependencies using the cargo-chef recipe
RUN cargo chef cook --release --recipe-path recipe.json

# Copy the source code and build the project
COPY . .
RUN cargo build --release

# Stage 4: Final runtime image (lean image)
FROM debian:bullseye-slim AS runtime

# Set the working directory for the final container
WORKDIR /usr/local/bin

# Install necessary runtime dependencies (OpenSSL and CA certificates)
RUN apt-get update && apt-get install -y \
  libssl-dev \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/bolt-sidecar /usr/local/bin/bolt-sidecar

# Define the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/bolt-sidecar"]
