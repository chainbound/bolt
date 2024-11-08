FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx
FROM --platform=$BUILDPLATFORM rust:1.81.0-alpine AS base

WORKDIR /app

# Copy xx scripts to the build stage
COPY --from=xx / /

FROM base AS planner

# Copy files for dependency & binary resolution
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs ./src/main.rs

# Pre-fetch dependencies with caching
RUN --mount=type=cache,target=/root/.cargo/git/db \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/registry/index \
    cargo fetch

FROM base AS builder

# Install necessary tools for cross-compilation
RUN apk add clang lld musl-dev libc-dev build-base pkgconfig openssl-dev

# Set PKG_CONFIG_PATH to the directory containing openssl.pc
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig"

# Copy application source code
COPY . .

# Set the target platform using xx-cargo
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/root/.cargo/git/db \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/registry/index \
    xx-cargo build --release --target-dir ./build && \
    xx-verify ./build/$(xx-cargo --print-target-triple)/release/bolt-boost

# Final stage - runtime with Alpine
FROM alpine:latest AS runtime
WORKDIR /app

# Install only necessary runtime dependencies
RUN apk add --no-cache openssl ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /app/build/$(xx-cargo --print-target-triple)/release/bolt-boost /usr/local/bin/

# Set executable permissions if needed
RUN chmod +x /usr/local/bin/bolt-boost

ENTRYPOINT ["/usr/local/bin/bolt-boost"]
