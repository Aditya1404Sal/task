# Multi-stage build for eBPF application
# Stage 1: Builder - Install Rust toolchain and eBPF dependencies
FROM rust:1.86-slim as builder

# Install system dependencies needed for eBPF compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    lld \
    libelf-dev \
    zlib1g-dev \
    linux-libc-dev \
    pkg-config \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker for Aya eBPF programs
RUN cargo install bpf-linker

# Install nightly toolchain and rust-src for eBPF compilation
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && rustup default nightly \
    && rustup override set 1.86.0

# Set working directory
WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY task/Cargo.toml ./task/
COPY task-common/Cargo.toml ./task-common/
COPY task-ebpf/Cargo.toml ./task-ebpf/

# Fetch dependencies
RUN cargo fetch

# Copy source code
COPY . .

# Build the application in release mode
RUN cargo build --release --locked

# Stage 2: Runtime - Minimal runtime environment
FROM debian:bookworm-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from builder stage
COPY --from=builder /app/target/release/task /usr/local/bin/task

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV RUST_LOG=info

# Expose HTTP API port
EXPOSE 3000

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh", "/usr/local/bin/task"]