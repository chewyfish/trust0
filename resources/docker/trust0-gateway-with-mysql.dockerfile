FROM rust:1.76 AS chef
RUN \
    apt-get update && \
    apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        gcc \
        libssl-dev \
        libmariadb-dev-compat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN cargo chef prepare --recipe-path recipe.json --bin crates/gateway

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --bin trust0-gateway --features mysql_db
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN cargo build --release --bin trust0-gateway --features mysql_db

FROM debian:bookworm-slim AS runtime
WORKDIR app
RUN \
    apt update && \
    apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        gcc \
        libssl-dev \
        libmariadb-dev-compat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*;
COPY --from=builder /app/target/release/trust0-gateway /app
ENTRYPOINT ["/app/trust0-gateway"]
