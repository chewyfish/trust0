FROM lukemathwalker/cargo-chef:latest-rust-1.85.1-slim-bookworm AS chef
WORKDIR app

FROM chef AS planner
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN cargo chef prepare --recipe-path recipe.json --bin crates/common

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN cargo build --release --bins

FROM debian:bookworm-slim AS runtime
WORKDIR app
RUN \
    apt update; \
    apt install -y wget ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*;
COPY --from=builder /app/target/release/trust0-* /app
CMD ["/bin/bash"]
