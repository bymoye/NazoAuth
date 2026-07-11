FROM docker.io/library/rust:1.96-slim AS builder

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --release

FROM docker.io/library/debian:trixie-slim AS runtime-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM runtime-base AS oidf-seed

COPY --from=builder /app/target/release/nazo_oauth_seed_oidf /usr/local/bin/nazo_oauth_seed_oidf

FROM runtime-base AS runtime

COPY --from=builder /app/target/release/nazo-oauth-server /usr/local/bin/nazo-oauth-server
COPY --from=builder /app/target/release/nazo-oauth-migrate /usr/local/bin/nazo-oauth-migrate
COPY --from=builder /app/target/release/nazo-oauth-keyctl /usr/local/bin/nazo-oauth-keyctl

EXPOSE 8000

CMD ["nazo-oauth-server"]

FROM runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
