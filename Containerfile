# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1.97.1-slim@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c AS build-base

ENV RUSTUP_TOOLCHAIN=1.97.1

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git make perl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./
COPY crates ./crates
COPY migrations ./migrations
COPY release/frontend.json ./release/frontend.json

FROM build-base AS product-builder

RUN --mount=type=cache,id=nazoauth-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=nazoauth-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=nazoauth-target,target=/app/target,sharing=locked \
    cargo build --release --locked \
      --package nazoauth --bin nazoauth \
    && install -Dm755 target/release/nazoauth /out/nazoauth

FROM docker.io/library/debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS runtime-base

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --gid 10001 nazoauth \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nazoauth \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM runtime-base AS runtime

COPY --from=product-builder /out/nazoauth /usr/local/bin/nazoauth

USER 10001:10001

EXPOSE 8000

CMD ["nazoauth", "server"]

FROM runtime-base AS release-export

COPY --from=product-builder /out/nazoauth /usr/local/bin/nazoauth

FROM runtime AS development-runtime

COPY --from=product-builder /app/.env.yaml.example /app/.env.yaml

FROM docker.io/library/postgres:18@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280 AS compose-postgres

COPY --chmod=0555 deploy/compose/initialize-postgres.sh /docker-entrypoint-initdb.d/initialize-nazoauth-runtime.sh

FROM development-runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
