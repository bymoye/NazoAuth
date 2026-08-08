# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1.97.1-slim@sha256:3b2879047d42784ca9403ad20c51ed3df361a50f1df96f5777d39b4e33aa65cd AS build-base

ENV RUSTUP_TOOLCHAIN=1.97.0

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./
COPY crates ./crates
COPY migrations ./migrations

FROM build-base AS product-builder

ARG NAZOAUTH_BUILD_RELEASE=development
ARG NAZOAUTH_BUILD_REVISION=development
ARG NAZOAUTH_BUILD_ID=local:development
ENV NAZOAUTH_BUILD_RELEASE=${NAZOAUTH_BUILD_RELEASE} \
    NAZOAUTH_BUILD_REVISION=${NAZOAUTH_BUILD_REVISION} \
    NAZOAUTH_BUILD_ID=${NAZOAUTH_BUILD_ID}

RUN --mount=type=cache,id=nazoauth-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=nazoauth-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=nazoauth-target,target=/app/target,sharing=locked \
    cargo build --release --locked \
      --package nazo-oauth-server --bin nazoauth \
      --package nazoauthctl --bin nazoauthctl \
      --package nazo-operator-protocol --example ci_operator_task \
    && install -Dm755 target/release/nazoauth /out/nazoauth \
    && install -Dm755 target/release/nazoauthctl /out/nazoauthctl \
    && install -Dm755 target/release/examples/ci_operator_task /out/ci_operator_task

FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS runtime-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
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
COPY --from=product-builder /out/nazoauthctl /usr/local/bin/nazoauthctl

FROM runtime AS development-runtime

COPY --from=product-builder /out/ci_operator_task /usr/local/bin/ci_operator_task

FROM development-runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
