# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1.97.1-slim@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS build-base

ENV RUSTUP_TOOLCHAIN=1.97.1

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends make perl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./
COPY crates ./crates
COPY migrations ./migrations
COPY release/frontend.json ./release/frontend.json

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
      --package nazo-operator-protocol --example automation_operator_task \
    && install -Dm755 target/release/nazoauth /out/nazoauth \
    && install -Dm755 target/release/examples/automation_operator_task /out/automation_operator_task

FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS runtime-base

RUN apt-get update \
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

COPY --from=product-builder /out/automation_operator_task /usr/local/bin/automation_operator_task
COPY --from=product-builder /app/.env.yaml.example /app/.env.yaml

FROM docker.io/library/alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS compose-secrets-init

COPY --chmod=0555 deploy/compose/initialize-secrets.sh /usr/local/libexec/nazoauth-initialize-secrets.sh

ENTRYPOINT ["/bin/sh", "/usr/local/libexec/nazoauth-initialize-secrets.sh"]

FROM development-runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
