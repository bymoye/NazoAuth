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

FROM docker.io/library/debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS runtime-base

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

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS compose-secrets-init

COPY --chmod=0555 deploy/compose/initialize-secrets.sh /usr/local/libexec/nazoauth-initialize-secrets.sh

ENTRYPOINT ["/bin/sh", "/usr/local/libexec/nazoauth-initialize-secrets.sh"]

FROM development-runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
