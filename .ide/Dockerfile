FROM docker.io/grafana/k6:2.1.0 AS k6
FROM docker.io/docker:27-cli AS docker-cli

FROM docker.io/library/rust:1-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=always
ENV RUST_BACKTRACE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        gnupg \
        jq \
        less \
        libpq-dev \
        lld \
        llvm \
        make \
        openssh-client \
        pkg-config \
        postgresql-client \
        protobuf-compiler \
        python3 \
        python3-pip \
        python3-venv \
        redis-tools \
        shellcheck \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --break-system-packages --no-cache-dir \
        "argon2-cffi==25.1.0" \
        "cryptography==46.0.3" \
        "psycopg[binary]==3.3.2" \
        "redis==7.1.0"

RUN mkdir -p /usr/local/cargo /usr/local/libexec/docker/cli-plugins

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

RUN printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && docker --version \
    && docker compose version \
    && k6 version \
    && rustc --version \
    && cargo --version

WORKDIR /workspace
