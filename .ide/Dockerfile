FROM docker.io/grafana/k6:2.1.0@sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669 AS k6
FROM docker.io/docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS docker-cli

FROM docker.io/library/rust:1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

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
        openssh-server \
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

RUN mkdir -p /run/sshd \
    && sshd -t

RUN python3 -m pip install --break-system-packages --no-cache-dir \
        "argon2-cffi==25.1.0" \
        "cryptography==46.0.3" \
        "psycopg[binary]==3.3.4" \
        "redis==7.1.0"

RUN mkdir -p /usr/local/cargo /usr/local/libexec/docker/cli-plugins

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

RUN printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && docker --version \
    && docker compose version \
    && k6 version \
    && sshd -t \
    && rustc --version \
    && cargo --version

WORKDIR /workspace
