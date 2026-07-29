# Deployment Guide

NazoAuth uses the same Docker Compose interface on every supported operator
platform. Host-specific release scripts are implementation details, not part of
the public deployment contract.

## Quick start

Requirements:

- Docker Engine or another Compose-compatible container runtime;
- Docker Compose v2.

From the repository root:

```sh
docker compose up -d --build
docker compose ps
```

Compose starts PostgreSQL and Valkey, runs `nazoauth migrate`, then starts
`nazoauth server`. Open:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/.well-known/openid-configuration`

The first source build requires network access to download Rust dependencies.
Later builds reuse the local container cache.

The default is a loopback-only evaluation deployment. PostgreSQL, Valkey,
signing keys, and avatars use named volumes and survive
`docker compose down`. Do not use `docker compose down -v` unless deleting all
local data is intentional.

## Public deployment

Create a private `.env.yaml` from `.env.yaml.example` and select it through the
`NAZOAUTH_CONFIG` Compose variable. At minimum, change:

```yaml
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://<user>:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<stable random secret of at least 32 bytes>"
RUST_LOG: "info"
```

New deployments do not need to select one global authorization-server
profile. Configure elevated behavior through runtime modules and explicit
per-client `security_policy`.

Keep this file outside version control. `PUBLIC_BASE_URL` must be the exact
HTTPS origin without a trailing slash. `CLIENT_SECRET_PEPPER` must remain
stable across restarts.
When using the bundled PostgreSQL service, keep `POSTGRES_DB`,
`POSTGRES_USER`, and `POSTGRES_PASSWORD` consistent with `DATABASE_URL`;
percent-encode the password inside the URL. Independently managed PostgreSQL
and Valkey services are preferable for production.

Start the same topology:

```sh
docker compose up -d --build
docker compose ps
```

Compose binds NazoAuth to host loopback port `8000`. Put any
standards-compliant TLS reverse proxy in front of
`http://127.0.0.1:8000`. Configure `TRUSTED_PROXY_CIDRS` only for proxy
addresses you control, and keep `CLIENT_IP_HEADER_MODE=none` until the proxy
sanitizes forwarded headers correctly.

Set `NAZOAUTH_PORT` when the host loopback port must differ. Changing the host
port does not change the issuer: `PUBLIC_BASE_URL` must still match the public
HTTPS address seen by clients.

## Validation

Activation requires all of these checks:

1. `docker compose ps` shows PostgreSQL, Valkey, and `server` running;
2. the one-shot `migrate` service exited successfully;
3. `/health` returns HTTP 200;
4. `/.well-known/openid-configuration` returns the configured issuer;
5. the reverse proxy serves the same endpoints through the public HTTPS origin;
6. signing-key and avatar volumes remain mounted after a service restart.

Inspect failures with:

```sh
docker compose logs migrate
docker compose logs server
```

## Upgrade and rollback

For an upgrade:

```sh
docker compose build --pull
docker compose up -d
docker compose ps
```

Compose runs migrations before replacing the server. Production releases
should pin a reviewed image digest or exact source commit rather than an
unbounded tag.

Rollback the application by restoring the previous image or source revision
and running `docker compose up -d` again. Database rollback is separate:
migrations may be forward-only, so take and verify a PostgreSQL backup before
every production upgrade.

## Production boundaries

The bundled topology is a single-node deployment. Before relying on it for
production:

- replace example database credentials;
- define backup and restore procedures;
- monitor PostgreSQL, Valkey, disk usage, and `/health`;
- keep signing keys and avatars on durable storage;
- use an external PostgreSQL/Valkey service or an orchestrator when HA is
  required;
- require the exact-commit security and conformance gates described in
  [release-security.md](release-security.md).

For an intentional clean-data replacement with OIDF-gated activation, use
[Fresh Deployment and Production Activation](fresh-production-activation.md).
Advanced settings are documented in [configuration.md](configuration.md).
