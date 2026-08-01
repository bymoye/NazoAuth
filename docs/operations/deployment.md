# Deployment Guide

NazoAuth has two explicit deployment contracts: Compose for source-based
development, and the signed `nazoauthctl` lifecycle for standalone Linux
production on Podman, Docker, or a host systemd service.

## Source-tree development sandbox

Requirements:

- Docker Engine or another Compose-compatible container runtime;
- Docker Compose v2.

From the repository root:

```sh
docker compose up -d --build
docker compose ps
```

Compose generates private PostgreSQL and Valkey credentials in a named volume,
starts both services, and uses a short-lived development operator identity to
run the same signed `nazoauth operator-task` migration entry point before the
server accepts traffic. This identity is deliberately not a production trust
root. Open:

- `http://127.0.0.1:8000/ready` for dependency readiness
- `http://127.0.0.1:8000/live` for process liveness
- `http://127.0.0.1:8000/.well-known/openid-configuration`

The first source build requires network access to download Rust dependencies.
Later builds reuse the local container cache.

The default is a loopback-only evaluation deployment. PostgreSQL, Valkey,
signing keys, and avatars use named volumes and survive
`docker compose down`. Do not use `docker compose down -v` unless deleting all
local data is intentional.

When the database has no administrator, the server log reports a time-bounded,
single-use setup URL. Treat it as a password; it creates the first administrator
without requiring SMTP.

## Public deployment

For a formal release, prefer the lifecycle entry point:

```sh
sudo nazoauthctl install \
  --runtime auto \
  --public-url https://auth.example.com
```

`auto` selects Podman first and Docker second. Existing PostgreSQL/Valkey,
host installation, generated secrets, and backup boundaries are documented in
[one-click installation and updates](one-click-update.md).

`nazoauthctl` generates the private server configuration, dependency credentials,
deployment identities, signing identities, and recovery state. It binds NazoAuth
to the selected host loopback port. Put any
standards-compliant TLS reverse proxy in front of
`http://127.0.0.1:8000`. Configure `TRUSTED_PROXY_CIDRS` only for proxy
addresses you control, and keep `CLIENT_IP_HEADER_MODE=none` until the proxy
sanitizes forwarded headers correctly.

Set `NAZOAUTH_PORT` when the host loopback port must differ. Changing the host
port does not change the issuer: `PUBLIC_BASE_URL` must still match the public
HTTPS address seen by clients.

## Validation

Activation requires all of these checks:

1. `sudo nazoauthctl status` reports the signed Release and both target identities;
2. `sudo nazoauthctl doctor` verifies audit, readiness, target digest, and the runtime DDL boundary;
3. `/ready` returns HTTP 200;
4. `/.well-known/openid-configuration` returns the configured issuer;
5. the reverse proxy serves the same endpoints through the public HTTPS origin;
6. signing-key and avatar volumes remain mounted after a service restart.

Inspect the non-secret deployment state with:

```sh
sudo nazoauthctl status
sudo nazoauthctl audit show
```

## Upgrade and rollback

For a released standalone installation, the normal upgrade is:

```sh
sudo nazoauthctl update
```

This verifies the tag-specific Sigstore identity and immutable artifact
digests, creates recovery backups, runs migrations, replaces the application,
checks readiness and public Discovery, and automatically restores the previous
application image and persistent application files if verification fails. See
[One-click installation and updates](one-click-update.md).

Source deployments may still use Compose during development. They are not the
normal production update path. Database restoration remains separate because
migrations may be forward-only; the updater therefore accepts automatic
rollback only when the signed release declares the migration set compatible
with restarting the previous application.

## Production boundaries

The bundled topology is a single-node deployment. Before relying on it for
production:

- back up Compose-generated database, Valkey, and application secrets or use an external secret manager;
- define backup and restore procedures;
- monitor PostgreSQL, Valkey, disk usage, and `/ready`; use `/live` only for
  process restart decisions;
- keep signing keys and avatars on durable storage;
- use an external PostgreSQL/Valkey service or an orchestrator when HA is
  required;
- require the exact-commit security and conformance gates described in
  [release-security.md](release-security.md).

For an intentional clean-data replacement with OIDF-gated activation, use
[Fresh Deployment and Production Activation](fresh-production-activation.md).
Advanced settings are documented in [configuration.md](configuration.md).
