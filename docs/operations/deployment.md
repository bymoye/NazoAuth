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

Compose bakes the secret initializer and safe default configuration into images
through the build context, so the Docker daemon does not need direct access to
the CLI host's absolute source paths. Do not add a manual secret initialization
step when using a remote Docker context or a containerized Web IDE. To change
both the host port and the public origin seen by browsers, run:

```sh
NAZOAUTH_PORT=443 \
NAZOAUTH_BIND_ADDRESS=0.0.0.0 \
NAZOAUTH_PUBLIC_BASE_URL=https://auth.example.com \
NAZOAUTH_BUILD_REVISION="$(git rev-parse HEAD)" \
NAZOAUTH_BUILD_ID="source:$(git rev-parse HEAD)" \
docker compose up -d --build
```

This remains a source development sandbox, not a signed, attested Release
installation.

`NAZOAUTH_BIND_ADDRESS=0.0.0.0` is required when a containerized Web IDE or
platform port mapper reaches the published host port through a non-loopback
interface. Keep the default `127.0.0.1` when a reverse proxy on the same host
terminates TLS. Do not bind all interfaces unless the platform or firewall
controls direct access to the plaintext port.

Compose generates private PostgreSQL and Valkey credentials in a named volume,
starts both services, and uses a short-lived development operator identity to
run the same signed `nazoauth operator-task` migration entry point before the
server accepts traffic. This identity is deliberately not a production trust
root. The task identifies its local automation actor as `docker-compose` and
binds the expected embedded release, revision, and build ID to the same values
used to compile the image; it does not contact or impersonate GitHub Actions.
Open:

- `http://127.0.0.1:8000/ready` for dependency readiness
- `http://127.0.0.1:8000/live` for process liveness
- `http://127.0.0.1:8000/.well-known/openid-configuration`

The first source build requires network access to download Rust dependencies.
Later builds reuse the local container cache.

The default is a loopback-only evaluation deployment. PostgreSQL, Valkey, and
application state—including signing keys, avatars, generated secrets,
bootstrap state, and the UI release cache—use named volumes and survive
`docker compose down`. Do not use `docker compose down -v` unless deleting all
local data is intentional.

When the database has no administrator, the server creates a time-bounded,
single-use token in its private bootstrap state. It never prints the token or a
token-bearing URL. The formal managed flow reads that private runtime-owned state through
`nazoauthctl bootstrap-admin`; the authorization server exposes only the JSON
`POST /auth/bootstrap-admin` API and does not serve an embedded setup page.

## Public deployment

For a formal release, prefer the lifecycle entry point:

```sh
sudo nazoauthctl install \
  --runtime auto \
  --public-url https://auth.example.com
sudo nazoauthctl bootstrap-admin
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

### Reverse proxy and mTLS

When RFC 8705 or the full OIDF profile is enabled, the TLS terminator must
request a client certificate and forward it with the RFC 9440 `Client-Cert`
header. NazoAuth authenticates the certificate against the client registration;
the proxy must not accept a `Client-Cert` or `Client-Cert-Chain` value supplied
by the Internet client. Configure `MTLS_CERTIFICATE_SOURCE=rfc9440` and set
`TRUSTED_PROXY_CIDRS` to the exact address NazoAuth observes for that proxy. Do
not trust a whole container subnet when one host address is sufficient.

NazoAuthCtl conformance clients use a fresh CA and leaf certificate for every
run. A proxy in front of a conformance deployment therefore cannot advertise a
stale, fixed client-CA list. Install the public CA bundle generated for that run
before starting Suite modules and restore the previous bundle in the same run's
cleanup path. With HAProxy 3.2, use this pattern:

The leaf subject DN must differ from the CA subject DN, while its issuer DN must
match that CA. Include `openssl verify -CAfile run-ca.pem client.pem` in the
preflight; otherwise OpenSSL/HAProxy can classify a different-key leaf with the
same subject/issuer DN as self-signed and reject the handshake.

```haproxy
frontend nazoauth
  bind :443 ssl crt /run/nazoauth/server.pem ca-file /run/nazoauth/active-conformance-client-cas.pem verify optional ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3 no-tls-tickets ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384 ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
  http-request del-header Client-Cert
  http-request del-header Client-Cert-Chain
  http-request set-header Client-Cert ":%[ssl_c_der,base64]:" if { ssl_c_used }
  default_backend nazoauth

backend nazoauth
  server app 127.0.0.1:8000 check
```

`verify optional` is required to request a certificate while retaining ordinary
HTTPS routes on the same listener; `verify none` does not request one. A client
that supplies a certificate must chain to the active run bundle. NazoAuth still
performs the registration subject/SAN and optional certificate-digest checks.
All of the following must remain true:

- HAProxy deletes inbound certificate headers before adding its own value;
- the cleartext upstream is loopback-only or otherwise inaccessible to clients;
- NazoAuth trusts only the exact proxy address and validates the presented leaf
  against the registered certificate identity;
- TLS 1.2 and TLS 1.3 are restricted separately to the approved AES-GCM suites.

Build the run bundle only from the public `mtls_trust_anchor_pem` values bound to
the active lease. Write it atomically, validate the entire bundle, reload the
proxy, and confirm its digest before creating Suite modules. Cleanup restores
the previous bundle and reloads the proxy even after interruption. A shared
proxy must serialize this install/restore lifecycle unless each run has its own
listener and CA bundle. Never use `ca-ignore-err all` or `crt-ignore-err all` as
a production substitute for installing the run CA: that delegates all chain
trust to the application and can weaken RFC 8705 clients registered only by a
standard subject selector.

For ordinary production clients issued by a stable CA, install that CA in
HAProxy and use `verify required` on a dedicated mTLS listener. Do not combine
that listener with run-scoped conformance certificates unless the control plane
can atomically install and restore their CA.

Before reloading HAProxy, validate the candidate with the same HAProxy image or
binary (`haproxy -c -f /path/to/candidate.cfg`) and retain a root-only copy of
the previous configuration. After reload, verify `/ready`, Discovery, the
unauthenticated Suite boundary, an allowed AES-GCM handshake, and rejection of
CBC and CHACHA20. Roll back the saved configuration and reload immediately if
any check fails.

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
