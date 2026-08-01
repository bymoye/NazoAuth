# One-click installation and updates

`nazoauthctl` is the supported lifecycle entry point for standalone Linux
deployments. It consumes immutable tagged release artifacts without cloning
source or requiring Rust, Node.js, or an image build toolchain on the host.
It is a Rust executable built and signed in the same release as `nazoauth`.

## First installation

The public GitHub Release contains executables only. The repository's bootstrap
script downloads the matching controller through the anonymous public Release
and artifact-attestation APIs, verifies the closed manifest with the digest-pinned
Cosign image, and only then installs the verified file. It binds the artifact,
tag ref, source commit, signer workflow, repository, and GitHub-hosted runner.
Neither a GitHub login nor `GH_TOKEN` is used. No shell installer or detached
bundle is part of the public Release, and `curl | sh` is intentionally not a
trusted bootstrap path.

Review the small bootstrap from the same immutable source tag, then run it with
that tag pinned:

```sh
version=v0.2.0
curl --fail --silent --show-error --location --proto '=https' \
  --output install_nazoauthctl.sh \
  "https://raw.githubusercontent.com/nazozero/NazoAuth/$version/scripts/install_nazoauthctl.sh"
less install_nazoauthctl.sh
sudo sh install_nazoauthctl.sh --version "$version"
```

Bootstrap requires `curl`, `python3`, `sha256sum`, and `install`, plus Podman or
Docker for the pinned Cosign verifier. A separately provisioned local `cosign`
is accepted only when neither container engine is available. Anonymous GitHub
API rate limits apply; a rate-limit response fails closed instead of asking for
or discovering an account token.

`auto` selects an installed Podman runtime first and Docker second:

```sh
sudo nazoauthctl install --runtime auto
```

Without a public URL, NazoAuth is published only at
`http://127.0.0.1:8000`. The installer generates PostgreSQL, Valkey, and
application secrets; creates persistent storage and configuration; installs
the signed frontend; and verifies readiness, Discovery, and `/ui/`.

The runtime can be selected explicitly:

```sh
sudo nazoauthctl install --runtime podman
sudo nazoauthctl install --runtime docker
sudo nazoauthctl install --runtime host
```

After a fresh installation, create the first administrator interactively:

```sh
sudo nazoauthctl bootstrap-admin
```

The controller prompts for the email and reads the password without echo. It
resolves the host source of the managed bootstrap mount, verifies that the
directory and token are private regular objects owned by the exact runtime UID
(`10001` for containers or the configured systemd service UID for host mode), and sends the
single-use token and credentials only as an HTTPS request body through the
child process stdin. They never enter argv, ordinary environment variables,
configuration, logs, audit records, or command output. Automation supplies a
closed JSON object containing exactly `email` and `password`:

```sh
secret-provider read nazoauth/initial-admin | \
  sudo nazoauthctl bootstrap-admin --credentials-stdin --yes
```

`--yes` skips only the confirmation prompt. The command still verifies the
exact HTTP 201 response contract, the `/ui/auth` continuation, and durable
consumption of the local one-time token.

The controller persists only a non-secret request ID, a deployment-secret-revision
HMAC of the normalized email, the recovery epoch and verified application receipt
identity, and a closed status. Controller or break-glass key rotation therefore
does not strand the pending request. If the database commits but the
HTTP response is lost, the next invocation reuses that request ID and retrieves
the same database-owned receipt; it does not create another administrator.
Network and malformed-response windows are audited as outcome-unknown until a
matching receipt is verified. The password, email, and token are never stored
in this recovery state.

`host` installs the signed `nazoauth` binary as a systemd service. Unless
external dependency URLs are supplied, an installed Podman or Docker runtime
still manages PostgreSQL and Valkey. Host mode also executes the candidate's
`--help` before changing the service so dynamic-link incompatibility fails
before activation. Native executables are released for Linux x86-64 and Arm64;
use the corresponding musl target on a musl-based distribution.

DNS and certificate ownership cannot be inferred. When `--public-url` is an
HTTPS origin, an existing TLS ingress must already forward that origin to the
installation port. Installation succeeds only after public Discovery reports
the exact issuer.

The default `baseline` profile is the safe general-purpose installation. The
declared full OIDF certification matrix uses the explicit `standards-full`
profile. The official public onboarding workflow emits a manifest-bound,
ready-to-use `standards-full-profile.json`, so the normal path needs no manual
assembly:

```sh
python3 scripts/oidf_onboarding_bundle.py verify \
  --artifact-directory /absolute/oidf-public-onboarding-material \
  --expected-source-commit "$source_commit" \
  --expected-target-issuer https://auth.example.com \
  --expected-suite-base-url https://suite.example \
  --expected-onboarding-profile official
sudo nazoauthctl install --runtime podman \
  --public-url https://auth.example.com --profile standards-full \
  --profile-material \
  /absolute/oidf-public-onboarding-material/standards-full-profile.json
```

The workflow first proves that `source_commit` is the commit behind the exact
immutable Release tag. A commit that is not yet on the default branch is
accepted only after the public non-draft Release and its tag-specific,
GitHub-hosted-runner attestation are verified. It then checks out that exact
commit before rendering any material. The artifact manifest binds the source
commit, target issuer, suite origin, and every file digest. Advanced operators
may instead use
`build_oidf_full_install_profile.py` in explicit-input mode when integrating a
different standards suite.

The material file is a closed, public-only trust/configuration document:
private JWK members, private keys, non-HTTPS origins, unknown fields, symlinks,
and relative paths are rejected. `nazoauthctl` generates the DCR, CIBA and
OpenID4VC management/encryption secrets locally, persists them only in managed
secret files, and creates the matching credential signing key and certificate
through an authenticated one-shot application task before startup. External
trust anchors and suite public keys are never guessed. `standards-full` therefore
requires an explicit material file; the baseline never silently enables it.

### Existing PostgreSQL and Valkey

Interactive entry avoids echoing credentials:

```sh
sudo nazoauthctl install --runtime host --external-dependencies
```

Automation supplies strict JSON through stdin or an already-open file
descriptor; URLs are rejected in argv and ordinary environment variables:

```sh
secret-provider read nazoauth/dependencies | sudo nazoauthctl install \
  --runtime host --external-dependencies --secrets-stdin
```

The JSON has exactly `database_url`, `migration_database_url`, and `valkey_url`.
The runtime PostgreSQL role must not have DDL privileges; the independently
supplied migration URL is exposed only to the one-shot migration task. The
input is persisted only in root-managed secret files and is never copied into
the topology, task envelope, logs, or audit records.

External-dependency installation and every subsequent update must create a
validated PostgreSQL custom-format dump and a Valkey RDB before migrations.
A container-free host deployment therefore requires `cosign`, `pg_dump`,
`pg_restore`, and `valkey-cli`.

## Normal operations

```sh
sudo nazoauthctl status
sudo nazoauthctl doctor
sudo nazoauthctl check
sudo nazoauthctl update --plan
sudo nazoauthctl update --yes --to v1.2.3
sudo nazoauthctl rollback --yes
sudo nazoauthctl recover --yes
sudo nazoauthctl migrate --yes
sudo nazoauthctl keys list
sudo nazoauthctl keys validate
sudo nazoauthctl audit verify
sudo nazoauthctl audit show [--request-id REQUEST_ID]
sudo nazoauthctl identity rotate --yes
sudo nazoauthctl break-glass recover-controller --reason lost --yes
```

The file-backed break-glass private key is independent from the controller and
audit keys and is never mounted into an application or task container. Export
an encrypted copy to offline escrow after installation. The current file-backed
flow still requires the root-owned host copy; a future provider integration is
required before removing it. File permissions do not protect it from host root.
Every break-glass recovery signs the transition
with the old recovery identity and atomically replaces controller, audit, and
break-glass identities; archive the new recovery key before the next incident.

`install` is idempotent and does not rebuild or upgrade an already ready
managed installation. `check` is non-mutating; `update` selects the latest
formal release; and `--to` pins an immutable version.

Automation can rely on exit code `0` for success, `2` for rejected CLI usage,
and `1` for any fail-closed lifecycle, trust, authorization, health, backup, or
recovery failure. A nonzero result never authorizes continuing from the failed
step in the clean-install acceptance procedure.

`nazoauthctl` runs on the host, but application-aware work stays in the target
runtime. For Docker or Podman it starts a one-shot container from the active or
candidate image, attaches the deployment network, and mounts only the
operation-specific configuration and state. It invokes the fixed
`nazoauth operator-task` entry point and passes a 60-second Ed25519 JWS on
stdin. JWS authenticates origin and integrity; it does not encrypt. Secret
material therefore travels only through secure stdin/FD, a secret mount, or a
secret provider, never argv, ordinary environment, logs, audit, or a persisted
task envelope. For a host deployment, the same verified binary runs as the
service user. The final signed receipt binds the controller-verified OCI/host
digest to the application-verified embedded build identity; the application
does not claim to prove its OCI digest.

## Trust and transaction boundary

For each tag, `release-security` publishes only the platform-suffixed
`nazoauth` and `nazoauthctl` executables as GitHub Release assets. Each subject
has a schema-4 GitHub attestation binding both executable digests, the signed
multi-platform OCI index, the independently attested NazoAuthWeb descriptor,
and the rollback boundary. Verification requires the exact
`release-security.yml@refs/tags/<version>` workflow identity before any subject
or predicate is trusted. SBOMs, predicates, signature bundles, and OCI archives
remain CI evidence rather than public Release assets.

Container modes can run the reviewed, OCI-digest-pinned Cosign image when a
local executable is unavailable. A container-free host deployment requires a
local Cosign executable.

Installation and update transactions:

1. take an exclusive host lock;
2. verify the subject attestation, closed manifest predicate, and required artifacts;
3. prepare and verify the candidate, then stop the active application writer;
4. create and validate PostgreSQL and Valkey backups and snapshot signing keys,
   generated secrets, and bootstrap state;
5. verify the image revision or execute the host binary;
6. run migrations and start the candidate;
7. atomically switch the signed frontend;
8. verify readiness, Discovery, and `/ui/`;
9. record the deployment and update `nazoauthctl` from the same release.

`update --plan` separately reports artifact rollback, schema-compatible
rollback, backup/PITR recovery, and an irreversible migration barrier. The
controller never describes database recovery as automatic. It restores the
previous artifact only when the signed policy says the resulting schema is
compatible; `recover --yes` is the explicit verified-backup restoration path.
The `20260801000100` receipt migration is additive, so the immediately previous
application can run without a schema downgrade and artifact rollback remains
schema-compatible. Its down migration deliberately refuses to erase a new
bootstrap receipt or application audit event. That conditional schema-downgrade
barrier is distinct from artifact rollback and from explicit verified-backup
database recovery; `update --plan` reports the signed migration floor and this
boundary in the policy rationale.
Before a managed database restore mutates PostgreSQL or Valkey, ctl durably
rotates the bootstrap recovery epoch. This invalidates any locally cached
successful initial-administrator receipt. After a restore, ctl therefore
cannot treat an old success as current or delete a newly generated bootstrap
token. If an external PITR changes database state without the managed recovery
workflow, a changed runtime token is detected against its HMAC binding and the
operation fails closed rather than claiming success.
For managed dependencies, the single managed application writer is stopped
before both backups; restored Valkey state can still invalidate ephemeral
sessions. For external dependencies, the operator must quiesce every other
writer and own the declared backup/PITR procedure. `update --plan` reports this
boundary instead of claiming cross-store transactional backup.

## Prerequisites and configuration

The baseline requires Linux x86-64 or Arm64, root, `curl`, `python3`,
`sha256sum`, and `install`, plus either local Cosign or a container engine that
can run the pinned Cosign image. The bootstrap uses anonymous GitHub APIs and
does not require GitHub CLI or an account token. Container modes additionally
require Podman or Docker.
Pure host mode needs systemd with `systemd-run`; external PostgreSQL/Valkey
dependencies also require `pg_dump`, `pg_restore`, and `valkey-cli`.
Automatically managed PostgreSQL and Valkey images are pinned to reviewed
multi-architecture OCI digests. Download `nazoauthctl` from the target GitHub
Release, verify its custom attestation as shown above, and install it at
`/usr/local/sbin/nazoauthctl`.

The lifecycle controller accepts `uname -m` architectures `x86_64` and
`aarch64` (often displayed as Arm64 by providers). It rejects other OS/CPU
pairs before creating deployment state. Native host installs use the matching
target-specific Release executables; Podman and Docker use the signed
`linux/amd64` or `linux/arm64` platform-manifest digest for the current host.

The installer generates root-owned, non-group/world-writable
`/etc/nazoauth/update.json`. Existing hand-managed deployments can start from
`deploy/update/update.example.json`; `install` will not take ownership of a
configuration without its `managed_install` marker.

Automatic scheduled upgrades are disabled by default. Authentication
infrastructure should be updated by an explicit operator action or separately
reviewed maintenance-window automation.
