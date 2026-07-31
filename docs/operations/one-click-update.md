# One-click updates

`nazoauthctl` is the supported update path for a standalone Podman deployment.
It consumes immutable tagged release assets; it does not clone source code or
run Rust, Node.js, or Docker builds on the production host.

After the initial installation has placed the root-owned configuration at
`/etc/nazoauth/update.json`, the normal operator action is:

```sh
sudo nazoauthctl update
```

Use `nazoauthctl check` to verify the newest release without changing runtime
state, `nazoauthctl update --to v1.2.3` to pin an exact release, and
`nazoauthctl status` to inspect the active image revision.

## Trust and transaction boundary

For a tagged release, `release-security` publishes:

- an immutable backend image archive;
- the frontend artifact pinned by `release/frontend.lock`;
- the unified `nazoauth` binary and CycloneDX SBOM;
- `nazoauthctl`;
- a release manifest containing every artifact size and SHA-256 digest;
- keyless Sigstore bundles bound to the tag-specific GitHub Actions workflow
  identity.

The updater first verifies the manifest with Cosign and the exact
`release-security.yml@refs/tags/<version>` certificate identity. Only then does
it parse artifact names and hashes. A floating image tag, an unsigned
manifest, a different workflow identity, a digest mismatch, an unexpected
image revision, or a release that does not declare database rollback
compatibility fails closed.

If the host does not provide a `cosign` executable, the updater runs the
official multi-architecture Cosign release image pinned by OCI digest. Updating
that verifier digest is a reviewed source change, not a network-selected
`latest` dependency.

The update transaction:

1. takes an exclusive host lock;
2. downloads and verifies the signed manifest and required artifacts;
3. creates and validates a PostgreSQL custom-format backup;
4. completes a Valkey `BGSAVE` and copies the resulting RDB;
5. snapshots configured application-owned persistent paths;
6. loads the exact image and verifies its revision label;
7. runs migrations, replaces the application container, and waits for readiness;
8. atomically switches the signed frontend release;
9. verifies public Discovery and records the completed deployment;
10. atomically refreshes the updater itself from the signed release.

If migration, startup, readiness, or public verification fails, the updater
removes the candidate, restores the snapshotted application paths, restarts
the previous image, and records the rollback. PostgreSQL restoration is not
silently attempted: it is a separate recovery operation from the verified
backup. Consequently, one-click updates accept only release manifests whose
reviewed `release/update-policy.json` declares the migration set compatible
with restarting the immediately previous application version.

## Configuration

Start from `deploy/update/update.example.json`. The file contains topology and
path information, not a shell program. Keep it root-owned and not
group/world-writable:

```sh
sudo install -d -m 0755 /etc/nazoauth
sudo install -m 0600 deploy/update/update.example.json /etc/nazoauth/update.json
sudo install -m 0755 deploy/update/nazoauthctl /usr/local/sbin/nazoauthctl
```

Review container names, database/user names, issuer, network/IP, mounts,
snapshot paths, Valkey password-file location, and UI paths before the first
update. `nazoauthctl check` is the non-mutating acceptance check.

The updater intentionally does not apply releases on a timer by default.
Authentication infrastructure should be upgraded by an explicit operator
action or a separately reviewed maintenance automation.
