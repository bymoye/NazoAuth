# NazoAuthCtl repository split

NazoAuth and NazoAuthCtl are separate release and failure domains.

NazoAuth owns the server, `operator-task`, migrations, production-key mutation,
consistency leases, and the bootstrap-admin endpoint. NazoAuthCtl owns host and
container orchestration, Release/OCI verification, task issuance and receipt
verification, controller audit state, backup lifecycle, recovery, diagnostics,
the bootstrap-admin client, and controller self-update/rollback.

`crates/operator-protocol` remains only in this repository. NazoAuthCtl pins its
package version and a full Git commit. Tagged server Releases additionally
publish that exact package with provenance so later controller dependency
updates have an immutable review subject; the compiled controller never
downloads it during recovery. The server Release manifest schema 5
contains `operator_protocol.version`, `minimum_ctl_version`, and
`maximum_ctl_version_exclusive`; missing, malformed, or unsupported contracts
fail closed.

The same crate owns the signed online discovery and offline deployment
statement contracts; see [control discovery](control-discovery.md). These
identity statements never substitute for independent Release and artifact
verification.

The server release workflow builds each server platform binary once. The same
uploaded binary is used by OCI assembly, smoke checks, custom attestation,
standard provenance, signing evidence, and publication. It never builds or
publishes NazoAuthCtl. Cross-repository integration downloads signed server
Release/OCI artifacts and does not rebuild the server.

The legacy `crates/nazoauthctl` directory remains temporarily to preserve a
reviewable transition and to support cross-repository comparison. It must not be
deleted until the NazoAuthCtl PR has passed controller-only CI and the signed
current/previous server matrix. Its presence is not authority to resume coupled
server/ctl publication.

Recovery commands are not application operations. Rollback, backup recovery,
interrupted-update recovery, identity recovery, and previous trusted activation
must work with the HTTP service stopped and without executing the current server
binary, current OCI image, or operator-task. Whole-machine loss remains an
off-host recovery-package boundary; a controller stored only on the lost machine
cannot satisfy it.
