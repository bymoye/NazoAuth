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

The legacy `crates/nazoauthctl` directory was removed only after NazoAuthCtl PR
[#1](https://github.com/nazozero/NazoAuthCtl/pull/1) passed controller-only CI,
the signed current/previous server matrix, and real Docker, Podman, and systemd
recovery scenarios, and after independent NazoAuthCtl `v0.1.20` publication.
The NazoAuth `v0.1.20` tag retains the pre-removal source and remains the exact
review/rollback point. Coupled server/ctl publication must not be reintroduced.

Recovery commands are not application operations. Rollback, backup recovery,
interrupted-update recovery, identity recovery, and previous trusted activation
must work with the HTTP service stopped and without executing the current server
binary, current OCI image, or operator-task. Whole-machine loss remains an
off-host recovery-package boundary; a controller stored only on the lost machine
cannot satisfy it.
