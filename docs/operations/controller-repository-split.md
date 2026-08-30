# NazoAuthCtl repository split

NazoAuth and NazoAuthCtl are separate release and failure domains.

NazoAuth owns the server, `operator-task`, migrations, production-key mutation,
consistency leases, and the bootstrap-admin endpoint. NazoAuthCtl owns host and
container orchestration, Release/OCI verification, task issuance and receipt
verification, controller audit state, backup lifecycle, recovery, diagnostics,
the bootstrap-admin client, and controller self-update/rollback.

`crates/operator-protocol` remains only in this repository. NazoAuthCtl pins a
released package version by server tag. Tagged server Releases additionally
publish that exact package with provenance so later controller dependency
updates have an immutable review subject; the compiled controller never
downloads it during recovery. The server Release manifest schema 6
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
Release/OCI artifacts and does not rebuild the server. Before publication,
candidate validation may build both current working trees directly, including
their uncommitted changes; the exact artifact digests, not Git state, identify
what is deployed for that validation.

The server repository contains no controller implementation, controller release
job, controller state, or alternate command surface. NazoAuthCtl is built and
published from its own repository. Cross-repository verification selects one
exact controller commit and one exact supported server Release; coupled
publication must not be reintroduced.

Recovery commands are not application operations. Backup recovery,
interrupted-update recovery, and identity recovery must work with the HTTP
service stopped and without trusting execution of the failed server runtime.
Whole-machine loss remains an off-host recovery-package boundary; a controller
and backup stored only on the lost machine cannot satisfy it.
