# Release and conformance boundary

NazoAuth production artifacts contain the protocol implementation, migrations,
and the independently signed `nazoauth` executable. `nazoauthctl` is built,
signed, and released only by `nazozero/NazoAuthCtl`. Server artifacts do not contain OIDF plan definitions, runner source,
browser automation, expected-result registries, onboarding fixtures, test
credentials, or conformance scripts.

The long-running runtime container contains only the `nazoauth` executable.
Its public `server` entry point cannot mutate schema; privileged work is accepted
only by the closed, signed `operator-task` protocol. The host `nazoauthctl`
verifies the actual OCI/host digest, prepares a least-privilege one-shot sandbox,
and only then issues the 60-second task. Host deployments run the same verified
binary as the service user. OIDF tools stay in
the source repository and interact with a deployed
issuer only through its public HTTPS protocol and normal public administration
flows. Product code must not branch on suite aliases, plan names, callback
paths, test headers, or a conformance build flag.

The official OpenID Foundation Conformance Suite is checked out at an exact
commit and its tracked source must remain unchanged. Repository code may prepare
external runner configuration and monitor public suite APIs, but must never
patch the official runner or its protocol assertions.

These boundaries are enforced by `tests/unit/test_release_governance.py` and the
container build. A change that needs an OIDF-specific product branch is invalid;
implement the governing specification and verify the resulting public behavior
instead.

`crates/operator-protocol` remains the single source of protocol types and
cryptographic rules. NazoAuthCtl consumes it by exact package version and full
NazoAuth Git revision. The server Release manifest declares both the protocol
version and the supported controller SemVer range; unsupported combinations
fail closed.
