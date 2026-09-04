# Release and black-box validation boundary

NazoAuth production artifacts contain the protocol implementation, migrations,
and the independently signed `nazoauth` executable. `nazoauthctl` is built,
signed, and released by `nazozero/NazoAuthCtl`.

The server repository and artifacts contain no third-party test runner, plan
registry, browser automation, test credentials, test-only onboarding model, or
expected-result catalog. An external validator is an ordinary client: it uses
public HTTPS protocols and the same tenant/client administration available to
all other integrations. Product code never branches on validator identity,
plan names, callback paths, test headers, or build flags.

The long-running runtime container contains only `nazoauth`. Its `server` entry
point cannot mutate schema; privileged host work uses the signed controller
protocol. External validation tooling is versioned, operated, and evidenced
outside this repository.

`crates/operator-protocol` remains the single source of controller protocol and
cryptographic rules. Release compatibility is declared by protocol version and
supported controller version; unsupported combinations fail closed.
