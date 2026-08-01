# Release Platform Support

## What the Release Matrix Proves

The tagged Release workflow builds and executes each binary on a native runner
with the same operating system and CPU architecture as the target. It does not
label a cross-compiled file as supported without executing it. Every matrix
entry runs the complete `nazoauthctl` test target, executes both binaries, and
checks the `nazoauth build-identity` JSON against the exact tag, commit, operator
protocol, and workflow build ID.

| Rust target | Native runner | GitHub Release assets |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Ubuntu 24.04 x86-64 | `nazoauth-x86_64-unknown-linux-gnu`, `nazoauthctl-x86_64-unknown-linux-gnu` |
| `aarch64-unknown-linux-gnu` | Ubuntu 24.04 Arm64 | `nazoauth-aarch64-unknown-linux-gnu`, `nazoauthctl-aarch64-unknown-linux-gnu` |
| `x86_64-unknown-linux-musl` | Ubuntu 24.04 x86-64 | `nazoauth-x86_64-unknown-linux-musl`, `nazoauthctl-x86_64-unknown-linux-musl` |
| `aarch64-unknown-linux-musl` | Ubuntu 24.04 Arm64 | `nazoauth-aarch64-unknown-linux-musl`, `nazoauthctl-aarch64-unknown-linux-musl` |
| `x86_64-pc-windows-msvc` | Windows 2025 x86-64 | `nazoauth-x86_64-pc-windows-msvc.exe`, `nazoauthctl-x86_64-pc-windows-msvc.exe` |
| `aarch64-pc-windows-msvc` | Windows 11 Arm64 | `nazoauth-aarch64-pc-windows-msvc.exe`, `nazoauthctl-aarch64-pc-windows-msvc.exe` |
| `x86_64-apple-darwin` | macOS 15 Intel | `nazoauth-x86_64-apple-darwin`, `nazoauthctl-x86_64-apple-darwin` |
| `aarch64-apple-darwin` | macOS 15 Apple Silicon | `nazoauth-aarch64-apple-darwin`, `nazoauthctl-aarch64-apple-darwin` |

The GNU binaries inherit the glibc baseline of Ubuntu 24.04. Use the matching
musl artifact for older or heterogeneous Linux userspace. The workflow rejects
musl binaries with dynamic dependencies and rejects every desktop or GNU binary
that dynamically loads libpq, libssl, or libcrypto. Normal operating-system
libraries and frameworks remain platform dependencies.

The container Release is a single OCI index at
`ghcr.io/nazozero/nazoauth:<version>` containing exactly `linux/amd64` and
`linux/arm64`. The workflow scans an OCI archive first, publishes that exact
archive without rebuilding, and records the index and both platform-manifest
digests.

## Product and Controller Boundaries

`nazoauth` is the portable application executable. `nazoauthctl` is shipped on
the same targets so its parsing, verification, status, and diagnostic surfaces
can be used consistently, but the managed host lifecycle currently requires
Linux, root, and systemd. Podman and Docker lifecycle automation is qualified on
Linux. A successful Windows or macOS binary smoke does not claim that Linux
service installation, ownership, mount labeling, or database recovery commands
work natively on those operating systems.

The browser UI is not embedded in either backend executable. A schema-4 Release
attestation binds the independently attested NazoAuthWeb Release descriptor;
the runtime obtains and verifies that UI artifact through the documented
control-plane flow.

## Binary-Only GitHub Releases

Persistent GitHub Release assets contain exactly the 16 platform-suffixed
executables in the table. Manifests, signatures, SBOMs, OCI archives, bootstrap
scripts, and other JSON or tar files are not Release assets. Supply-chain
evidence remains in GitHub Actions, GitHub artifact attestations, Sigstore, and
the signed GHCR image.

Each executable has a custom GitHub attestation with predicate type
`https://nazo.run/attestations/release-manifest/v1`. Its closed schema binds the
target, both executable digests, embedded build identity, frontend descriptor,
OCI index and platform manifests, and rollback boundary. Verify a downloaded
file before execution:

```sh
version=v1.2.3
gh attestation verify ./nazoauth-x86_64-unknown-linux-musl \
  --repo nazozero/NazoAuth \
  --predicate-type https://nazo.run/attestations/release-manifest/v1 \
  --signer-workflow nazozero/NazoAuth/.github/workflows/release-security.yml \
  --source-ref "refs/tags/$version" \
  --deny-self-hosted-runners
```

Digest verification proves the downloaded subject; the predicate then provides
the Release metadata bound to that subject. Do not substitute an artifact from
another target merely because its file name is similar.
