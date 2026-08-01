# Release Security

## Scope

Dependency, image, signing, and provenance checks are release gates. A release
artifact is not trusted until these gates pass for the exact commit or tag.

## Continuous Gates

The `conformance-security` workflow runs supply-chain checks for code,
dependency, migration, script, deployment, container, runtime config, and
workflow changes:

- `cargo audit` over `Cargo.lock`
- `cargo deny` using `deny.toml`
- CycloneDX SBOM generation for Rust dependencies
- container image build from `Containerfile`
- Trivy vulnerability scan of the built image
- SBOM upload as a workflow artifact

The supply-chain job is independent from the Rust unit/integration gate.
Dependency and image regressions fail before a deployment-shaped release is
trusted.

`dependency-review` also runs `cargo audit` on a weekly schedule, so a newly
published advisory is evaluated even when the repository has no new commit.
Dependabot and the single root `renovate.json` configuration cover Cargo,
GitHub Actions, container/Compose inputs, locked Python inputs, the exact Rust
stable pin, and the pinned security CLI versions. Renovate vulnerability
alerts are not restricted to the normal weekly update window.

## Tagged Release Gates

The `release-security` workflow runs for `v*` tags and manual dispatch:

- a tag-triggered run accepts only an exact stable `vMAJOR.MINOR.PATCH` tag;
  the tag without its `v` prefix must equal `[workspace.package].version`, and
  `cargo metadata --locked` must resolve every workspace member to that same
  version. A mismatch stops the policy job before artifacts are built or
  published
- a branch-triggered `workflow_dispatch` remains a non-publishing native-matrix
  rehearsal. It embeds `sha-<commit>` as the release identity, runs the policy,
  native tests, binary builds, and OCI assembly, and skips every tag-only
  attestation and publication job

- builds eight platform targets on native x86-64 and Arm64 Linux, Windows, and
  macOS runners with the pinned Rust toolchain
- runs the `nazoauthctl` tests and executes both binaries on every target
- verifies the application binary's embedded tag, commit, protocol, and build ID
- reruns `cargo audit` and `cargo deny` for the exact tag
- builds one `linux/amd64` plus `linux/arm64` OCI index
- scans the exact OCI archive with Trivy and publishes that archive without a
  second build
- generates separate CycloneDX SBOMs for both Rust binaries
- binds each binary to the closed schema-4 ReleaseManifest with the custom
  `https://nazo.run/attestations/release-manifest/v1` GitHub attestation
- binds the independently released and attested NazoAuthWeb descriptor rather
  than embedding or republishing UI files
- signs the OCI index; a rerun accepts an existing tag only when it resolves to
  the exact scanned digest and rejects every mismatch
- retains SBOMs, OCI archives, predicates, and Sigstore bundles as internal CI
  evidence
- publishes exactly 16 platform-suffixed executable files as persistent GitHub
  Release assets; JSON, tar, bundle, script, and SBOM files are not Release assets
- resumes partial publication only when every existing Release asset is
  byte-identical, and never overwrites a mismatching tag or asset
- emits standard provenance attestations in addition to the custom manifest
  predicates

Standalone production deployments consume the binaries through `nazoauthctl`.
The lifecycle tool retrieves the subject's GitHub attestation, verifies the
tag-specific workflow identity and closed predicate before parsing artifact
names or changing runtime state, and separately verifies the attested frontend
and OCI descriptors. Custom deployment pipelines must enforce the same
identity, digest, target, backup, and rollback-compatibility boundaries.

`nazoauthctl` does not download or install frontend files. The signed runtime
downloads the independently released frontend, verifies the descriptor's
archive digest and size, safely materializes its content-addressed cache, and
writes the exact descriptor marker. Lifecycle acceptance then requires that
marker, the cached `index.html`, and the bytes actually served from `/ui/` to
match; an unrelated successful HTTP response is not sufficient.

All controller GitHub requests are HTTPS-only across redirects and have
connection, redirect-count, total-time, and response-size bounds. Once an
attested artifact size is known, that exact size is the curl transfer ceiling;
only the first updater fetch uses a fixed bootstrap ceiling because its digest
is the subject used to retrieve the attestation. When host Cosign is absent,
the private temporary staging directory is mounted into the pinned Cosign
container as `ro,Z`: read-only with a private SELinux relabel, compatible with
Podman and Docker without sharing the label or adding container privileges.

The precise native target and managed-lifecycle qualification boundary is
documented in [platform-support.md](platform-support.md).

## Required Evidence

For each production release, preserve:

- Git tag and commit SHA
- `conformance-security` workflow URL and conclusion
- `release-security` workflow URL and conclusion
- all 16 binary asset names and digests
- each target's custom ReleaseManifest attestation URL
- both internal SBOM artifact names and digests
- Trivy scan result
- Sigstore certificate identity and issuer
- OCI index digest and both platform-manifest digests
- GitHub artifact attestation URLs and internal bundle references

Do not publish a release image if audit, deny, SBOM generation, image scanning,
signing, or provenance attestation fails.
