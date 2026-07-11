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

## Tagged Release Gates

The `release-security` workflow runs for `v*` tags and manual dispatch:

- builds the release binaries with the pinned Rust toolchain
- builds the container image
- exports the container image as a release artifact
- generates a CycloneDX Rust SBOM
- signs the binaries, SBOM, and image archive with keyless Sigstore signing through GitHub OIDC
- uploads binaries, SBOM, image archive, and signature bundles as GitHub Actions artifacts
- emits GitHub artifact provenance attestations for the binaries, SBOM, and image archive

Downstream deployments consume artifacts from a successful tagged release workflow, or repeat the same checks in their own release pipeline.

## Required Evidence

For each production release, preserve:

- Git tag and commit SHA
- `conformance-security` workflow URL and conclusion
- `release-security` workflow URL and conclusion
- SBOM artifact name and digest
- Trivy scan result
- Sigstore certificate identity and issuer
- GitHub artifact attestation URLs or bundle references

Do not publish a release image if audit, deny, SBOM generation, image scanning,
signing, or provenance attestation fails.
