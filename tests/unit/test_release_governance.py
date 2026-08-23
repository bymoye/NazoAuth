from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseGovernanceTests(unittest.TestCase):
    def test_production_rust_sources_do_not_contain_suite_plan_specific_behavior(self) -> None:
        forbidden = re.compile(
            r"(?i)(?:conformance-suite|certification\.openid\.net|"
            r"oidcc-[a-z0-9-]+-test-plan|fapi2-[a-z0-9-]+-test-plan)"
        )
        offenders: list[str] = []
        for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
            if forbidden.search(path.read_text(encoding="utf-8")):
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(
            offenders,
            [],
            "production Rust sources must implement standards and conformance control planes, "
            "not Suite plan-specific behavior",
        )

    def test_runtime_container_copies_only_the_unified_product_binary(self) -> None:
        source = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("target=/usr/local/cargo/registry,sharing=locked", source)
        self.assertIn("target=/app/target,sharing=locked", source)
        self.assertIn(
            "COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./",
            source,
        )
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn(".env.*", dockerignore)
        self.assertIn("!.env.yaml.example", dockerignore)
        final_stage = source.split("FROM runtime-base AS runtime", 1)[1].split(
            "\nFROM ", 1
        )[0]
        self.assertNotIn("scripts/", final_stage)
        self.assertNotIn("tests/", final_stage)
        self.assertNotIn("docs/", final_stage)
        self.assertNotIn("oidf", final_stage.lower())
        self.assertEqual(final_stage.count("/usr/local/bin/nazoauth"), 1)
        self.assertNotIn("/usr/local/bin/nazoauthctl", final_stage)
        for retired_binary in (
            "nazo-oauth-server",
            "nazo-oauth-migrate",
            "nazo-oauth-keyctl",
        ):
            self.assertNotIn(retired_binary, final_stage)

    def test_release_oci_reuses_the_exact_native_application_binaries(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        containerfile = (ROOT / "Containerfile.release").read_text(encoding="utf-8")

        self.assertIn("container-image:\n    needs: platform-binaries", workflow)
        self.assertIn("release-binaries-x86_64-unknown-linux-gnu", workflow)
        self.assertIn("release-binaries-aarch64-unknown-linux-gnu", workflow)
        self.assertIn("file: Containerfile.release", workflow)
        self.assertNotIn("cargo build", containerfile)
        self.assertIn(
            "COPY target/release-container/${TARGETARCH}/nazoauth "
            "/usr/local/bin/nazoauth",
            containerfile,
        )
        self.assertNotIn("nazoauthctl", containerfile)

    def test_release_scans_a_validated_read_only_oci_layout(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        validator = (ROOT / "scripts" / "validate_release_oci.py").read_text(
            encoding="utf-8"
        )
        scan = workflow.split("- name: Scan the exact OCI archive before publication", 1)[
            1
        ].split("- name: Record the closed OCI descriptor", 1)[0]
        record = workflow.split("- name: Record the closed OCI descriptor", 1)[1].split(
            "- name: Upload OCI descriptor", 1
        )[0]

        self.assertIn('archive="${{ runner.temp }}/nazoauth-image.oci.tar"', scan)
        self.assertIn('layout="$(mktemp -d "${RUNNER_TEMP}/nazoauth-image.oci.XXXXXX")"', scan)
        self.assertIn("python3 scripts/validate_release_oci.py", scan)
        self.assertIn('--expected-index-digest "${{ steps.oci.outputs.digest }}"', scan)
        self.assertIn("--output target/release-evidence/oci/descriptor.json", scan)
        self.assertIn('tarfile.open(archive, mode="r:*")', validator)
        self.assertIn("member.isfile() or member.isdir()", validator)
        self.assertIn('or ".." in parts', validator)
        self.assertNotIn("extractall(", validator)
        self.assertIn('metadata != {"imageLayoutVersion": "1.0.0"}', validator)
        self.assertIn("OCI layout has unexpected root entries", validator)
        self.assertIn("OCI layout contains an unexpected directory", validator)
        self.assertIn("digest.hexdigest() != entry.name", validator)
        self.assertIn("OCI release index must contain exactly two images and two attestations", validator)
        self.assertIn("OCI layout contains unreferenced blobs", validator)
        self.assertIn('--security-opt no-new-privileges', scan)
        self.assertIn('-v "$layout:/image:ro"', scan)
        self.assertIn("--input /image", scan)
        self.assertIn("for platform in linux/amd64 linux/arm64; do", scan)
        self.assertIn('--platform "$platform"', scan)
        self.assertNotIn("--input /image.tar", scan)
        self.assertEqual(
            scan.count(
                "docker.io/aquasec/trivy:0.74.0@sha256:"
                "62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
            ),
            1,
        )
        self.assertIn('descriptor="target/release-evidence/oci/descriptor.json"', record)
        self.assertIn(".platform_manifests[\"linux/amd64\"]", record)
        self.assertIn(".platform_manifests[\"linux/arm64\"]", record)
        self.assertNotIn("skopeo inspect --raw", record)
        self.assertIn("tests.unit.test_release_oci", workflow)

    def test_public_quick_start_is_platform_neutral_verified_controller(self) -> None:
        public_guides = [
            ROOT / "README.md",
            ROOT / "README.zh-CN.md",
            ROOT / "docs" / "operations" / "deployment.md",
            ROOT / "docs" / "operations" / "deployment.zh-CN.md",
        ]
        forbidden = re.compile(
            r"(?i)(?:\.ps1\b|\bpwsh\b|\bpowershell\b|[a-z]:\\|/home/nazoauth\b)"
        )
        for path in public_guides:
            source = path.read_text(encoding="utf-8")
            self.assertIsNone(
                forbidden.search(source),
                f"{path.relative_to(ROOT)} exposes a host-specific deployment path",
            )

        for path in (ROOT / "README.md", ROOT / "README.zh-CN.md"):
            source = path.read_text(encoding="utf-8")
            self.assertIn("nazoauthctl install --runtime auto", source)
            self.assertIn("nazoauthctl doctor", source)
            self.assertIn("compose.yml", source)
            self.assertRegex(source.lower(), r"development|开发")
            self.assertNotIn("docker compose up -d --build", source)

    def test_compose_quick_start_is_self_contained_and_project_scoped(self) -> None:
        source = (ROOT / "compose.yml").read_text(encoding="utf-8")
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertNotIn("./deploy/compose/initialize-secrets.sh:", source)
        self.assertNotIn("${NAZOAUTH_CONFIG:-./.env.yaml.example}", source)
        self.assertIn("target: compose-secrets-init", source)
        self.assertIn(
            "COPY --chmod=0555 deploy/compose/initialize-secrets.sh", containerfile
        )
        self.assertIn(
            "COPY --from=product-builder /app/.env.yaml.example /app/.env.yaml",
            containerfile,
        )
        self.assertIn(
            "PUBLIC_BASE_URL: ${NAZOAUTH_PUBLIC_BASE_URL:-http://127.0.0.1:8000}",
            source,
        )
        self.assertIn(
            "NAZOAUTH_BUILD_REVISION: ${NAZOAUTH_BUILD_REVISION:-development}",
            source,
        )
        self.assertNotIn("ci_operator_task", source)
        self.assertIn("automation_operator_task prepare", source)
        self.assertIn("--deployment-id development-compose", source)
        self.assertIn("--actor-id docker-compose", source)
        self.assertIn("--embedded-release", source)
        self.assertIn("--embedded-revision", source)
        self.assertIn("--embedded-build-id", source)
        self.assertIn("$$(cat /run/nazoauth-secrets/revision)", source)
        self.assertIn('generate_hex_secret "$secret_dir/revision"', (
            ROOT / "deploy" / "compose" / "initialize-secrets.sh"
        ).read_text(encoding="utf-8"))
        self.assertNotIn(
            "ci_operator_task",
            (ROOT / "docker-compose.perf.yml").read_text(encoding="utf-8"),
        )
        self.assertIn(
            '"${NAZOAUTH_BIND_ADDRESS:-127.0.0.1}:${NAZOAUTH_PORT:-8000}:8000"',
            source,
        )
        self.assertIn("condition: service_completed_successfully", source)
        self.assertIn("keys_data:/var/lib/nazo_oauth/keys", source)
        self.assertIn("avatars_data:/var/lib/nazo_oauth/avatars", source)
        self.assertIn("ui_releases:/state/ui-releases", source)
        self.assertIn("ui_releases:/var/lib/nazo_oauth/ui-releases", source)
        self.assertNotIn("container_name:", source)
        self.assertNotIn("ipv4_address:", source)
        self.assertNotIn("name: nazo_oauth_net", source)

    def test_public_bootstrap_requires_an_attested_release_reader(self) -> None:
        for name in ("one-click-update.md", "one-click-update.zh-CN.md"):
            source = (ROOT / "docs" / "operations" / name).read_text(encoding="utf-8")
            self.assertIn("`python3`", source)
            self.assertIn("`sha256sum`", source)
            self.assertIn("`install`", source)
            self.assertNotIn("controller-keyed HMAC", source)
            self.assertNotIn("使用 controller key 计算", source)
            self.assertIn("GitHub CLI", source)
            self.assertRegex(source, r"public non-draft Release|公开非草稿 Release")

    def test_server_release_builds_only_the_application_executable(self) -> None:
        server_manifest = (
            ROOT / "crates" / "authorization-server" / "Cargo.toml"
        ).read_text(encoding="utf-8")
        ctl_manifest = ROOT / "crates" / "nazoauthctl" / "Cargo.toml"
        self.assertEqual(server_manifest.count("[[bin]]"), 1)
        self.assertIn('name = "nazoauth"', server_manifest)
        self.assertFalse(ctl_manifest.exists())

        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo build --release --locked --target ${{ matrix.target }}", release)
        self.assertIn("--package nazo-oauth-server --bin nazoauth", release)
        self.assertNotIn("--package nazoauthctl --bin nazoauthctl", release)
        self.assertIn("nazoauth-${{ matrix.target }}", release)
        self.assertNotIn("nazoauthctl-${{ matrix.target }}", release)
        self.assertNotRegex(
            release,
            r"target/release/nazo-oauth-(?:server|migrate|keyctl)",
        )

    def test_tag_release_requires_the_exact_workspace_package_version(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        validation = release.split("- name: Validate immutable release input", 1)[1].split(
            "- name: Verify the independently released frontend subject", 1
        )[0]

        self.assertIn('if [[ "$GITHUB_REF_TYPE" = tag ]]; then', validation)
        self.assertIn(
            '[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]',
            validation,
        )
        self.assertNotIn("[0-9A-Za-z.-]+", validation)
        self.assertIn('release_version="${GITHUB_REF_NAME#v}"', validation)
        self.assertIn('["workspace"]["package"]["version"]', validation)
        self.assertIn(
            "cargo metadata --locked --no-deps --format-version 1", validation
        )
        self.assertIn(".workspace_members[] as $member", validation)
        self.assertIn("select(.id == $member and .version != $version)", validation)
        self.assertIn("does not match workspace package versions", validation)

        policy = release.split("  policy:", 1)[1].split("  platform-binaries:", 1)[0]
        self.assertLess(
            policy.index("uses: dtolnay/rust-toolchain@"),
            policy.index("- name: Validate immutable release input"),
        )

    def test_tag_release_requires_successful_governed_ci_for_the_exact_commit(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "actions: read",
            "NAZOAUTH_RELEASE_BRANCH: agent/extract-nazoauthctl",
            "printf 'x-access-token:%s' \"$GH_TOKEN\" | base64 -w 0",
            "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic_auth",
            "refs/heads/main:refs/remotes/origin/main",
            '"refs/heads/$NAZOAUTH_RELEASE_BRANCH:$release_ref"',
            'git merge-base --is-ancestor "$RELEASE_SHA" refs/remotes/origin/main',
            '[[ "$(git rev-parse "$release_ref")" = "$RELEASE_SHA" ]]',
            "gate_event=push",
            "gate_branch=main",
            "gate_event=workflow_dispatch",
            "gate_branch=$NAZOAUTH_RELEASE_BRANCH",
            'neither reachable from main nor the exact release branch head',
            "/actions/workflows/${workflow}/runs",
            '-f event="$gate_event"',
            '-f branch="$gate_branch"',
            '-f head_sha="$RELEASE_SHA"',
            "for workflow in code-quality.yml release-policy.yml; do",
            '.head_sha == $sha',
            '.head_branch == $branch',
            '.event == $event',
            '.status == "completed"',
            '.conclusion == "success"',
        ):
            self.assertIn(required, release)

        gate = release.split(
            "- name: Require successful governed CI for exact tag commit", 1
        )[1].split("- uses: dtolnay/rust-toolchain@", 1)[0]
        self.assertNotIn("github.ref_type == 'tag'", gate)

        policy = (
            ROOT / ".github" / "workflows" / "release-policy.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("push:\n    branches: [main]", policy)
        self.assertIn('      - "release/**"', policy)

        quality = (
            ROOT / ".github" / "workflows" / "code-quality.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(quality.count('      - "release/**"'), 2)

    def test_pull_request_coverage_never_sends_the_codecov_token(self) -> None:
        coverage = (
            ROOT / ".github" / "workflows" / "codecov.yml"
        ).read_text(encoding="utf-8")
        upload = coverage.split("- name: Upload coverage to Codecov", 1)[1].split(
            "- name: Verify complete Git patch coverage", 1
        )[0]
        self.assertIn("if: github.event_name != 'pull_request'", upload)
        self.assertIn("token: ${{ secrets.CODECOV_TOKEN }}", upload)

    def test_branch_dispatch_keeps_the_native_matrix_without_publishing(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        platform_binaries = release.split("  platform-binaries:", 1)[1].split(
            "  container-image:", 1
        )[0]

        self.assertIn("workflow_dispatch:", release)
        self.assertIn("    needs: policy", platform_binaries)
        self.assertNotIn("github.ref_type == 'tag'", platform_binaries)
        for job in (
            "attest-platform-binaries",
            "attest-operator-protocol",
            "publish-container",
            "publish-release",
        ):
            self.assertRegex(
                release,
                rf"(?m)^  {re.escape(job)}:\n    if: github\.ref_type == 'tag'$",
                job,
            )

    def test_platform_binaries_use_canonical_attestations_without_duplicate_signing(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        attestation_job = release.split("  attest-platform-binaries:", 1)[1].split(
            "  attest-operator-protocol:", 1
        )[0]

        self.assertIn("actions/attest@", attestation_job)
        self.assertIn("actions/attest-build-provenance@", attestation_job)
        self.assertNotIn("cosign sign-blob", attestation_job)
        self.assertNotIn("release-evidence/signatures", attestation_job)

    def test_release_matrix_is_native_smoked_and_server_only(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        targets = {
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        }
        for target in targets:
            self.assertGreaterEqual(release.count(f"target: {target}"), 1, target)
        for runner in (
            "ubuntu-24.04",
            "ubuntu-24.04-arm",
            "windows-2025",
            "windows-11-arm",
            "macos-15-intel",
            "macos-15",
        ):
            self.assertIn(f"runner: {runner}", release)
        self.assertNotIn("cargo test --locked --package nazoauthctl --all-targets", release)
        self.assertIn("& $server build-identity | ConvertFrom-Json", release)
        self.assertIn("Verify Linux single-file native dependency boundary", release)
        self.assertIn("Bind musl builds to the native musl compiler", release)
        self.assertIn('echo "$cc_variable=musl-gcc"', release)
        self.assertIn('echo "$linker_variable=musl-gcc"', release)
        self.assertIn("platforms: linux/amd64,linux/arm64", release)
        self.assertIn(
            "outputs: type=oci,dest=${{ runner.temp }}/nazoauth-image.oci.tar,"
            "name=ghcr.io/nazozero/nazoauth:${{ env.NAZOAUTH_BUILD_RELEASE }},"
            "oci-artifact=true",
            release,
        )
        scan = release.split(
            "- name: Scan the exact OCI archive before publication", 1
        )[1].split("- name: Record the closed OCI descriptor", 1)[0]
        self.assertLess(
            scan.index('chmod -R go+rX "$layout"'),
            scan.index("docker run --rm"),
        )
        self.assertIn("Publish the exact scanned OCI index without rebuilding", release)
        self.assertIn(
            "msvc_component: Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            release,
        )
        self.assertIn(
            "msvc_component: Microsoft.VisualStudio.Component.VC.Tools.ARM64",
            release,
        )
        self.assertIn(
            '$installation = & $vswhere -latest -products * -requires $component -property installationPath',
            release,
        )
        self.assertIn(
            'Get-ChildItem -LiteralPath "$env:MSVC_INSTALLATION\\VC\\Tools\\MSVC"',
            release,
        )
        self.assertEqual(release.count("Microsoft.VisualStudio.Component.VC.Tools.ARM64"), 1)
        action_refs = re.findall(r"uses:\s+[^\s@]+@([^\s#]+)", release)
        self.assertTrue(action_refs)
        for action_ref in action_refs:
            self.assertRegex(action_ref, r"^[0-9a-f]{40}$")

        publish = release.split(
            "name: Publish immutable server and protocol GitHub Release assets", 1
        )[1]
        self.assertIn("target/release-binaries/*", publish)
        for forbidden in (".tar", ".json", ".bundle", "SBOM", "install_nazoauthctl"):
            self.assertNotIn(forbidden, publish)

    def test_operator_protocol_is_packaged_attested_and_published_once(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")

        package_job = release.split("  operator-protocol-package:", 1)[1].split(
            "  platform-binaries:", 1
        )[0]
        self.assertIn(
            "cargo package --locked --package nazo-operator-protocol", package_job
        )
        self.assertNotIn("--no-verify", package_job)
        self.assertIn("release-operator-protocol-package", package_job)

        attest_job = release.split("  attest-operator-protocol:", 1)[1].split(
            "  publish-container:", 1
        )[0]
        self.assertIn("needs: operator-protocol-package", attest_job)
        self.assertIn("actions/attest-build-provenance@", attest_job)
        self.assertIn("steps.protocol_package.outputs.path", attest_job)

        publish = release.split(
            "name: Publish immutable server and protocol GitHub Release assets", 1
        )[1]
        self.assertIn(
            'protocol_asset="nazo-operator-protocol-${GITHUB_REF_NAME#v}.crate"',
            publish,
        )
        self.assertIn('test "$(wc -l < "$allowed_names")" -eq 9', publish)
        self.assertIn(
            'diff -u "$allowed_names" <(sort "$remote_names")', publish
        )

    def test_each_release_binary_gets_the_closed_custom_attestation(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            release.count("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"),
            1,
        )
        self.assertEqual(
            release.count("predicate-type: https://nazo.run/attestations/release-manifest/v1"),
            1,
        )
        self.assertIn("scripts/build_release_attestation.py", release)
        self.assertIn("--frontend release/frontend.json", release)
        self.assertIn("--oci target/release-evidence/oci/descriptor.json", release)
        self.assertIn("--operator-compatibility release/operator-compatibility.json", release)

    def test_conformance_workflow_does_not_repeat_the_rust_quality_gate(self) -> None:
        quality = (
            ROOT / ".github" / "workflows" / "code-quality.yml"
        ).read_text(encoding="utf-8")
        conformance = (
            ROOT / ".github" / "workflows" / "conformance-security.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2",
            quality,
        )
        self.assertIn("cargo clippy --workspace --all-targets", quality)
        self.assertIn("cargo test --workspace --all-features", quality)
        self.assertNotIn("cargo check --workspace", quality)
        self.assertNotIn("cargo check --workspace", conformance)
        self.assertNotIn("cargo clippy --workspace", conformance)
        self.assertNotIn("cargo test --workspace", conformance)

    def test_conformance_workflow_reuses_the_scanned_service_image(self) -> None:
        conformance = (
            ROOT / ".github" / "workflows" / "conformance-security.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(conformance.count("file: Containerfile"), 1)
        self.assertIn("name: Upload scanned service image", conformance)
        self.assertIn("name: Download scanned service image", conformance)
        self.assertIn("sha256sum --check nazo-oauth-service.tar.sha256", conformance)
        self.assertIn("docker load --input target/ci-service-image/nazo-oauth-service.tar", conformance)

    def test_conformance_operator_task_mounts_secret_revision_authority(self) -> None:
        conformance = (
            ROOT / ".github" / "workflows" / "conformance-security.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('secret_revision=ci-secret-revision', conformance)
        self.assertIn(
            'printf \'%s\' "$secret_revision" >runtime/e2e/operator/secret-revision',
            conformance,
        )
        self.assertIn("chmod 0400 runtime/e2e/operator/secret-revision", conformance)
        self.assertIn(
            "operator/secret-revision:/run/nazoauth-operator/secret-revision:ro",
            conformance,
        )

    def test_official_suite_is_never_patched(self) -> None:
        tracked = [
            *sorted((ROOT / "scripts").rglob("*.py")),
            *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
        ]
        offenders = []
        for path in tracked:
            if not path.is_file():
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
            if "apply_oidf_runner_patch" in source or "oidf-v5.2.0-terminal-info.patch" in source:
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(offenders, [])

    def test_heavy_pull_request_workflows_do_not_match_docs_only_changes(self) -> None:
        for name in (
            "code-quality.yml",
            "codecov.yml",
            "codeql.yml",
            "conformance-security.yml",
            "dependency-review.yml",
        ):
            source = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            pull_request = source.split("pull_request:", 1)[1].split("workflow_dispatch:", 1)[0]
            self.assertIn("paths:", pull_request, name)
            self.assertNotRegex(pull_request, r'(?m)^\s+-\s+"?(?:README\.md|docs/\*\*)"?\s*$')

    def test_codeql_security_page_excludes_quality_only_queries(self) -> None:
        source = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("queries: security-extended", source)
        self.assertNotIn("security-and-quality", source)

    def test_performance_images_have_path_scoped_build_and_smoke_checks(self) -> None:
        source = (ROOT / ".github" / "workflows" / "perf-images.yml").read_text(
            encoding="utf-8"
        )
        pull_request = source.split("pull_request:", 1)[1].split("push:", 1)[0]
        self.assertIn('"perf/**"', pull_request)
        self.assertIn('"scripts/ensure_runtime_keyset.py"', pull_request)
        self.assertIn("perf/runner/Containerfile", source)
        self.assertIn("perf/keyset/Containerfile", source)
        self.assertIn("performance dependencies import successfully", source)
        self.assertIn("test -s /tmp/keys/keyset.json", source)

    def test_proptest_regression_corpus_is_versioned(self) -> None:
        corpus = ROOT / "proptest-regressions" / "support"
        self.assertTrue((corpus / "responses.txt").is_file())
        self.assertTrue((corpus / "uri_policy.txt").is_file())

    def test_documented_secret_inventory_matches_workflow_references(self) -> None:
        referenced: set[str] = set()
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            referenced.update(
                re.findall(r"secrets\.([A-Z][A-Z0-9_]*)", path.read_text(encoding="utf-8"))
            )
        documented = set(
            re.findall(
                r"(?m)^\| `([A-Z][A-Z0-9_]*)`(?:, `([A-Z][A-Z0-9_]*)`)? \|",
                (ROOT / "docs" / "operations" / "github-actions-secrets.md").read_text(
                    encoding="utf-8"
                ),
            )
        )
        documented = {name for pair in documented for name in pair if name}
        self.assertEqual(referenced, documented)


if __name__ == "__main__":
    unittest.main()
