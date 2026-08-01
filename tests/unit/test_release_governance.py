from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseGovernanceTests(unittest.TestCase):
    def test_production_rust_sources_do_not_contain_oidf_specific_behavior(self) -> None:
        forbidden = re.compile(
            r"(?i)(?:\boidf\b|conformance-suite|certification\.openid\.net|"
            r"oidcc-[a-z0-9-]+-test-plan|fapi2-[a-z0-9-]+-test-plan)"
        )
        offenders: list[str] = []
        for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
            if forbidden.search(path.read_text(encoding="utf-8")):
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(
            offenders,
            [],
            "production Rust sources must implement standards, not OIDF plan-specific behavior",
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

    def test_public_quick_start_is_platform_neutral_verified_controller(self) -> None:
        public_guides = [
            ROOT / "README.md",
            ROOT / "README.zh-CN.md",
            ROOT / "docs" / "operations" / "deployment.md",
            ROOT / "docs" / "operations" / "deployment.zh-CN.md",
            ROOT / "docs" / "operations" / "fresh-production-activation.md",
            ROOT / "docs" / "operations" / "fresh-production-activation.zh-CN.md",
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
        self.assertIn("${NAZOAUTH_CONFIG:-./.env.yaml.example}", source)
        self.assertIn('"127.0.0.1:${NAZOAUTH_PORT:-8000}:8000"', source)
        self.assertIn("condition: service_completed_successfully", source)
        self.assertIn("keys_data:/var/lib/nazo_oauth/keys", source)
        self.assertIn("avatars_data:/var/lib/nazo_oauth/avatars", source)
        self.assertNotIn("container_name:", source)
        self.assertNotIn("ipv4_address:", source)
        self.assertNotIn("name: nazo_oauth_net", source)

    def test_release_builds_one_application_and_one_lifecycle_executable(self) -> None:
        server_manifest = (
            ROOT / "crates" / "authorization-server" / "Cargo.toml"
        ).read_text(encoding="utf-8")
        ctl_manifest = (
            ROOT / "crates" / "nazoauthctl" / "Cargo.toml"
        ).read_text(encoding="utf-8")
        self.assertEqual(server_manifest.count("[[bin]]"), 1)
        self.assertIn('name = "nazoauth"', server_manifest)
        self.assertEqual(ctl_manifest.count("[[bin]]"), 1)
        self.assertIn('name = "nazoauthctl"', ctl_manifest)

        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo build --release --locked --target ${{ matrix.target }}", release)
        self.assertIn("--package nazo-oauth-server --bin nazoauth", release)
        self.assertIn("--package nazoauthctl --bin nazoauthctl", release)
        self.assertIn("nazoauth-${{ matrix.target }}", release)
        self.assertIn("nazoauthctl-${{ matrix.target }}", release)
        self.assertNotRegex(
            release,
            r"target/release/nazo-oauth-(?:server|migrate|keyctl)",
        )

    def test_release_matrix_is_native_smoked_and_binary_only(self) -> None:
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
        self.assertIn("cargo test --locked --package nazoauthctl --all-targets", release)
        self.assertIn("& $server build-identity | ConvertFrom-Json", release)
        self.assertIn("Verify Linux single-file native dependency boundary", release)
        self.assertIn("Bind musl builds to the native musl compiler", release)
        self.assertIn('echo "$cc_variable=musl-gcc"', release)
        self.assertIn('echo "$linker_variable=musl-gcc"', release)
        self.assertIn("platforms: linux/amd64,linux/arm64", release)
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

        publish = release.split("name: Publish immutable binary-only GitHub Release assets", 1)[1]
        self.assertIn("target/release-binaries/*", publish)
        for forbidden in (".tar", ".json", ".bundle", "SBOM", "install_nazoauthctl"):
            self.assertNotIn(forbidden, publish)

    def test_each_release_binary_gets_the_closed_custom_attestation(self) -> None:
        release = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            release.count("uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"),
            2,
        )
        self.assertEqual(
            release.count("predicate-type: https://nazo.run/attestations/release-manifest/v1"),
            2,
        )
        self.assertIn("scripts/build_release_attestation.py", release)
        self.assertIn("--frontend release/frontend.json", release)
        self.assertIn("--oci target/release-evidence/oci/descriptor.json", release)

    def test_conformance_workflow_does_not_repeat_the_rust_quality_gate(self) -> None:
        quality = (
            ROOT / ".github" / "workflows" / "code-quality.yml"
        ).read_text(encoding="utf-8")
        conformance = (
            ROOT / ".github" / "workflows" / "conformance-security.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("Swatinem/rust-cache@v2.9.1", quality)
        self.assertIn("cargo clippy --workspace --all-targets", quality)
        self.assertIn("cargo test --workspace --all-features", quality)
        self.assertNotIn("cargo check --workspace", quality)
        self.assertNotIn("cargo check --workspace", conformance)
        self.assertNotIn("cargo clippy --workspace", conformance)
        self.assertNotIn("cargo test --workspace", conformance)

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
