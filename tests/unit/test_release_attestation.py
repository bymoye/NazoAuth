from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build_release_attestation.py"
TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}


class ReleaseAttestationBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = "x86_64-unknown-linux-gnu"
        self.binary = self.root / f"nazoauth-{self.target}"
        self.binary.write_bytes(b"server-binary")
        self.frontend = self.root / "frontend.json"
        self.frontend.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "nazozero/NazoAuthWeb",
                    "version": "v0.2.0",
                    "commit": "f" * 40,
                    "release_identity": (
                        "https://github.com/nazozero/NazoAuthWeb/"
                        ".github/workflows/release.yml@refs/tags/v0.2.0"
                    ),
                    "artifact": {
                        "repository": "nazozero/NazoAuthWeb",
                        "name": "nazoauth-web.tar.gz",
                        "sha256": "a" * 64,
                        "size": 123,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.oci = self.root / "oci.json"
        self.oci.write_text(
            json.dumps(
                {
                    "repository": "ghcr.io/nazozero/nazoauth",
                    "index_digest": "sha256:" + "b" * 64,
                    "platform_manifests": {
                        "linux/amd64": "sha256:" + "c" * 64,
                        "linux/arm64": "sha256:" + "d" * 64,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.output = self.root / "predicate.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *extra: str) -> list[str]:
        return [
            sys.executable,
            str(BUILDER),
            "--version",
            "v0.2.0",
            "--target",
            self.target,
            "--backend-commit",
            "e" * 40,
            "--build-id",
            "github:123:1",
            "--binary",
            str(self.binary),
            "--operator-compatibility",
            str(ROOT / "release" / "operator-compatibility.json"),
            "--frontend",
            str(self.frontend),
            "--oci",
            str(self.oci),
            "--policy",
            str(ROOT / "release" / "update-policy.json"),
            "--output",
            str(self.output),
            *extra,
        ]

    def test_builds_the_closed_schema_five_server_predicate(self) -> None:
        subprocess.run(self.command(), cwd=ROOT, check=True, capture_output=True, text=True)
        value = json.loads(self.output.read_text(encoding="utf-8"))

        self.assertEqual(
            set(value),
            {
                "schema",
                "version",
                "target",
                "backend_commit",
                "release_identity",
                "embedded",
                "operator_protocol",
                "artifacts",
                "frontend",
                "oci",
                "rollback",
            },
        )
        self.assertEqual(value["schema"], 5)
        self.assertEqual(value["target"], self.target)
        self.assertEqual(set(value["artifacts"]), {"binary"})
        self.assertEqual(value["artifacts"]["binary"]["repository"], "nazozero/NazoAuth")
        self.assertEqual(
            value["artifacts"]["binary"]["sha256"],
            hashlib.sha256(b"server-binary").hexdigest(),
        )
        self.assertEqual(value["embedded"]["release"], "v0.2.0")
        self.assertEqual(value["embedded"]["revision"], "e" * 40)
        self.assertEqual(value["embedded"]["protocol"], 1)
        self.assertEqual(
            value["operator_protocol"],
            {
                "version": 1,
                "minimum_ctl_version": "0.1.19",
                "maximum_ctl_version_exclusive": "0.2.0",
            },
        )
        self.assertEqual(set(value["oci"]["platform_manifests"]), {"linux/amd64", "linux/arm64"})

    def test_repository_frontend_descriptor_is_accepted_without_rewriting(self) -> None:
        self.frontend = ROOT / "release" / "frontend.json"
        subprocess.run(self.command(), cwd=ROOT, check=True, capture_output=True, text=True)
        value = json.loads(self.output.read_text(encoding="utf-8"))
        expected = json.loads(self.frontend.read_text(encoding="utf-8"))
        expected.pop("schema")
        self.assertEqual(value["frontend"], expected)

    def test_accepts_exactly_the_declared_release_targets(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        for target in TARGETS:
            self.assertIn(f'"{target}"', source)
        self.assertEqual(source.count("-unknown-linux-gnu\""), 2)
        self.assertEqual(source.count("-unknown-linux-musl\""), 2)
        self.assertEqual(source.count("-pc-windows-msvc\""), 2)
        self.assertEqual(source.count("-apple-darwin\""), 2)

    def test_rejects_unknown_descriptor_fields(self) -> None:
        value = json.loads(self.frontend.read_text(encoding="utf-8"))
        value["untrusted"] = True
        self.frontend.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("closed schema", result.stderr)

    def test_rejects_a_platform_manifest_gap(self) -> None:
        value = json.loads(self.oci.read_text(encoding="utf-8"))
        del value["platform_manifests"]["linux/arm64"]
        self.oci.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly linux/amd64 and linux/arm64", result.stderr)

    def test_rejects_frontend_identity_or_asset_name_outside_runtime_policy(self) -> None:
        value = json.loads(self.frontend.read_text(encoding="utf-8"))
        value["release_identity"] = value["release_identity"].replace(
            "/release.yml@", "/other.yml@"
        )
        self.frontend.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not bind", result.stderr)

        value["release_identity"] = value["release_identity"].replace(
            "/other.yml@", "/release.yml@"
        )
        value["artifact"]["name"] = "renamed-ui.tar.gz"
        self.frontend.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nazoauth-web.tar.gz", result.stderr)

    def test_rejects_artifact_name_target_confusion(self) -> None:
        self.binary.rename(self.root / "nazoauth-wrong-target")
        result = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected regular file", result.stderr)


if __name__ == "__main__":
    unittest.main()
