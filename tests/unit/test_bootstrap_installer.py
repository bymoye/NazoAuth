from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install_nazoauthctl.sh"
REPOSITORY = "nazozero/NazoAuth"
VERSION = "v0.1.4"
TARGET = "x86_64-unknown-linux-gnu"
ARTIFACT = f"nazoauthctl-{TARGET}"
UPDATER = b"#!/bin/sh\nexit 0\n"
DIGEST = hashlib.sha256(UPDATER).hexdigest()
COMMIT = "b" * 40
IDENTITY = (
    f"https://github.com/{REPOSITORY}/.github/workflows/"
    f"release-security.yml@refs/tags/{VERSION}"
)


def der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 128:
        encoded_length = bytes([length])
    else:
        width = (length.bit_length() + 7) // 8
        encoded_length = bytes([0x80 | width]) + length.to_bytes(width, "big")
    return bytes([tag]) + encoded_length + content


def oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(groups))
    return der(0x06, bytes(encoded))


def fake_certificate(runner: str) -> bytes:
    extension = der(
        0x30,
        oid("1.3.6.1.4.1.57264.1.11")
        + der(0x04, der(0x0C, runner.encode("utf-8"))),
    )
    extensions = der(0xA3, der(0x30, extension))
    tbs_certificate = der(0x30, extensions)
    return der(0x30, tbs_certificate + der(0x30, b"") + der(0x03, b"\x00"))


def descriptor(repository: str, name: str, digest: str, size: int) -> dict[str, object]:
    return {
        "repository": repository,
        "name": name,
        "sha256": digest,
        "size": size,
    }


def manifest() -> dict[str, object]:
    return {
        "schema": 4,
        "version": VERSION,
        "target": TARGET,
        "backend_commit": COMMIT,
        "release_identity": IDENTITY,
        "embedded": {
            "release": VERSION,
            "revision": COMMIT,
            "protocol": 1,
            "build_id": "github:1:1",
        },
        "artifacts": {
            "binary": descriptor(REPOSITORY, f"nazoauth-{TARGET}", "a" * 64, 1),
            "updater": descriptor(REPOSITORY, ARTIFACT, DIGEST, len(UPDATER)),
        },
        "frontend": {
            "repository": "nazozero/NazoAuthWeb",
            "version": "v0.1.0",
            "commit": "c" * 40,
            "release_identity": (
                "https://github.com/nazozero/NazoAuthWeb/.github/workflows/"
                "release.yml@refs/tags/v0.1.0"
            ),
            "artifact": descriptor(
                "nazozero/NazoAuthWeb", "nazoauth-web.tar.gz", "d" * 64, 1
            ),
        },
        "oci": {
            "repository": "ghcr.io/nazozero/nazoauth",
            "index_digest": f"sha256:{'e' * 64}",
            "platform_manifests": {
                "linux/amd64": f"sha256:{'f' * 64}",
                "linux/arm64": f"sha256:{'1' * 64}",
            },
        },
        "rollback": {
            "artifact": True,
            "schema_compatible": True,
            "database_restore": "backup",
            "irreversible_migration": False,
            "minimum_supported_version": "0.1.4",
            "migration_floor": "20260729000000",
            "rationale": "test fixture",
        },
    }


def attestation(predicate: dict[str, object] | None = None, runner: str = "github-hosted") -> dict[str, object]:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": ARTIFACT, "digest": {"sha256": DIGEST}}],
        "predicateType": "https://nazo.run/attestations/release-manifest/v1",
        "predicate": predicate or manifest(),
    }
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [],
            "timestampVerificationData": {},
            "certificate": {
                "rawBytes": base64.b64encode(fake_certificate(runner)).decode("ascii")
            },
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(
                json.dumps(statement, separators=(",", ":")).encode("utf-8")
            ).decode("ascii"),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        },
    }
    return {
        "bundle_url": "https://api.github.com/example",
        "repository_id": 1,
        "initiator": "github-actions[bot]",
        "bundle": bundle,
    }


class BootstrapInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")
        match = re.search(
            r"cat > \"\$temporary/verify_attestations\.py\" <<'PY'\n(.*?)\nPY\n",
            cls.source,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError("embedded attestation verifier was not found")
        cls.verifier = match.group(1) + "\n"

    def run_verifier(self, attestations: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
        temporary = tempfile.TemporaryDirectory(prefix="nazoauth-bootstrap-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        verifier = root / "verify_attestations.py"
        verifier.write_text(self.verifier, encoding="utf-8", newline="\n")
        artifact = root / ARTIFACT
        artifact.write_bytes(UPDATER)
        response = root / "attestations.json"
        response.write_text(
            json.dumps({"attestations": attestations}), encoding="utf-8", newline="\n"
        )
        return subprocess.run(
            [
                sys.executable,
                str(verifier),
                str(response),
                str(artifact),
                REPOSITORY,
                VERSION,
                TARGET,
                IDENTITY,
                DIGEST,
                str(root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_bootstrap_has_no_authenticated_github_cli_boundary(self) -> None:
        self.assertNotIn("command -v gh", self.source)
        self.assertNotIn("gh release", self.source)
        self.assertNotIn("gh attestation", self.source)
        self.assertNotIn("GH_TOKEN", self.source)
        self.assertIn("https://api.github.com/repos/$repository/releases/latest", self.source)
        self.assertIn("/attestations/sha256%3A$artifact_digest", self.source)
        self.assertIn("--max-filesize", self.source)
        self.assertIn("release-assets.githubusercontent.com", self.source)

    def test_bootstrap_pins_cosign_and_all_certificate_identity_claims(self) -> None:
        self.assertIn(
            "ghcr.io/sigstore/cosign/cosign@sha256:"
            "de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00",
            self.source,
        )
        self.assertIn("--certificate-identity", self.source)
        self.assertIn("--certificate-oidc-issuer", self.source)
        self.assertIn("--certificate-github-workflow-repository", self.source)
        self.assertIn("--certificate-github-workflow-ref", self.source)
        self.assertIn("--certificate-github-workflow-sha", self.source)
        self.assertIn('RUNNER_ENVIRONMENT_OID = "1.3.6.1.4.1.57264.1.11"', self.source)
        self.assertIn('values != ["github-hosted"]', self.source)

    def test_closed_manifest_and_github_hosted_candidate_is_accepted(self) -> None:
        completed = self.run_verifier([attestation()])
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_self_hosted_runner_certificate_is_rejected(self) -> None:
        completed = self.run_verifier([attestation(runner="self-hosted")])
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not created by a GitHub-hosted runner", completed.stderr)

    def test_conflicting_matching_predicates_are_rejected(self) -> None:
        conflicting = manifest()
        conflicting["backend_commit"] = "9" * 40
        embedded = dict(conflicting["embedded"])
        embedded["revision"] = "9" * 40
        conflicting["embedded"] = embedded
        completed = self.run_verifier([attestation(), attestation(conflicting)])
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("conflicting predicates", completed.stderr)

    def test_updater_digest_substitution_is_rejected(self) -> None:
        substituted = manifest()
        artifacts = dict(substituted["artifacts"])
        updater = dict(artifacts["updater"])
        updater["sha256"] = "9" * 64
        artifacts["updater"] = updater
        substituted["artifacts"] = artifacts
        completed = self.run_verifier([attestation(substituted)])
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not bind the downloaded updater", completed.stderr)

    def test_shell_syntax_is_valid_when_sh_is_available(self) -> None:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("sh is not installed on this platform")
        completed = subprocess.run(
            [shell, "-n", str(INSTALLER)], check=False, capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_public_bootstrap_succeeds_without_calling_gh(self) -> None:
        if os.name != "posix":
            self.skipTest("end-to-end bootstrap harness requires a POSIX host")
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("sh is not installed on this platform")
        temporary = tempfile.TemporaryDirectory(prefix="nazoauth-bootstrap-e2e-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fixture = root / "attestations.json"
        fixture.write_text(
            json.dumps({"attestations": [attestation()]}), encoding="utf-8", newline="\n"
        )

        def executable(name: str, content: str) -> None:
            path = fake_bin / name
            path.write_text(content, encoding="utf-8", newline="\n")
            path.chmod(0o755)

        executable(
            "curl",
            f"""#!{sys.executable}
import os
import shutil
import sys

args = sys.argv[1:]
output = args[args.index("--output") + 1]
url = args[-1]
if url.endswith("/releases/latest"):
    with open(output, "w", encoding="utf-8") as destination:
        destination.write('{{"tag_name":"{VERSION}"}}')
    print(url, end="")
elif "/releases/download/" in url:
    with open(output, "wb") as destination:
        destination.write({UPDATER!r})
    print("https://release-assets.githubusercontent.com/test", end="")
elif "/attestations/" in url:
    shutil.copyfile(os.environ["BOOTSTRAP_ATTESTATION_FIXTURE"], output)
    print(url, end="")
else:
    raise SystemExit("unexpected URL: " + url)
""",
        )
        executable("gh", "#!/bin/sh\nexit 99\n")
        executable(
            "podman",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$BOOTSTRAP_COSIGN_LOG\"\nexit 0\n",
        )
        executable(
            "install",
            "#!/bin/sh\nsource=$7\ndestination=$8\ncp \"$source\" \"$destination\"\nchmod 0755 \"$destination\"\n",
        )
        installed = root / "nazoauthctl"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "BOOTSTRAP_ATTESTATION_FIXTURE": str(fixture),
                "BOOTSTRAP_COSIGN_LOG": str(root / "cosign.log"),
            }
        )
        completed = subprocess.run(
            [
                shell,
                str(INSTALLER),
                "--version",
                VERSION,
                "--install-path",
                str(installed),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(installed.is_file())
        cosign = (root / "cosign.log").read_text(encoding="utf-8")
        self.assertIn("verify-blob-attestation", cosign)
        self.assertIn("--certificate-github-workflow-sha", cosign)


if __name__ == "__main__":
    unittest.main()
