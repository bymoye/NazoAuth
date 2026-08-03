from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "scripts" / "prepare_host_local_oidf_install.py"
    spec = importlib.util.spec_from_file_location("prepare_host_local_oidf_install", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_material() -> dict[str, object]:
    material: dict[str, object] = {
        "trust_anchor_pem": "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
    }
    for index, name in enumerate(
        ("wallet_private", "wallet_attested", "client_attestation", "key_attestation", "credential")
    ):
        material[name] = {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": f"kid-{index}",
            "x": f"x-{index}",
            "y": f"y-{index}",
            "d": f"d-{index}",
            "x5c": [f"certificate-{index}"],
        }
    return material


class PrepareHostLocalOidfInstallTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_prepares_exact_source_bound_public_and_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = (Path(temporary) / "prepared").resolve()
            material = fake_material()
            with (
                mock.patch.object(self.module, "verify_source") as verify,
                mock.patch.object(
                    self.module.host_local,
                    "generate_certificate_material",
                    return_value=material,
                ),
            ):
                result = self.module.prepare(
                    source_dir=ROOT,
                    source_commit="a" * 40,
                    suite_origin="https://suite.example/",
                    output_dir=output,
                )

            self.assertEqual(result, output)
            verify.assert_called_once_with(ROOT.resolve(), "a" * 40, "host-local preparation")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    self.module.PROFILE_FILE,
                    self.module.TRUST_FILE,
                    self.module.MATERIAL_FILE,
                    self.module.MANIFEST_FILE,
                },
            )
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                self.assertTrue(
                    all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
                )
            profile = json.loads((output / self.module.PROFILE_FILE).read_text())
            private = json.loads((output / self.module.MATERIAL_FILE).read_text())
            trust = json.loads((output / self.module.TRUST_FILE).read_text())
            manifest = json.loads((output / self.module.MANIFEST_FILE).read_text())
            self.assertNotIn('"d"', json.dumps(profile))
            self.assertNotIn('"d"', json.dumps(trust))
            self.assertIn('"d"', json.dumps(private))
            self.assertNotIn("client_attestation_issuer", profile)
            self.assertEqual(trust["client_attestation_issuer"], "https://suite.example/")
            self.assertEqual(manifest["source_commit"], "a" * 40)
            self.assertEqual(manifest["suite_origin"], "https://suite.example")
            for filename, digest in manifest["files"].items():
                self.assertEqual(
                    hashlib.sha256((output / filename).read_bytes()).hexdigest(), digest
                )

    def test_refuses_to_overwrite_an_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = (Path(temporary) / "prepared").resolve()
            output.mkdir()
            with self.assertRaisesRegex(self.module.PreparationError, "must not already exist"):
                self.module.prepare(
                    source_dir=ROOT,
                    source_commit="a" * 40,
                    suite_origin="https://suite.example",
                    output_dir=output,
                )


if __name__ == "__main__":
    unittest.main()
