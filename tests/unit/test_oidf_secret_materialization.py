import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load_script(name: str):
    script = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(f"{script.stem}_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class OidfSecretMaterializationTests(unittest.TestCase):
    def test_full_github_bridge_writes_only_private_declared_files(self):
        module = load_script("materialize_github_oidf_secrets.py")
        values = {
            "OIDF_PLAN_CONFIG_AGE_IDENTITY": "AGE-SECRET-KEY-test",
            "OIDF_MTLS_MATERIAL_AGE_IDENTITY": "AGE-SECRET-KEY-mtls",
            "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN": "dcr-token",
            "OIDF_CIBA_AUTOMATED_DECISION_TOKEN": "ciba-token",
            "OIDF_CONFORMANCE_TOKEN": "suite-token",
            "OIDF_DELIVERED_CLIENT_MATERIAL_JSON": '{"clients":[]}',
            "OIDF_USER_EMAIL": "applicant@example.test",
            "OIDF_USER_PASSWORD": "applicant-password",
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "secrets"
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, values, clear=True), contextlib.redirect_stdout(stdout):
                module.materialize(output)

            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "plan-config.agekey",
                    "mtls-material.agekey",
                    "dynamic-registration-token",
                    "ciba-decision-token",
                    "suite-token",
                    "delivered-client-material.json",
                    "browser-credentials.json",
                },
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for path in output.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_github_bridge_removes_partial_output_after_invalid_json(self):
        module = load_script("materialize_github_oidf_secrets.py")
        values = {
            "OIDF_PLAN_CONFIG_AGE_IDENTITY": "age-key",
            "OIDF_MTLS_MATERIAL_AGE_IDENTITY": "mtls-key",
            "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN": "dcr-token",
            "OIDF_CIBA_AUTOMATED_DECISION_TOKEN": "ciba-token",
            "OIDF_CONFORMANCE_TOKEN": "suite-token",
            "OIDF_DELIVERED_CLIENT_MATERIAL_JSON": "not-json",
            "OIDF_USER_EMAIL": "applicant@example.test",
            "OIDF_USER_PASSWORD": "applicant-password",
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "secrets"
            with mock.patch.dict(os.environ, values, clear=True):
                with self.assertRaisesRegex(RuntimeError, "not valid JSON"):
                    module.materialize(output)
            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "secure secret files are POSIX-only")
    def test_browser_credentials_are_applied_from_private_file_and_output_is_private(self):
        module = load_script("apply_oidf_browser_credentials.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "configs.json"
            credentials = root / "credentials.json"
            config.write_text(
                json.dumps({"configs": {"plan": {"nazo": {"other": True}}}}),
                encoding="utf-8",
            )
            config.chmod(0o600)
            credentials.write_text(
                json.dumps(
                    {
                        "applicant_email": "applicant@example.test",
                        "applicant_password": "applicant-password",
                    }
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)

            module.apply(config, credentials)

            document = json.loads(config.read_text(encoding="utf-8"))
            nazo = document["configs"]["plan"]["nazo"]
            self.assertEqual(nazo["oidf_user_email"], "applicant@example.test")
            self.assertEqual(nazo["oidf_user_password"], "applicant-password")
            self.assertTrue(nazo["other"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
