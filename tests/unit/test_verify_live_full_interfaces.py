import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_live_full_interfaces.py"


class VerifyLiveCliTests(unittest.TestCase):
    def test_help_is_offline_and_documents_explicit_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            missing_secrets = workdir / "does-not-exist.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--help",
                    "--secrets-path",
                    str(missing_secrets),
                ],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--base-url", completed.stdout)
        self.assertIn("--secrets-path", completed.stdout)
        self.assertIn("--expected-backend-sha", completed.stdout)

    def test_source_requires_operator_supplied_public_origin(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        self.assertIn('parser.add_argument("--base-url", required=True)', source)
        self.assertNotIn('default="https://issuer.example"', source)
        self.assertIn('default="/opt/nazo-oauth/secrets.json"', source)

    def test_backend_sha_is_bound_to_record_and_running_container(self) -> None:
        spec = importlib.util.spec_from_file_location("live_verifier", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expected = "a" * 40

        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "current.json"
            record.write_text(
                json.dumps(
                    {
                        "status": "deployment-success",
                        "backend_commit": expected,
                    }
                ),
                encoding="utf-8",
            )

            def runner(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, stdout=expected + "\n", stderr="")

            module.verify_deployed_backend(expected, record, runner)

            record.write_text(
                json.dumps({"status": "deployment-success", "backend_commit": "b" * 40}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "record backend SHA"):
                module.verify_deployed_backend(expected, record, runner)

    def test_email_verification_key_matches_tenant_scoped_server_contract(self) -> None:
        spec = importlib.util.spec_from_file_location("live_verifier_email_key", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        class FakeDigest:
            @staticmethod
            def hexdigest() -> str:
                return "ab" * 32

        class FakeBlake3:
            @staticmethod
            def blake3(value: bytes) -> FakeDigest:
                self.assertEqual(value, b"registered-live-full@example.com")
                return FakeDigest()

        module.blake3 = FakeBlake3()

        key = module.email_verification_code_key("registered-live-full@example.com")

        self.assertEqual(
            key,
            "oauth:email_verify:00000000-0000-0000-0000-000000000001:code:"
            + "ab" * 32,
        )
        self.assertNotIn("registered-live-full@example.com", key)

    def test_valkey_cleanup_deletes_only_keys_created_by_this_run(self) -> None:
        spec = importlib.util.spec_from_file_location("live_verifier_cleanup", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CREATED_VALKEY_KEYS.update({"created-a", "created-b"})

        class FakeRedis:
            def __init__(self) -> None:
                self.deleted = []

            def delete(self, key: str) -> None:
                self.deleted.append(key)

        redis_client = FakeRedis()
        module.cleanup_created_valkey_keys(redis_client)

        self.assertEqual(set(redis_client.deleted), {"created-a", "created-b"})
        self.assertEqual(module.CREATED_VALKEY_KEYS, set())


if __name__ == "__main__":
    unittest.main()
