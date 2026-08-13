import argparse
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "oidf_secret_input.py"
    spec = importlib.util.spec_from_file_location("oidf_secret_input_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class OidfSecretInputTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX mode bits")
    def test_mode_0600_file_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secrets.json"
            path.write_text(json.dumps({"token": "value"}), encoding="utf-8")
            path.chmod(0o600)
            args = argparse.Namespace(
                secrets_stdin=False,
                secret_fd=None,
                secret_file=path,
            )
            self.assertEqual(
                self.module.read_secret_document(args, required_fields=("token",)),
                {"token": "value"},
            )


    def test_duplicate_fields_are_rejected_from_inherited_descriptor(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b'{"token":"first","token":"second"}')
        finally:
            os.close(writer)
        args = argparse.Namespace(
            secrets_stdin=False,
            secret_fd=reader,
            secret_file=None,
        )
        try:
            with self.assertRaisesRegex(
                self.module.SecretInputError, "duplicate field"
            ):
                self.module.read_secret_document(args, required_fields=("token",))
        finally:
            os.close(reader)

    def test_unknown_fields_are_rejected_by_closed_schema(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b'{"token":"value","unexpected":"value"}')
        finally:
            os.close(writer)
        args = argparse.Namespace(
            secrets_stdin=False,
            secret_fd=reader,
            secret_file=None,
        )
        try:
            with self.assertRaisesRegex(self.module.SecretInputError, "closed schema"):
                self.module.read_secret_document(args, required_fields=("token",))
        finally:
            os.close(reader)

    @unittest.skipIf(os.name == "nt", "secure secret files are POSIX-only")
    def test_oversized_secret_document_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secrets.json"
            path.write_bytes(b"x" * (self.module.MAX_SECRET_DOCUMENT_BYTES + 1))
            path.chmod(0o600)
            args = argparse.Namespace(
                secrets_stdin=False,
                secret_fd=None,
                secret_file=path,
            )
            with self.assertRaisesRegex(self.module.SecretInputError, "1 through"):
                self.module.read_secret_document(args, required_fields=("token",))

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX mode bits")
    def test_group_readable_secret_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secrets.json"
            path.write_text('{"token":"value"}', encoding="utf-8")
            path.chmod(0o640)
            args = argparse.Namespace(
                secrets_stdin=False,
                secret_fd=None,
                secret_file=path,
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            with self.assertRaisesRegex(self.module.SecretInputError, "exactly 0600"):
                self.module.read_secret_document(args, required_fields=("token",))

    @unittest.skipIf(os.name == "nt", "secure secret files are POSIX-only")
    def test_hard_linked_secret_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secrets.json"
            link = Path(temporary) / "second-name.json"
            path.write_text('{"token":"value"}', encoding="utf-8")
            path.chmod(0o600)
            os.link(path, link)
            args = argparse.Namespace(
                secrets_stdin=False,
                secret_fd=None,
                secret_file=path,
            )
            with self.assertRaisesRegex(self.module.SecretInputError, "one hard link"):
                self.module.read_secret_document(args, required_fields=("token",))

    def test_only_closed_process_and_locale_allowlist_is_inherited(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "safe",
                "LANG": "C.UTF-8",
                "LC_TIME": "C",
                "OIDF_CONFORMANCE_TOKEN": "token",
                "OIDF_USER_PASSWORD": "password",
                "API_CREDENTIAL": "credential",
                "AGE_IDENTITY": "identity",
                "AUTH": "authorization",
                "KEY": "key-material",
                "COOKIE": "cookie",
                "DATABASE_URL": "database",
                "HARMLESS_CANARY": "must-not-cross",
            },
            clear=True,
        ):
            self.assertEqual(
                self.module.sanitized_environment(),
                {"PATH": "safe", "LANG": "C.UTF-8", "LC_TIME": "C"},
            )

    def test_explicit_non_secret_child_settings_are_added_without_parent_copy(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "safe", "HARMLESS_CANARY": "must-not-cross"},
            clear=True,
        ):
            environment = self.module.sanitized_environment(
                {"OIDF_TARGET_ISSUER": "https://issuer.example"}
            )
        self.assertEqual(
            environment,
            {"PATH": "safe", "OIDF_TARGET_ISSUER": "https://issuer.example"},
        )


if __name__ == "__main__":
    unittest.main()
