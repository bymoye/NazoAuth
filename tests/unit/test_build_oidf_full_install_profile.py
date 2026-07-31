import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import build_oidf_full_install_profile as profile


class OidfFullInstallProfileTests(unittest.TestCase):
    def test_public_jwks_rejects_private_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.json"
            path.write_text(
                json.dumps({"keys": [{"kty": "EC", "d": "private"}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(profile.ProfileError, "public asymmetric"):
                profile.public_jwks(path.resolve(), "test JWKS")

    def test_atomic_output_is_closed_and_owner_only_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = (Path(temporary) / "profile.json").resolve()
            profile.write_atomic(path, {"schema": 1, "public": True})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"public": True, "schema": 1},
            )
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_origin_rejects_credentials_paths_queries_and_http(self) -> None:
        self.assertEqual(
            profile.origin("https://suite.example/", "suite"),
            "https://suite.example",
        )
        for value in (
            "http://suite.example",
            "https://user@suite.example",
            "https://suite.example/path",
            "https://suite.example?query=1",
        ):
            with self.subTest(value=value), self.assertRaises(profile.ProfileError):
                profile.origin(value, "suite")


if __name__ == "__main__":
    unittest.main()
