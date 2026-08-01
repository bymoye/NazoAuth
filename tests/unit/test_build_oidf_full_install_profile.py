import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import build_oidf_full_install_profile as profile


class OidfFullInstallProfileTests(unittest.TestCase):
    @staticmethod
    def onboarding_document() -> dict[str, object]:
        attestation = {
            "issuer": "https://suite.example/",
            "attester_jwks": {
                "keys": [{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}]
            },
            "key_attestation_jwks": {
                "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "x2"}]
            },
        }
        return {
            "configs": {
                "renamed-sd-config.json": {
                    "client_attestation": attestation,
                    "vci": {"credential_configuration_id": "eu.europa.ec.eudi.pid.1"},
                    "nazo": {"credential_format": "sd_jwt_vc"},
                },
                "renamed-mdoc-config.json": {
                    "client_attestation": attestation,
                    "vci": {"credential_configuration_id": "org.iso.18013.5.1.mDL"},
                    "nazo": {"credential_format": "mdoc"},
                },
                "renamed-vp-config.json": {
                    "client": {
                        "request_object_trust_anchor_pem": (
                            "-----BEGIN CERTIFICATE-----\nsource-only-anchor\n"
                            "-----END CERTIFICATE-----\n"
                        )
                    },
                },
            }
        }

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

    def test_builds_closed_profile_from_public_onboarding_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = (Path(temporary) / "openid4vc-onboarding-configs.json").resolve()
            path.write_text(json.dumps(self.onboarding_document()), encoding="utf-8")

            document = profile.document_from_onboarding(
                path, "https://oauth-test.example/"
            )

        self.assertEqual(
            document["wallet_authorization_origins"], ["https://oauth-test.example"]
        )
        self.assertEqual(
            document["client_attestation_issuer"], "https://suite.example/"
        )
        configurations = document["credential_configurations"]
        self.assertEqual(
            configurations["eu.europa.ec.eudi.pid.1"]["format"], "dc+sd-jwt"
        )
        self.assertEqual(
            configurations["eu.europa.ec.eudi.pid.1"]["vct"],
            "eu.europa.ec.eudi.pid.1",
        )
        self.assertEqual(
            configurations["org.iso.18013.5.1.mDL"]["format"], "mso_mdoc"
        )
        self.assertEqual(
            configurations["org.iso.18013.5.1.mDL"]["doctype"],
            "org.iso.18013.5.1.mDL",
        )
        self.assertNotIn("trust_anchors_pem", document)

    def test_onboarding_profile_rejects_private_jwk_and_implicit_format(self) -> None:
        for mutation, message in (
            (
                lambda document: document["configs"]["renamed-sd-config.json"][
                    "client_attestation"
                ]["attester_jwks"]["keys"][0].update({"d": "private"}),
                "public asymmetric",
            ),
            (
                lambda document: document["configs"]["renamed-sd-config.json"][
                    "nazo"
                ].pop("credential_format"),
                "explicitly declare",
            ),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                document = self.onboarding_document()
                mutation(document)
                path = (Path(temporary) / "onboarding.json").resolve()
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(profile.ProfileError, message):
                    profile.document_from_onboarding(path, "https://suite.example")


if __name__ == "__main__":
    unittest.main()
