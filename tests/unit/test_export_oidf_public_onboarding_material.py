import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


script = Path(__file__).resolve().parents[2] / "scripts" / "export_oidf_public_onboarding_material.py"
sys.path.insert(0, str(script.parent))
spec = importlib.util.spec_from_file_location("export_oidf_public_onboarding_material", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
oidf_onboarding_bundle = importlib.import_module("oidf_onboarding_bundle")
SOURCE_COMMIT = "1" * 40


def export_args(input_path: Path, output_dir: Path) -> list[str]:
    return [
        "--config-json-file",
        str(input_path),
        "--output-dir",
        str(output_dir),
        "--source-commit",
        SOURCE_COMMIT,
        "--target-issuer",
        "https://issuer.example",
        "--suite-base-url",
        "https://suite.example",
        "--onboarding-profile",
        "official",
    ]


def make_mtls_material(
    root: Path,
    name: str,
    *,
    subject_name: str | None = None,
    extended_key_usage: str | None = None,
    ca_key_usage: str | None = "critical,keyCertSign,cRLSign",
) -> dict[str, str]:
    subject_name = subject_name or name
    ca_key = root / f"{name}-ca.key"
    ca_cert = root / f"{name}-ca.pem"
    leaf_key = root / f"{name}-leaf.key"
    leaf_csr = root / f"{name}-leaf.csr"
    leaf_cert = root / f"{name}-leaf.pem"
    extensions = root / f"{name}-leaf.ext"
    extension_text = (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    if extended_key_usage is not None:
        extension_text += f"extendedKeyUsage={extended_key_usage}\n"
    extensions.write_text(
        extension_text,
        encoding="ascii",
    )
    ca_command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
            "-subj", f"/CN={subject_name} test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
    ]
    if ca_key_usage is not None:
        ca_command.extend(["-addext", f"keyUsage={ca_key_usage}"])
    subprocess.run(
        ca_command,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(leaf_key), "-out", str(leaf_csr),
            "-subj", f"/CN={subject_name} test client",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(leaf_csr),
            "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(leaf_cert), "-days", "1", "-extfile", str(extensions),
        ],
        check=True,
        capture_output=True,
    )
    return {
        "ca": ca_cert.read_text(encoding="ascii"),
        "cert": leaf_cert.read_text(encoding="ascii"),
        "key": leaf_key.read_text(encoding="ascii"),
    }


class ExportOidfPublicPlanConfigsTests(unittest.TestCase):
    def test_export_merges_openid4vc_into_one_public_onboarding_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mtls = make_mtls_material(root, "combined")
            oauth = root / "oauth.json"
            oauth.write_text(
                json.dumps(
                    {
                        "configs": {
                            "oauth.json": {
                                "alias": "oauth",
                                "mtls": mtls,
                                "nazo": {
                                    "oidf_user_email": "holder@example.test"
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            openid4vc = root / "openid4vc.json"
            openid4vc.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-issuer.json": {
                                "alias": "issuer",
                                "client": {
                                    "client_id": "openid4vc-client",
                                    "scope": "openid pid",
                                    "jwks": {
                                        "keys": [
                                            {
                                                "kty": "EC",
                                                "crv": "P-256",
                                                "x": "x",
                                                "y": "y",
                                                "d": "private",
                                            }
                                        ]
                                    },
                                },
                                "vci": {"credential_configuration_id": "pid"},
                                "client_attestation": {
                                    "issuer": "https://attester.example/",
                                    "attester_jwks": {
                                        "keys": [
                                            {
                                                "kty": "EC",
                                                "crv": "P-256",
                                                "x": "x",
                                                "y": "y",
                                                "d": "private",
                                            }
                                        ]
                                    },
                                    "key_attestation_jwks": {
                                        "keys": [
                                            {
                                                "kty": "OKP",
                                                "crv": "Ed25519",
                                                "x": "x2",
                                                "d": "private",
                                            }
                                        ]
                                    },
                                },
                                "nazo": {
                                    "openid4vc_role": "issuer",
                                    "client_auth_type": "private_key_jwt",
                                    "credential_format": "sd_jwt_vc",
                                    "credential_dataset": {"given_name": "Specimen"},
                                },
                            },
                            "openid4vc-second-issuer.json": {
                                "vci": {"credential_configuration_id": "org.example.mdoc"},
                                "nazo": {
                                    "openid4vc_role": "issuer",
                                    "client_auth_type": "private_key_jwt",
                                    "credential_format": "mdoc",
                                    "credential_dataset": {"given_name": "Specimen"},
                                },
                            },
                            "openid4vc-verifier.json": {
                                "client": {
                                    "request_object_trust_anchor_pem": (
                                        "-----BEGIN CERTIFICATE-----\nanchor\n"
                                        "-----END CERTIFICATE-----\n"
                                    )
                                },
                                "nazo": {"openid4vc_role": "verifier"},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = root / "public"
            args = export_args(oauth, output)
            args[2:2] = ["--config-json-file", str(openid4vc)]
            self.assertEqual(module.main_with_args_for_test(args), 0)

            bundle = json.loads(
                (output / module.OPENID4VC_ONBOARDING_BUNDLE_FILE).read_text(
                    encoding="utf-8"
                )
            )
            config = bundle["configs"]["openid4vc-issuer.json"]
            self.assertEqual(config["vci"]["credential_configuration_id"], "pid")
            self.assertEqual(config["nazo"]["credential_dataset"]["given_name"], "Specimen")
            self.assertNotIn("d", config["client"]["jwks"]["keys"][0])
            self.assertRegex(
                bundle["credential_holder_email_sha256"], r"^[0-9a-f]{64}$"
            )
            manifest = json.loads(
                (output / module.MANIFEST_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertIn(module.OPENID4VC_ONBOARDING_BUNDLE_FILE, manifest["files"])
            self.assertIn(module.STANDARDS_FULL_PROFILE_FILE, manifest["files"])
            install_profile = json.loads(
                (output / module.STANDARDS_FULL_PROFILE_FILE).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                set(install_profile["credential_configurations"]),
                {"pid", "org.example.mdoc"},
            )

    def test_strip_private_jwks_removes_private_key_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mtls = make_mtls_material(tmp_path, "public-export")
            rendered = {
                "configs": {
                    "oidf-test-plan-config.json": {
                        "alias": "onboarding-alias",
                        "client": {
                            "client_id": "client-1",
                            "client_secret": "secret",
                            "scope": "openid accounts",
                            "backchannel_token_delivery_mode": "ping",
                            "backchannel_client_notification_endpoint": (
                                "https://www.certification.openid.net/test/a/"
                                "onboarding-alias/ciba-notification-endpoint"
                            ),
                            "backchannel_authentication_request_signing_alg": "PS256",
                            "backchannel_user_code_parameter": False,
                            "jwks": {
                                "keys": [
                                    {
                                        "kty": "RSA",
                                        "kid": "client-key",
                                        "alg": "PS256",
                                        "n": "modulus",
                                        "e": "AQAB",
                                        "d": "private",
                                        "p": "private",
                                        "q": "private",
                                        "dp": "private",
                                        "dq": "private",
                                        "qi": "private",
                                    }
                                ]
                            },
                            "request_object_trust_anchor_pem": (
                                "-----BEGIN CERTIFICATE-----\nanchor\n"
                                "-----END CERTIFICATE-----\n"
                            ),
                        },
                        "client_attestation": {
                            "issuer": "https://suite.example/",
                            "attester_jwks": {
                                "keys": [{"kty": "EC", "x": "x", "y": "y", "d": "private"}]
                            },
                            "key_attestation_jwks": {
                                "keys": [{"kty": "EC", "x": "x2", "y": "y2", "d": "private"}]
                            },
                        },
                        "client_secret_post": {
                            "client_id": "client-post",
                            "client_secret": "post-secret",
                            "scope": "openid",
                        },
                        "mtls": mtls,
                        "nazo": {
                            "fapi_profile": "plain_fapi",
                            "fapi_request_method": "signed_non_repudiation",
                            "fapi_response_mode": "jarm",
                            "client_auth_type": "mtls",
                            "sender_constrain": "mtls",
                            "credential_format": "sd_jwt_vc",
                            "oidf_user_email": "conformance@example.test",
                            "oidf_user_password": "secret",
                        },
                        "automated_ciba_approval_url": "https://example.test/ciba?token=secret",
                        "browser": [{"type": "text", "value": "secret"}],
                    }
                }
            }
            input_path = tmp_path / "configs.json"
            output_dir = tmp_path / "public"
            input_path.write_text(json.dumps(rendered), encoding="utf-8")

            self.assertEqual(
                module.main_with_args_for_test(
                    export_args(input_path, output_dir)
                ),
                0,
            )

            exported = json.loads((output_dir / "oidf-test-plan-config.json").read_text())
            bundle = (output_dir / module.BUNDLE_FILE_NAME).read_text(
                encoding="ascii"
            )

        self.assertEqual(exported["alias"], "onboarding-alias")
        self.assertEqual(exported["client"]["client_id"], "client-1")
        self.assertEqual(exported["client"]["scope"], "openid accounts")
        self.assertEqual(exported["client_secret_post"]["client_id"], "client-post")
        self.assertEqual(exported["client_secret_post"]["scope"], "openid")
        self.assertNotIn("client_secret", exported["client_secret_post"])
        self.assertEqual(
            exported["client_secret_post"]["client_secret_sha256"],
            "1a6979359a4a9a00863d570ad68b30fb1034eb9f032ef613451e9aeef745d69e",
        )
        self.assertEqual(
            exported["client"]["backchannel_token_delivery_mode"], "ping"
        )
        self.assertEqual(
            exported["client"]["backchannel_client_notification_endpoint"],
            "https://www.certification.openid.net/test/a/onboarding-alias/"
            "ciba-notification-endpoint",
        )
        self.assertEqual(
            exported["client"]["backchannel_authentication_request_signing_alg"],
            "PS256",
        )
        self.assertFalse(exported["client"]["backchannel_user_code_parameter"])
        self.assertIn(
            "BEGIN CERTIFICATE",
            exported["client"]["request_object_trust_anchor_pem"],
        )
        self.assertEqual(
            exported["client_attestation"]["issuer"],
            "https://suite.example/",
        )
        self.assertNotIn(
            "d", exported["client_attestation"]["attester_jwks"]["keys"][0]
        )
        self.assertNotIn(
            "d",
            exported["client_attestation"]["key_attestation_jwks"]["keys"][0],
        )

        self.assertEqual(exported["mtls"]["cert"], mtls["cert"])
        self.assertEqual(exported["nazo"]["fapi_profile"], "plain_fapi")
        self.assertEqual(
            exported["nazo"]["fapi_request_method"], "signed_non_repudiation"
        )
        self.assertEqual(exported["nazo"]["fapi_response_mode"], "jarm")
        self.assertEqual(exported["nazo"]["client_auth_type"], "mtls")
        self.assertEqual(exported["nazo"]["sender_constrain"], "mtls")
        self.assertEqual(exported["nazo"]["credential_format"], "sd_jwt_vc")

        jwk = exported["client"]["jwks"]["keys"][0]
        self.assertEqual(jwk["kid"], "client-key")
        self.assertEqual(jwk["n"], "modulus")
        self.assertNotIn("d", jwk)
        self.assertNotIn("p", jwk)
        self.assertNotIn("q", jwk)
        self.assertNotIn("dp", jwk)
        self.assertNotIn("dq", jwk)
        self.assertNotIn("qi", jwk)
        self.assertNotIn("client_secret", exported["client"])
        self.assertNotIn("key", exported["mtls"])
        self.assertEqual(exported["mtls"]["ca"], mtls["ca"])
        self.assertNotIn("oidf_user_password", exported["nazo"])
        self.assertNotIn("oidf_user_email", exported["nazo"])
        self.assertEqual(
            exported["nazo"]["oidf_user_password_sha256"],
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
        )
        self.assertEqual(
            exported["nazo"]["oidf_user_email_sha256"],
            "a23fb0e9642ab8fe5d3bd3288247ae0bbfb0a49a36bd3f3aa9c713279f88cf80",
        )
        self.assertNotIn("automated_ciba_approval_url", exported)
        self.assertNotIn("browser", exported)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertNotIn("PRIVATE KEY", bundle)

    def test_bundle_is_deterministic_and_deduplicates_shared_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_material = make_mtls_material(
                root, "deterministic-one", subject_name="shared-subject"
            )
            second_material = make_mtls_material(
                root, "deterministic-two", subject_name="shared-subject"
            )
            rendered = {
                "configs": {
                    "c.json": {"alias": "c", "mtls": first_material},
                    "b.json": {"alias": "b", "mtls": second_material},
                    "a.json": {"alias": "a", "mtls": first_material},
                }
            }
            input_path = root / "configs.json"
            input_path.write_text(json.dumps(rendered), encoding="utf-8")
            first = root / "first"
            second = root / "second"
            module.main_with_args_for_test(
                export_args(input_path, first)
            )
            rendered["configs"] = dict(reversed(list(rendered["configs"].items())))
            input_path.write_text(json.dumps(rendered), encoding="utf-8")
            module.main_with_args_for_test(
                export_args(input_path, second)
            )

            first_bundle = (first / module.BUNDLE_FILE_NAME).read_bytes()
            second_bundle = (second / module.BUNDLE_FILE_NAME).read_bytes()

        self.assertEqual(first_bundle, second_bundle)
        self.assertEqual(first_bundle.count(b"-----BEGIN CERTIFICATE-----"), 2)

    def test_artifact_manifest_binds_files_and_source_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            material = make_mtls_material(root, "manifest")
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": material}}}
                ),
                encoding="utf-8",
            )
            output_dir = root / "public"
            module.main_with_args_for_test(export_args(input_path, output_dir))

            manifest = json.loads(
                (output_dir / module.MANIFEST_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["source_commit"], SOURCE_COMMIT)
            self.assertRegex(manifest["tree_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(manifest["ca_der_sha256"])
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{64}", value) for value in manifest["ca_der_sha256"])
            )
            oidf_onboarding_bundle.validate_artifact_directory(
                output_dir,
                expected_source_commit=SOURCE_COMMIT,
            )
            with self.assertRaisesRegex(
                oidf_onboarding_bundle.BundleError,
                "does not match the deployed backend commit",
            ):
                oidf_onboarding_bundle.validate_artifact_directory(
                    output_dir,
                    expected_source_commit="2" * 40,
                )

            plan = output_dir / "test.json"
            plan.write_text(plan.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(
                oidf_onboarding_bundle.BundleError,
                "manifest does not match its files",
            ):
                oidf_onboarding_bundle.validate_artifact_directory(output_dir)

    def test_export_rejects_missing_malformed_non_ca_and_wrong_issuer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_mtls_material(root, "first", subject_name="shared-subject")
            second = make_mtls_material(root, "second", subject_name="shared-subject")
            input_path = root / "configs.json"
            output_dir = root / "public"
            cases = {
                "missing": {"cert": first["cert"]},
                "malformed": {"ca": "not a certificate", "cert": first["cert"]},
                "non-ca": {"ca": first["cert"], "cert": first["cert"]},
                "wrong-issuer": {"ca": first["ca"], "cert": second["cert"]},
            }
            for name, mtls in cases.items():
                with self.subTest(name=name):
                    input_path.write_text(
                        json.dumps({"configs": {"test.json": {"alias": "test", "mtls": mtls}}}),
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit):
                        module.main_with_args_for_test(
                            export_args(input_path, output_dir)
                        )

    def test_export_rejects_extra_ca_and_server_only_leaf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_mtls_material(root, "first-extra")
            second = make_mtls_material(root, "second-extra")
            server_only = make_mtls_material(
                root,
                "server-only",
                extended_key_usage="serverAuth",
            )
            input_path = root / "configs.json"
            for name, material in {
                "extra-ca": {
                    **first,
                    "ca": first["ca"] + second["ca"],
                },
                "server-only": server_only,
            }.items():
                with self.subTest(name=name):
                    input_path.write_text(
                        json.dumps(
                            {"configs": {"test.json": {"alias": "test", "mtls": material}}}
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit):
                        module.main_with_args_for_test(
                            export_args(input_path, root / f"public-{name}")
                        )

    def test_export_rejects_absent_or_restrictive_ca_key_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unrestricted = make_mtls_material(
                root,
                "missing-ca-key-usage",
                ca_key_usage=None,
            )
            restricted = make_mtls_material(
                root,
                "restricted-ca-key-usage",
                ca_key_usage="critical,digitalSignature",
            )
            noncritical = make_mtls_material(
                root,
                "noncritical-ca-key-usage",
                ca_key_usage="keyCertSign,cRLSign",
            )
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": unrestricted}}}
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                module.main_with_args_for_test(
                    export_args(input_path, root / "public-missing-ca-key-usage")
                )

            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": restricted}}}
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                module.main_with_args_for_test(
                    export_args(input_path, root / "public-restricted-ca-key-usage")
                )

            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": noncritical}}}
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                module.main_with_args_for_test(
                    export_args(input_path, root / "public-noncritical-ca-key-usage")
                )

    def test_failed_export_does_not_replace_existing_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "public"
            output_dir.mkdir()
            bundle = output_dir / module.BUNDLE_FILE_NAME
            bundle.write_bytes(b"existing bundle\n")
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps({"configs": {"test.json": {"alias": "test", "mtls": {"ca": ""}}}}),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                module.main_with_args_for_test(
                    export_args(input_path, output_dir)
                )

            self.assertEqual(bundle.read_bytes(), b"existing bundle\n")

    def test_successful_export_refuses_to_merge_with_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            material = make_mtls_material(root, "existing-output")
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": material}}}
                ),
                encoding="utf-8",
            )
            output_dir = root / "public"
            output_dir.mkdir()
            sentinel = output_dir / "stale.json"
            sentinel.write_text("stale\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "output directory already exists"):
                module.main_with_args_for_test(
                    export_args(input_path, output_dir)
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "stale\n")
            self.assertEqual(list(output_dir.iterdir()), [sentinel])

    def test_invalid_file_name_is_rejected_before_output_is_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            material = make_mtls_material(root, "invalid-name")
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps(
                    {
                        "configs": {
                            "valid.json": {"alias": "valid", "mtls": material},
                            "../escape.json": {"alias": "invalid"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            output_dir = root / "public"

            with self.assertRaisesRegex(SystemExit, "invalid OIDF config file name"):
                module.main_with_args_for_test(
                    export_args(input_path, output_dir)
                )

            self.assertFalse(output_dir.exists())

    def test_each_leaf_must_chain_to_the_ca_declared_in_its_own_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_mtls_material(root, "first", subject_name="shared-subject")
            second = make_mtls_material(root, "second", subject_name="shared-subject")
            rendered = {
                "configs": {
                    "correct.json": {"alias": "correct", "mtls": first},
                    "wrong.json": {
                        "alias": "wrong",
                        "mtls": {"ca": first["ca"], "cert": second["cert"]},
                    },
                    "also-correct.json": {"alias": "also-correct", "mtls": second},
                }
            }
            input_path = root / "configs.json"
            input_path.write_text(json.dumps(rendered), encoding="utf-8")

            with self.assertRaises(SystemExit):
                module.main_with_args_for_test(
                    export_args(input_path, root / "public")
                )

    def test_exported_nazo_fields_are_artifact_metadata_not_server_inputs(self):
        onboarding = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "apply_public_conformance_onboarding.py"
        ).read_text(encoding="utf-8")

        self.assertNotIn("DATABASE_URL", onboarding)
        self.assertNotIn("nazo_postgres", onboarding)
        self.assertIn("/auth/me/access-requests", onboarding)
        self.assertEqual(
            module.OPENID4VC_ONBOARDING_NAZO_FIELDS,
            {
                "client_auth_type",
                "openid4vc_role",
                "credential_format",
                "credential_dataset",
            },
        )

    def test_public_export_preserves_every_onboarding_policy_decision_input(self):
        policy_inputs = {
            "fapi_profile": "fapi_client_credentials_grant",
            "fapi_request_method": "signed_non_repudiation",
            "fapi_response_mode": "jarm",
            "client_auth_type": "mtls",
            "sender_constrain": "mtls",
        }

        self.assertEqual(module.public_onboarding_nazo(policy_inputs), policy_inputs)

    def test_real_fapi_matrix_template_preserves_onboarding_policy_fields(self):
        template = Path(__file__).resolve().parents[2] / "docs" / "conformance" / "oidf-plan-config-template.json"
        template_text = template.read_text(encoding="utf-8")
        configs = json.loads(template_text)["configs"]
        mtls = module.public_onboarding_config(
            configs[
                "oidf-fapi-matrix-security-final-mtls-mtls-openid-connect-plain-fapi-plain-response-plan-config.json"
            ]
        )
        jarm = module.public_onboarding_config(
            configs[
                "oidf-fapi-matrix-message-final-private-key-jwt-dpop-openid-connect-plain-fapi-jarm-plan-config.json"
            ]
        )

        self.assertNotIn("-----BEGIN CERTIFICATE-----", template_text)
        self.assertNotIn("Local OIDF mTLS", template_text)

        self.assertEqual(mtls["nazo"]["client_auth_type"], "mtls")
        self.assertEqual(mtls["nazo"]["sender_constrain"], "mtls")
        self.assertEqual(jarm["nazo"]["client_auth_type"], "private_key_jwt")
        self.assertEqual(jarm["nazo"]["fapi_profile"], "plain_fapi")
        self.assertEqual(
            jarm["nazo"]["fapi_request_method"], "signed_non_repudiation"
        )
        self.assertEqual(jarm["nazo"]["fapi_response_mode"], "jarm")
        self.assertEqual(jarm["nazo"]["sender_constrain"], "dpop")


if __name__ == "__main__":
    unittest.main()
