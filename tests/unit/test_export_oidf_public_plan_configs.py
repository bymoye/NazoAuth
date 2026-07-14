import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


script = Path(__file__).resolve().parents[2] / "scripts" / "export_oidf_public_plan_configs.py"
sys.path.insert(0, str(script.parent))
spec = importlib.util.spec_from_file_location("export_oidf_public_plan_configs", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
oidf_mtls_ca_bundle = importlib.import_module("oidf_mtls_ca_bundle")
SOURCE_COMMIT = "1" * 40


def export_args(input_path: Path, output_dir: Path) -> list[str]:
    return [
        "--config-json-file",
        str(input_path),
        "--output-dir",
        str(output_dir),
        "--source-commit",
        SOURCE_COMMIT,
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
    def test_strip_private_jwks_removes_private_key_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mtls = make_mtls_material(tmp_path, "public-export")
            rendered = {
                "configs": {
                    "oidf-test-plan-config.json": {
                        "alias": "seed-alias",
                        "client": {
                            "client_id": "client-1",
                            "client_secret": "secret",
                            "scope": "openid accounts",
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
                        },
                        "mtls": mtls,
                        "nazo": {
                            "fapi_profile": "plain_fapi",
                            "fapi_request_method": "signed_non_repudiation",
                            "fapi_response_mode": "jarm",
                            "client_auth_type": "mtls",
                            "sender_constrain": "mtls",
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

        self.assertEqual(exported["alias"], "seed-alias")
        self.assertEqual(exported["client"]["client_id"], "client-1")
        self.assertEqual(exported["client"]["scope"], "openid accounts")

        self.assertEqual(exported["mtls"]["cert"], mtls["cert"])
        self.assertEqual(exported["nazo"]["fapi_profile"], "plain_fapi")
        self.assertEqual(
            exported["nazo"]["fapi_request_method"], "signed_non_repudiation"
        )
        self.assertEqual(exported["nazo"]["fapi_response_mode"], "jarm")
        self.assertEqual(exported["nazo"]["client_auth_type"], "mtls")
        self.assertEqual(exported["nazo"]["sender_constrain"], "mtls")

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
            oidf_mtls_ca_bundle.validate_artifact_directory(
                output_dir,
                expected_source_commit=SOURCE_COMMIT,
            )
            with self.assertRaisesRegex(
                oidf_mtls_ca_bundle.BundleError,
                "does not match the deployed backend commit",
            ):
                oidf_mtls_ca_bundle.validate_artifact_directory(
                    output_dir,
                    expected_source_commit="2" * 40,
                )

            plan = output_dir / "test.json"
            plan.write_text(plan.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(
                oidf_mtls_ca_bundle.BundleError,
                "manifest does not match its files",
            ):
                oidf_mtls_ca_bundle.validate_artifact_directory(output_dir)

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

    def test_export_accepts_absent_ca_key_usage_but_rejects_restrictive_usage(self):
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
            input_path = root / "configs.json"
            input_path.write_text(
                json.dumps(
                    {"configs": {"test.json": {"alias": "test", "mtls": unrestricted}}}
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                module.main_with_args_for_test(
                    export_args(input_path, root / "public-missing-ca-key-usage")
                ),
                0,
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

    def test_exported_nazo_fields_exactly_cover_seeder_policy_inputs(self):
        seeder = (
            Path(__file__).resolve().parents[2]
            / "crates"
            / "authorization-server"
            / "src"
            / "bin"
            / "nazo_oauth_seed_oidf.rs"
        ).read_text(encoding="utf-8")
        policy_body = seeder.split("fn fapi_client_policy", 1)[1].split(
            "\n}\n\n#[tokio::main]", 1
        )[0]
        consumed_nazo_fields = set(
            re.findall(r'value\.get\("([^"]+)"\)', policy_body)
        )

        self.assertEqual(consumed_nazo_fields, module.SEED_NAZO_FIELDS)

    def test_public_export_preserves_every_seed_policy_decision_input(self):
        policy_inputs = {
            "fapi_profile": "fapi_client_credentials_grant",
            "fapi_request_method": "signed_non_repudiation",
            "fapi_response_mode": "jarm",
            "client_auth_type": "mtls",
            "sender_constrain": "mtls",
        }

        self.assertEqual(module.public_seed_nazo(policy_inputs), policy_inputs)

    def test_real_fapi_matrix_template_preserves_seed_policy_fields(self):
        template = Path(__file__).resolve().parents[2] / "docs" / "conformance" / "oidf-plan-config-template.json"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            output_dir = tmp_path / "public"

            self.assertEqual(
                module.main_with_args_for_test(
                    export_args(template, output_dir)
                ),
                0,
            )

            mtls = json.loads(
                (
                    output_dir
                    / "oidf-fapi-matrix-security-final-mtls-mtls-openid-connect-plain-fapi-plain-response-plan-config.json"
                ).read_text()
            )
            jarm = json.loads(
                (
                    output_dir
                    / "oidf-fapi-matrix-message-final-private-key-jwt-dpop-openid-connect-plain-fapi-jarm-plan-config.json"
                ).read_text()
            )

        self.assertEqual(mtls["nazo"]["client_auth_type"], "mtls")
        self.assertEqual(mtls["nazo"]["sender_constrain"], "mtls")
        self.assertEqual(
            jarm["nazo"],
            {
                "client_auth_type": "private_key_jwt",
                "fapi_profile": "plain_fapi",
                "fapi_request_method": "signed_non_repudiation",
                "fapi_response_mode": "jarm",
                "sender_constrain": "dpop",
            },
        )


if __name__ == "__main__":
    unittest.main()
