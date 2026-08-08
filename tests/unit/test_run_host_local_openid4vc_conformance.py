from __future__ import annotations

import base64
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "scripts" / "run_host_local_openid4vc_conformance.py"
    spec = importlib.util.spec_from_file_location("host_local_openid4vc", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostLocalOpenid4vcTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def fake_material(self) -> dict[str, object]:
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

    def write_prepared_directory(self, directory: Path) -> tuple[object, str, str]:
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        material = self.fake_material()
        profile = self.module.build_prepared_install_profile(
            material, "https://suite.example"
        )

        def write(name: str, value: object) -> str:
            payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
            path = directory / name
            path.write_bytes(payload)
            path.chmod(0o600)
            return hashlib.sha256(payload).hexdigest()

        profile_digest = write(self.module.PREPARED_PROFILE_FILE, profile)
        trust_digest = write(
            self.module.PREPARED_TRUST_FILE,
            self.module.build_prepared_conformance_trust(
                material, "https://suite.example"
            ),
        )
        material_digest = write(self.module.PREPARED_MATERIAL_FILE, material)
        write(
            self.module.PREPARED_MANIFEST_FILE,
            {
                "schema": 1,
                "source_commit": "a" * 40,
                "suite_origin": "https://suite.example",
                "files": {
                    self.module.PREPARED_PROFILE_FILE: profile_digest,
                    self.module.PREPARED_TRUST_FILE: trust_digest,
                    self.module.PREPARED_MATERIAL_FILE: material_digest,
                },
            },
        )
        return material, material_digest, trust_digest

    def test_secret_schema_is_closed_and_has_no_secret_file_option(self):
        with self.assertRaises(SystemExit):
            self.module.parse_args(
                [
                    "--deployed-sha", "a" * 40,
                    "--target-issuer", "https://issuer.example",
                    "--conformance-server", "https://suite.example",
                    "--suite-dir", "/suite",
                    "--suite-revision", "b" * 40,
                    "--work-dir", "/work",
                    "--export-dir", "/export",
                    "--run-namespace", "host-test",
                    "--request-object-trust-anchor-pem", "/anchor.pem",
                    "--secrets-stdin",
                    "--secret-file", "/secret.json",
                ]
            )

    def test_secret_schema_has_only_minimal_operator_credentials_and_tokens(self):
        self.assertEqual(
            self.module.SECRET_FIELDS,
            (
                "applicant_email",
                "applicant_password",
                "admin_email",
                "admin_password",
                "admin_mfa_totp_secret",
                "suite_token",
                "issuer_management_token",
                "verifier_management_token",
            ),
        )

    def test_admin_credentials_fd_includes_mfa_without_other_secrets(self):
        secrets = {field: f"value-{field}" for field in self.module.SECRET_FIELDS}
        with self.module.admin_credentials_fd(secrets) as descriptor:
            payload = b""
            while chunk := os.read(descriptor, 4096):
                payload += chunk
        self.assertEqual(
            json.loads(payload),
            {
                "admin_email": secrets["admin_email"],
                "admin_password": secrets["admin_password"],
                "admin_mfa_totp_secret": secrets["admin_mfa_totp_secret"],
            },
        )
        self.assertNotIn("openid4vc_base_config_json", self.module.SECRET_FIELDS)
        self.assertNotIn("openid4vc_driver_config_json", self.module.SECRET_FIELDS)

    def test_driver_tokens_subject_and_anchor_only_come_from_declared_boundaries(self):
        secrets = {
            "applicant_email": "applicant@example.test",
            "applicant_password": "applicant-secret",
            "admin_email": "admin@example.test",
            "admin_password": "admin-secret",
            "admin_mfa_totp_secret": "totp-secret",
            "issuer_management_token": "issuer-token",
            "verifier_management_token": "verifier-token",
        }
        result = self.module.build_driver_input(
            secrets,
            subject_id="00000000-0000-0000-0000-000000000123",
            trust_anchor="-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        self.assertEqual(result["issuer"]["management_token"], "issuer-token")
        self.assertEqual(result["verifier"]["management_token"], "verifier-token")
        self.assertEqual(
            result["hosted_authorization"],
            {
                "email": "applicant@example.test",
                "password": "applicant-secret",
            },
        )
        self.assertEqual(result["issuer"]["subject_id"], "00000000-0000-0000-0000-000000000123")
        self.assertIn("BEGIN CERTIFICATE", result["verifier"]["request_object_trust_anchor_pem"])
        self.assertTrue(result["issuer"]["dedicated_conformance_subject"])
        self.assertEqual(
            result["issuer"]["credential_configuration_ids"]["sd_jwt_vc"],
            "eu.europa.ec.eudi.pid.1",
        )
        self.assertEqual(result["issuer"]["credential_configuration_ids"]["mdoc"], "org.iso.18013.5.1.mDL")
        self.assertEqual(len(result["issuer"]["tx_code"]), 6)

    def test_conformance_lease_carries_only_the_public_run_credential_anchor(self):
        material = self.fake_material()
        trust = self.module.build_prepared_conformance_trust(
            material, "https://suite.example"
        )
        self.assertEqual(
            trust["credential_trust_anchor_pem"], material["trust_anchor_pem"]
        )
        self.assertNotIn("PRIVATE KEY", trust["credential_trust_anchor_pem"])
        self.assertNotIn("d", trust["client_attestation_jwks"]["keys"][0])
        self.assertNotIn("d", trust["key_attestation_jwks"]["keys"][0])

    def test_manifest_refuses_mtls_trust_requests_for_the_17_plan_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "clients": [
                            {
                                "logical_client_id": f"wallet-{index}",
                                "request": {"client_type": "confidential"},
                                "mtls_trust_anchor_pem": None,
                            }
                            for index in range(4)
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.module.assert_openid4vc_manifest_boundary(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["clients"][0]["mtls_trust_anchor_pem"] = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(self.module.HostLocalOpenid4vcError, "must not request mTLS"):
                self.module.assert_openid4vc_manifest_boundary(path)

    def test_public_onboarding_jwks_must_match_private_suite_configs(self):
        def private_jwk(label: str) -> dict[str, str]:
            return {
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": label,
                "x": f"x-{label}", "y": f"y-{label}", "d": f"d-{label}",
            }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_configs = root / "configs.json"
            identities = ["private", "private2", "attested", "attested2"]
            keys = {identity: private_jwk(identity) for identity in identities}
            plan_configs.write_text(
                json.dumps(
                    {
                        "configs": {
                            "private": {
                                "nazo": {},
                                "client": {"client_id": "private", "jwks": {"keys": [keys["private"]]}},
                                "client2": {"client_id": "private2", "jwks": {"keys": [keys["private2"]]}},
                            },
                            "attested": {
                                "nazo": {},
                                "client": {"client_id": "attested", "jwks": {"keys": [keys["attested"]]}},
                                "client2": {"client_id": "attested2", "jwks": {"keys": [keys["attested2"]]}},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            manifest = root / "manifest.json"
            payload = {
                "schema": 1,
                "clients": [
                    {
                        "logical_client_id": identity,
                        "request": {"jwks": {"keys": [self.module.public_jwk(keys[identity])]}}
                    }
                    for identity in identities
                ],
            }
            with mock.patch.object(self.module.onboarding, "require_manifest", return_value=payload):
                self.module.assert_public_onboarding_key_alignment(manifest, plan_configs)
            payload["clients"][0]["request"]["jwks"]["keys"][0]["x"] = "wrong"
            with mock.patch.object(self.module.onboarding, "require_manifest", return_value=payload):
                with self.assertRaisesRegex(self.module.HostLocalOpenid4vcError, "do not match"):
                    self.module.assert_public_onboarding_key_alignment(manifest, plan_configs)

    def test_public_anchor_rejects_private_material_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "anchor.pem"
            path.write_text(
                "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                self.module.HostLocalOpenid4vcError,
                "private key|changed while it was read",
            ):
                self.module.read_public_trust_anchor(path)
            self.assertIn("PRIVATE KEY", self.module.read_public_trust_anchor.__code__.co_consts)

    def test_public_anchor_requires_absolute_non_symlink_path(self):
        with self.assertRaisesRegex(
            self.module.HostLocalOpenid4vcError,
            "path must be absolute",
        ):
            self.module.read_public_trust_anchor(Path("anchor.pem"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.pem"
            target.write_text(
                "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
                encoding="ascii",
            )
            link = root / "anchor.pem"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks are unavailable on this platform")
            with self.assertRaisesRegex(
                self.module.HostLocalOpenid4vcError,
                "non-symlink",
            ):
                self.module.read_public_trust_anchor(link)

    def test_each_run_generates_unique_p256_keys_certificates_and_no_reusable_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.module.generate_certificate_material(
                root / "first", suite_origin="https://suite.example"
            )
            second = self.module.generate_certificate_material(
                root / "second", suite_origin="https://suite.example"
            )
            self.module.validate_generated_material(first)
            self.module.validate_generated_material(second)
            key_names = ("wallet_private", "wallet_attested", "client_attestation", "key_attestation", "credential")
            self.assertEqual(
                len({first[name]["d"] for name in key_names}),
                len(key_names),
            )
            self.assertTrue(all(first[name]["x5c"] for name in key_names))
            self.assertNotEqual(first["wallet_private"]["d"], second["wallet_private"]["d"])
            credential_certificate = root / "credential.der"
            credential_certificate.write_bytes(
                base64.b64decode(first["credential"]["x5c"][0], validate=True)
            )
            credential_text = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    str(credential_certificate),
                    "-noout",
                    "-text",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("1.0.18013.5.1.2", credential_text)
            self.assertIn("DNS:suite.example", credential_text)
            deployed_anchor = "-----BEGIN CERTIFICATE-----\ndeployed\n-----END CERTIFICATE-----\n"
            base = self.module.build_base_input(
                first,
                suite_origin="https://suite.example",
                deployed_trust_anchor=deployed_anchor,
            )
            self.assertEqual(set(base), {"vci", "vci_haip", "vp", "vp_haip"})
            self.assertNotIn("client_attestation", base["vci"])
            self.assertIn("key_attestation_jwks", base["vci"]["vci"])
            self.assertIn("client_attestation", base["vci_haip"])
            self.assertIn("trust_anchor", base["vci_haip"]["client_attestation"])
            for key in ("vci", "vci_haip"):
                self.assertEqual(base[key]["credential"]["trust_anchor_pem"], deployed_anchor)
                self.assertEqual(
                    base[key]["credential"]["status_list_trust_anchor_pem"],
                    deployed_anchor,
                )
            self.assertIn("signing_jwk", base["vp"]["credential"])
            for key in ("vp", "vp_haip"):
                self.assertEqual(
                    base[key]["credential"]["trust_anchor_pem"],
                    first["trust_anchor_pem"],
                )
                self.assertEqual(
                    base[key]["credential"]["status_list_trust_anchor_pem"],
                    first["trust_anchor_pem"],
                )
            self.module.delete_private_configs(root / "first")
            self.assertFalse((root / "first" / "generated-openid4vc-material").exists())

    def test_prepared_install_material_is_source_bound_and_consumed_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "prepared"
            material, expected_digest, trust_digest = self.write_prepared_directory(directory)
            args = self.module.argparse.Namespace(
                prepared_install_dir=directory.resolve(),
                deployed_sha="a" * 40,
                conformance_server="https://suite.example",
            )

            loaded = self.module.prepared_material(args)

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded, (material, expected_digest, trust_digest))
            self.module.consume_prepared_material(directory, expected_digest)
            self.assertFalse((directory / self.module.PREPARED_MATERIAL_FILE).exists())
            self.assertTrue((directory / self.module.PREPARED_PROFILE_FILE).is_file())
            self.assertTrue((directory / self.module.PREPARED_MANIFEST_FILE).is_file())

    def test_prepared_install_rejects_digest_or_profile_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "prepared"
            self.write_prepared_directory(directory)
            profile_path = directory / self.module.PREPARED_PROFILE_FILE
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile["client_attestation_issuer"] = "https://other.example/"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            profile_path.chmod(0o600)
            args = self.module.argparse.Namespace(
                prepared_install_dir=directory.resolve(),
                deployed_sha="a" * 40,
                conformance_server="https://suite.example",
            )
            with self.assertRaisesRegex(
                self.module.HostLocalOpenid4vcError, "manifest does not match"
            ):
                self.module.prepared_material(args)

    def test_ctl_lease_is_created_from_public_trust_and_revoked(self):
        lease_id = "018f3f2a-7b55-7a25-8f20-6d526f8f44e1"
        args = self.module.argparse.Namespace(
            nazoauthctl=Path("/usr/local/bin/nazoauthctl"),
            nazoauthctl_config=Path("/etc/nazoauth/update.json"),
            prepared_install_dir=Path("/run/nazoauth-host-local-oidf-install"),
            prepared_trust_digest="a" * 64,
            lease_ttl_seconds=28_800,
        )
        with (
            mock.patch.object(
                self.module,
                "create_lease",
                return_value=lease_id,
            ) as create,
            mock.patch.object(self.module, "revoke_and_cleanup") as revoke,
            mock.patch.object(self.module, "consume_prepared_trust") as consume,
        ):
            self.assertEqual(self.module.create_conformance_lease(args), lease_id)
            self.module.revoke_conformance_lease(args, lease_id)

        create.assert_called_once_with(
            args.nazoauthctl,
            args.nazoauthctl_config,
            profile="openid4vc",
            material=args.prepared_install_dir / self.module.PREPARED_TRUST_FILE,
            ttl_seconds=28_800,
            candidate=None,
        )
        consume.assert_called_once_with(args.prepared_install_dir, "a" * 64)
        revoke.assert_called_once_with(
            args.nazoauthctl,
            args.nazoauthctl_config,
            lease_id,
            candidate=None,
        )

    def test_ctl_lease_is_registered_before_prepared_trust_consumption(self):
        lease_id = "018f3f2a-7b55-7a25-8f20-6d526f8f44e1"
        args = self.module.argparse.Namespace(
            nazoauthctl=Path("/usr/local/bin/nazoauthctl"),
            nazoauthctl_config=Path("/etc/nazoauth/update.json"),
            prepared_install_dir=Path("/run/nazoauth-host-local-oidf-install"),
            prepared_trust_digest="a" * 64,
            lease_ttl_seconds=28_800,
        )

        def consume_and_fail(*_args):
            self.assertEqual(args.active_lease_id, lease_id)
            raise RuntimeError("prepared trust consumption failed")

        with (
            mock.patch.object(self.module, "create_lease", return_value=lease_id),
            mock.patch.object(self.module, "consume_prepared_trust", side_effect=consume_and_fail),
        ):
            with self.assertRaisesRegex(RuntimeError, "consumption failed"):
                self.module.create_conformance_lease(args)

        self.assertEqual(args.active_lease_id, lease_id)

    def test_final_receipt_is_credential_free_and_states_no_proxy_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.module.argparse.Namespace(
                export_dir=root,
                deployed_sha="a" * 40,
                runner_sha="b" * 40,
                suite_revision="c" * 40,
                target_issuer="https://issuer.example",
                conformance_server="https://suite.example",
            )
            manifest = root / "evidence-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "summary": {"plan_count": 17, "module_results": {"PASSED": 17}},
                        "archives": [
                            {
                                "modules": [
                                    {"test_info": {"planId": f"plan-{index}"}}
                                    for index in range(17)
                                ]
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            path = self.module.write_receipt(
                args,
                outcome="PASSED",
                cleanup_complete=True,
                manifest_path=manifest,
            )
            receipt = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "PASSED")
            self.assertEqual(receipt["plan_registry_count"], 17)
            self.assertEqual(len(receipt["evidence"]["plan_ids"]), 17)
            self.assertEqual(len(receipt["evidence"]["manifest_sha256"]), 64)
            self.assertFalse(receipt["mTLS_proxy_trust_touched"])
            self.assertNotIn("token", json.dumps(receipt).lower())

    def test_run_matrix_uses_inherited_descriptors_not_secret_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "configs": {
                    f"openid4vc-{slug}.json": {"alias": f"alias-{index}"}
                    for index, (_, slug, _) in enumerate(self.module.materializer.matrix_cases())
                }
            }
            (root / "openid4vc-plan-configs.json").write_text(json.dumps(config), encoding="utf-8")
            (root / "openid4vc-expected-problems.json").write_text("[]", encoding="utf-8")
            (root / "openid4vc-expected-skips.json").write_text("[]", encoding="utf-8")
            args = self.module.argparse.Namespace(
                work_dir=root,
                suite_dir=Path("/suite"),
                suite_revision="a" * 40,
                conformance_server="https://suite.example",
                target_issuer="https://issuer.example",
                export_dir=root / "export",
                timeout_seconds=1,
                monitor_interval_seconds=1,
                plan_group_size=4,
            )
            with (
                mock.patch.object(self.module.openid4vc, "main", return_value=0) as main,
                mock.patch.object(self.module.oidf, "inspect_oidf_state", return_value=None),
            ):
                self.module.run_matrix(
                    args,
                    {
                        "applicant_email": "applicant@example.test",
                        "applicant_password": "applicant-password",
                        "admin_email": "admin@example.test",
                        "admin_password": "admin-password",
                        "admin_mfa_totp_secret": "admin-totp-secret",
                        "suite_token": "suite-token",
                    },
                )
            invocation = main.call_args.args[0]
            self.assertIn("--operator-credentials-fd", invocation)
            self.assertIn("--suite-token-fd", invocation)
            self.assertNotIn("--operator-credentials-file", invocation)
            self.assertNotIn("--suite-token-file", invocation)

    def test_receipt_is_durable_before_signal_handlers_are_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            export = root / "export"
            suite = root / "suite"
            suite.mkdir()
            anchor = root / "anchor.pem"
            anchor.write_text("public", encoding="ascii")
            args = self.module.argparse.Namespace(
                plan_group_size=4,
                target_issuer="https://issuer.example",
                conformance_server="https://suite.example",
                work_dir=work,
                export_dir=export,
                suite_dir=suite,
                deployed_source_dir=ROOT,
                deployed_sha="a" * 40,
                runner_sha="a" * 40,
                suite_revision="b" * 40,
                request_object_trust_anchor_pem=anchor,
                prepared_install_dir=root / "prepared",
                nazoauthctl=ROOT / "scripts" / "run_host_local_openid4vc_conformance.py",
                nazoauthctl_config=None,
                lease_ttl_seconds=28_800,
                run_namespace="receipt-window",
                secrets_stdin=True,
                secret_fd=None,
                timeout_seconds=1,
                monitor_interval_seconds=1,
            )
            handlers = {
                self.module.signal.SIGINT: object(),
                self.module.signal.SIGTERM: object(),
            }
            original = dict(handlers)

            def set_signal(signum, handler):
                previous = handlers[signum]
                handlers[signum] = handler
                return previous

            def assert_receipt_window(*_args, **_kwargs):
                self.assertIs(handlers[self.module.signal.SIGINT], self.module.signal.SIG_IGN)
                self.assertIs(handlers[self.module.signal.SIGTERM], self.module.signal.SIG_IGN)
                return export / "host-local-openid4vc-receipt.json"

            secret_values = {field: f"private-{field}" for field in self.module.SECRET_FIELDS}
            with (
                mock.patch.object(self.module, "validate_output_paths"),
                mock.patch.object(self.module, "verify_source"),
                mock.patch.object(self.module, "verify_suite"),
                mock.patch.object(
                    self.module,
                    "prepared_material",
                    return_value=(
                        self.fake_material(),
                        "prepared-digest",
                        "prepared-trust-digest",
                    ),
                ),
                mock.patch.object(self.module, "read_public_trust_anchor", return_value="public"),
                mock.patch.object(self.module, "read_secret_document", return_value=secret_values),
                mock.patch.object(self.module, "verify_suite_boundary"),
                mock.patch.object(
                    self.module.applicant_provisioning,
                    "provision",
                    return_value={"user_id": "00000000-0000-0000-0000-000000000123"},
                ),
                mock.patch.object(self.module, "materialize_configs"),
                mock.patch.object(self.module, "consume_prepared_material"),
                mock.patch.object(self.module, "apply_public_onboarding"),
                mock.patch.object(self.module, "run_matrix"),
                mock.patch.object(
                    self.module,
                    "sanitize_evidence_tree",
                    return_value=export / "evidence-manifest.json",
                ),
                mock.patch.object(self.module, "write_receipt", side_effect=assert_receipt_window),
                mock.patch.object(self.module.signal, "getsignal", side_effect=lambda signum: handlers[signum]),
                mock.patch.object(self.module.signal, "signal", side_effect=set_signal),
            ):
                self.module.run(args)

            self.assertIs(handlers[self.module.signal.SIGINT], original[self.module.signal.SIGINT])
            self.assertIs(handlers[self.module.signal.SIGTERM], original[self.module.signal.SIGTERM])


if __name__ == "__main__":
    unittest.main()
