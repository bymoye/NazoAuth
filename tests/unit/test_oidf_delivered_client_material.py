import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    path = ROOT / "scripts" / name
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class OidfDeliveredClientMaterialTests(unittest.TestCase):
    def test_official_loader_ignores_manifest_bound_install_profile(self):
        module = load("prepare_official_oidf_public_onboarding.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "oidf-plan.json").write_text('{"alias":"plan"}', encoding="utf-8")
            (root / "standards-full-profile.json").write_text(
                '{"public":"install-material"}', encoding="utf-8"
            )

            configs = module.load_configs(root)

        self.assertEqual(configs, {"oidf-plan.json": {"alias": "plan"}})

    def test_official_application_builder_derives_static_oidc_clients_from_artifact_fields(self):
        module = load("prepare_official_oidf_public_onboarding.py")
        common = {
            "client": {"client_id": "basic", "scope": "openid profile"},
            "client2": {"client_id": "basic-2", "scope": "openid profile"},
            "client_secret_post": {"client_id": "post", "scope": "openid profile"},
        }
        configs = {
            "oidf-oidcc-basic-plan-config.json": {"alias": "basic-alias", **common},
            "oidf-oidcc-formpost-plan-config.json": {
                "alias": "formpost-alias",
                **common,
            },
            "oidf-oidcc-rp-initiated-logout-plan-config.json": {
                "alias": "rp-alias",
                "client": {"client_id": "rp", "scope": "openid"},
            },
            "oidf-oidcc-backchannel-logout-plan-config.json": {
                "alias": "back-alias",
                "client": {"client_id": "back", "scope": "openid"},
            },
            "oidf-oidcc-frontchannel-logout-plan-config.json": {
                "alias": "front-alias",
                "client": {"client_id": "front", "scope": "openid"},
            },
            "oidf-oidcc-session-management-plan-config.json": {
                "alias": "session-alias",
                "client": {"client_id": "session", "scope": "openid"},
            },
        }

        clients = module.prepare_oidc_clients(
            configs,
            target_origin="https://issuer.example",
            suite_origin="https://suite.example",
        )

        self.assertEqual(
            {item["logical_client_id"] for item in clients},
            {"basic", "basic-2", "post", "rp", "back", "front", "session"},
        )
        basic = next(item for item in clients if item["logical_client_id"] == "basic")
        self.assertEqual(
            basic["request"]["redirect_uris"],
            [
                "https://suite.example/test/a/basic-alias/callback",
                "https://suite.example/test/a/formpost-alias/callback",
            ],
        )
        front = next(item for item in clients if item["logical_client_id"] == "front")
        self.assertTrue(front["request"]["frontchannel_logout_session_required"])
        rp = next(item for item in clients if item["logical_client_id"] == "rp")
        self.assertEqual(
            rp["request"]["post_logout_redirect_uris"],
            ["https://suite.example/test/a/rp-alias/post_logout_redirect"],
        )
        back = next(item for item in clients if item["logical_client_id"] == "back")
        self.assertEqual(
            back["request"]["backchannel_logout_uri"],
            "https://suite.example/test/a/back-alias/backchannel_logout",
        )
        self.assertTrue(back["request"]["backchannel_logout_session_required"])

    def test_mapping_is_target_bound_and_updates_only_client_id_fields(self):
        module = load("apply_oidf_delivered_client_material.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            material = root / "material.json"
            configs = root / "configs.json"
            material.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "suite_base_url": "https://suite.example",
                        "clients": [
                            {
                                "logical_client_id": "logical-client",
                                "client_id": "delivered-client",
                                "client_secret": "delivered-secret",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            configs.write_text(
                json.dumps(
                    {
                        "configs": {
                            "plan.json": {
                                "client": {"client_id": "logical-client"},
                                "description": "logical-client",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "sys.argv",
                [
                    "apply_oidf_delivered_client_material.py",
                    "--material-json-file",
                    str(material),
                    "--config-json-file",
                    str(configs),
                    "--expected-target-issuer",
                    "https://issuer.example",
                    "--expected-suite-base-url",
                    "https://suite.example",
                ],
            ):
                self.assertEqual(module.main(), 0)
            updated = json.loads(configs.read_text(encoding="utf-8"))
            plan = updated["configs"]["plan.json"]
            self.assertEqual(plan["client"]["client_id"], "delivered-client")
            self.assertEqual(plan["client"]["client_secret"], "delivered-secret")
            self.assertEqual(plan["description"], "logical-client")

    def test_mapping_rejects_a_different_suite(self):
        module = load("apply_oidf_delivered_client_material.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            material = root / "material.json"
            configs = root / "configs.json"
            material.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "suite_base_url": "https://wrong.example",
                        "clients": [
                            {
                                "logical_client_id": "logical",
                                "client_id": "actual",
                                "client_secret": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            configs.write_text('{"configs":{"p":{"client_id":"logical"}}}', encoding="utf-8")
            with (
                patch(
                    "sys.argv",
                    [
                        "apply_oidf_delivered_client_material.py",
                        "--material-json-file",
                        str(material),
                        "--config-json-file",
                        str(configs),
                        "--expected-target-issuer",
                        "https://issuer.example",
                        "--expected-suite-base-url",
                        "https://suite.example",
                    ],
                ),
                self.assertRaisesRegex(SystemExit, "suite base URL"),
            ):
                module.main()


if __name__ == "__main__":
    unittest.main()
