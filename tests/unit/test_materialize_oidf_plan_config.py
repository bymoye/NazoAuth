import importlib.util
import json
import unittest
from pathlib import Path


def load_materializer_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "materialize_oidf_plan_config.py"
    spec = importlib.util.spec_from_file_location("materialize_oidf_plan_config", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class MaterializeOidfPlanConfigTests(unittest.TestCase):
    def test_repository_template_can_derive_both_new_logout_configs(self):
        module = load_materializer_module()
        template = (
            Path(__file__).resolve().parents[2]
            / "docs"
            / "conformance"
            / "oidf-plan-config-template.json"
        )
        rendered = json.loads(template.read_text(encoding="utf-8"))

        module.derive_logout_oidcc_configs(rendered)

        configs = rendered["configs"]
        self.assertIn(module.OIDCC_RP_INITIATED_LOGOUT_CONFIG_FILE, configs)
        self.assertIn(module.OIDCC_BACKCHANNEL_LOGOUT_CONFIG_FILE, configs)

    def test_logout_derivation_creates_independent_rp_and_backchannel_profiles(self):
        module = load_materializer_module()
        frontchannel = {
            "alias": "official-frontchannel-logout",
            "description": "front-channel",
            "client": {"client_id": "front-client"},
            "browser": [
                {
                    "match": "https://issuer.example/logout*",
                    "tasks": [
                        {
                            "task": "Reach post-logout redirect page",
                            "commands": [["wait", "url", "https://suite.example/callback"]],
                        }
                    ],
                }
            ],
            "override": {"front-only": True},
        }
        rendered = {
            "configs": {module.OIDCC_FRONTCHANNEL_LOGOUT_CONFIG_FILE: frontchannel}
        }

        module.derive_logout_oidcc_configs(rendered)

        configs = rendered["configs"]
        rp = configs[module.OIDCC_RP_INITIATED_LOGOUT_CONFIG_FILE]
        backchannel = configs[module.OIDCC_BACKCHANNEL_LOGOUT_CONFIG_FILE]
        self.assertEqual(rp["alias"], "official-rp-initiated-logout")
        self.assertEqual(rp["client"]["client_id"], "oidf-rp-initiated-logout-client")
        self.assertNotIn("override", rp)
        self.assertEqual(backchannel["alias"], "official-backchannel-logout")
        self.assertEqual(
            backchannel["client"]["client_id"],
            "oidf-backchannel-logout-client",
        )
        self.assertNotIn("override", backchannel)
        logout_tasks = rp["browser"][0]["tasks"]
        self.assertEqual(logout_tasks[0]["task"], "Confirm an unbound logout request")
        self.assertTrue(logout_tasks[0]["optional"])
        self.assertEqual(
            logout_tasks[0]["commands"],
            [["click", "id", "nazo-logout-confirm", "optional"]],
        )
        self.assertEqual(logout_tasks[1]["task"], "Capture local logout result page")
        self.assertTrue(logout_tasks[1]["optional"])
        self.assertEqual(logout_tasks[2]["task"], "Reach post-logout redirect page")
        self.assertTrue(logout_tasks[2]["optional"])
        self.assertEqual(frontchannel["client"]["client_id"], "front-client")

    def test_mtls_material_replaces_every_identity_and_rejects_unused_clients(self):
        module = load_materializer_module()
        rendered = {
            "configs": {
                "one.json": {
                    "client": {"client_id": "client-one"},
                    "client2": {"client_id": "client-two"},
                    "mtls": {"ca": "old", "cert": "old", "key": "old"},
                    "mtls2": {"ca": "old", "cert": "old", "key": "old"},
                },
                "two.json": {
                    "client": {"client_id": "client-one"},
                    "mtls": {"ca": "old", "cert": "old", "key": "old"},
                },
            }
        }
        material = {
            "schema": 1,
            "ca": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
            "clients": {
                "client-one": {
                    "cert": "-----BEGIN CERTIFICATE-----\none\n-----END CERTIFICATE-----\n",
                    "key": "-----BEGIN PRIVATE KEY-----\none\n-----END PRIVATE KEY-----\n",
                },
                "client-two": {
                    "cert": "-----BEGIN CERTIFICATE-----\ntwo\n-----END CERTIFICATE-----\n",
                    "key": "-----BEGIN PRIVATE KEY-----\ntwo\n-----END PRIVATE KEY-----\n",
                },
            },
        }

        module.apply_mtls_material(rendered, material)

        self.assertEqual(rendered["configs"]["one.json"]["mtls"]["ca"], material["ca"])
        self.assertEqual(
            rendered["configs"]["two.json"]["mtls"]["cert"],
            material["clients"]["client-one"]["cert"],
        )
        material["clients"]["unused"] = material["clients"]["client-one"]
        with self.assertRaisesRegex(SystemExit, "unused clients: unused"):
            module.apply_mtls_material(rendered, material)

    def test_dynamic_derivation_creates_distinct_signed_userinfo_config(self):
        module = load_materializer_module()
        basic = {
            "alias": "official-basic",
            "client": {"client_id": "static-1", "scope": "openid profile"},
            "client2": {"client_id": "static-2", "scope": "openid profile"},
            "client_secret_post": {
                "client_id": "static-3",
                "scope": "openid profile",
            },
        }
        rendered = {"configs": {module.OIDCC_BASIC_CONFIG_FILE: basic}}

        module.derive_dynamic_oidcc_config(rendered, "initial-token")

        dynamic = rendered["configs"][module.OIDCC_DYNAMIC_CONFIG_FILE]
        formpost = rendered["configs"][module.OIDCC_FORMPOST_CONFIG_FILE]
        third_party = rendered["configs"][module.OIDCC_THIRD_PARTY_INIT_CONFIG_FILE]
        self.assertEqual(dynamic["alias"], "official-basic-dynamic")
        self.assertEqual(formpost["alias"], "official-basic-formpost")
        self.assertEqual(formpost["client"]["client_id"], "static-1")
        self.assertEqual(third_party["alias"], "official-basic-third-party-init")
        self.assertEqual(third_party["client"]["initial_access_token"], "initial-token")

    def test_ciba_derivation_creates_four_distinct_orthogonal_profiles(self):
        module = load_materializer_module()
        source_slug = "fapi-ciba-plain-private-key-jwt-poll"
        source = {
            "alias": f"official-{source_slug}",
            "client": {
                "client_id": f"official-{source_slug}-client-1",
                "jwks": {"keys": [{"kid": f"official-{source_slug}-client-1-key"}]},
            },
            "client2": {
                "client_id": f"official-{source_slug}-client-2",
                "jwks": {"keys": [{"kid": f"official-{source_slug}-client-2-key"}]},
            },
            "mtls": {"cert": "shared-cert", "key": "shared-key"},
            "nazo": {},
        }
        rendered = {"configs": {module.FAPI_CIBA_SOURCE_CONFIG_FILE: source}}

        module.derive_fapi_ciba_matrix_configs(
            rendered, "https://www.certification.openid.net/"
        )

        configs = rendered["configs"]
        ciba_configs = {name: value for name, value in configs.items() if "fapi-ciba" in name}
        self.assertEqual(len(ciba_configs), 4)
        self.assertEqual(
            {
                (value["nazo"]["client_auth_type"], value["nazo"]["ciba_mode"])
                for value in ciba_configs.values()
            },
            {
                ("private_key_jwt", "poll"),
                ("mtls", "poll"),
                ("private_key_jwt", "ping"),
                ("mtls", "ping"),
            },
        )
        for value in ciba_configs.values():
            self.assertEqual(value["nazo"]["sender_constrain"], "mtls")
        self.assertEqual(
            len({value["client"]["client_id"] for value in ciba_configs.values()}), 4
        )
        for value in ciba_configs.values():
            client = value["client"]
            self.assertEqual(client["backchannel_authentication_request_signing_alg"], "PS256")
            self.assertFalse(client["backchannel_user_code_parameter"])
            if value["nazo"]["ciba_mode"] == "ping":
                self.assertEqual(
                    client["backchannel_client_notification_endpoint"],
                    "https://www.certification.openid.net/test/a/"
                    f"{value['alias']}/ciba-notification-endpoint",
                )
            else:
                self.assertNotIn("backchannel_client_notification_endpoint", client)
        self.assertEqual(
            ciba_configs[module.FAPI_CIBA_SOURCE_CONFIG_FILE]["mtls"],
            {"cert": "shared-cert", "key": "shared-key"},
        )

    def test_ciba_decision_token_is_rebound_without_preserving_old_secret(self):
        module = load_materializer_module()
        rendered = {
            "configs": {
                "poll.json": {
                    "automated_ciba_approval_url": (
                        "https://issuer.example/auth/ciba-automated-decision"
                        "?token={auth_req_id}&type={action}&decision_token=old-secret"
                    )
                },
                "ping.json": {
                    "automated_ciba_approval_url": (
                        "https://issuer.example/auth/ciba-automated-decision"
                        "?decision_token=old-secret&token={auth_req_id}"
                    )
                },
            }
        }
        token = "new-deployment-token-0123456789abcdef"

        module.bind_ciba_automated_decision_token(rendered, token)

        serialized = json.dumps(rendered)
        self.assertNotIn("old-secret", serialized)
        self.assertEqual(serialized.count(token), 2)
        self.assertIn("&token={auth_req_id}", serialized)
        for invalid in ("short", "x" * 32 + "&suffix", " x" * 20):
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                module.bind_ciba_automated_decision_token(rendered, invalid)

    def test_target_issuer_rewrites_every_template_issuer_url(self):
        module = load_materializer_module()
        rendered = {
            "configs": {
                module.FAPI_CIBA_SOURCE_CONFIG_FILE: {
                    "alias": "official-fapi-ciba-plain-private-key-jwt-poll",
                    "server": {
                        "discoveryUrl": "https://issuer.example/.well-known/openid-configuration",
                    },
                    "resource": {
                        "resourceUrl": "https://issuer.example/fapi/resource",
                    },
                    "browser": [
                        {"match": "https://issuer.example/authorize*"},
                        {"match": "*/test/*/callback*"},
                    ],
                    "client": {
                        "client_id": "official-fapi-ciba-plain-private-key-jwt-poll-client-1",
                        "jwks": {
                            "keys": [
                                {
                                    "kid": (
                                        "official-fapi-ciba-plain-private-key-jwt-poll"
                                        "-client-1-key"
                                    )
                                }
                            ]
                        },
                    },
                    "client2": {
                        "client_id": "official-fapi-ciba-plain-private-key-jwt-poll-client-2",
                        "jwks": {
                            "keys": [
                                {
                                    "kid": (
                                        "official-fapi-ciba-plain-private-key-jwt-poll"
                                        "-client-2-key"
                                    )
                                }
                            ]
                        },
                    },
                    "nazo": {},
                }
            }
        }

        module.derive_fapi_ciba_matrix_configs(
            rendered, "https://www.certification.openid.net"
        )
        rewritten = module.replace_template_issuer(rendered, "https://public.example")
        serialized = json.dumps(rewritten, sort_keys=True)

        self.assertNotIn("https://issuer.example", serialized)
        self.assertIn("https://public.example/authorize*", serialized)
        self.assertIn("https://public.example/.well-known/openid-configuration", serialized)
        self.assertIn("https://public.example/fapi/resource", serialized)
        self.assertIn(
            "https://www.certification.openid.net/test/a/"
            "official-fapi-ciba-plain-mtls-ping/ciba-notification-endpoint",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()
