import importlib.util
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
        crypto = rendered["configs"][module.OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE]
        self.assertEqual(dynamic["alias"], "official-basic-dynamic")
        self.assertEqual(crypto["alias"], "official-basic-dynamic-crypto")
        self.assertEqual(crypto["client"]["initial_access_token"], "initial-token")
        self.assertEqual(crypto["client"]["scope"], "openid profile")
        self.assertNotIn("client_id", crypto["client"])


if __name__ == "__main__":
    unittest.main()
