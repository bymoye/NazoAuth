import importlib.util
import unittest
from pathlib import Path


def load_setup_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "setup_local_oidf_podman.py"
    spec = importlib.util.spec_from_file_location("setup_local_oidf_podman", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SetupLocalOidfPodmanTests(unittest.TestCase):
    def test_session_management_browser_automation_waits_for_result_pages(self):
        module = load_setup_module()

        automation = module.browser_automation()
        commands = [
            command
            for entry in automation
            for task in entry.get("tasks", [])
            for command in task.get("commands", [])
        ]

        self.assertIn(["wait", "contains", "/session_result?state=unchanged", 30], commands)
        self.assertIn(
            ["wait", "contains", "/second_session_result?state=changed", 30],
            commands,
        )

    def test_frontchannel_logout_uses_single_authorize_automation(self):
        module = load_setup_module()

        config = module.write_frontchannel_logout_plan_config()

        authorize_entries = [
            entry
            for entry in config.get("browser", [])
            if entry.get("match") == f"{module.ISSUER}/authorize*"
        ]
        self.assertEqual(len(authorize_entries), 1)
        self.assertNotIn("override", config)

    def test_fapi_ciba_plan_uses_mtls_sender_constraint(self):
        module = load_setup_module()

        configs = module.write_fapi_ciba_plan_config()
        config = configs["oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json"]

        self.assertEqual(config["nazo"]["sender_constrain"], "mtls")
        self.assertIn("mtls", config)
        self.assertIn("mtls2", config)

    def test_all_generated_plans_allow_the_native_sso_metadata_extension(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_oidcc_config_plan_config(),
            module.write_frontchannel_logout_plan_config(),
            module.write_session_management_plan_config(),
        ]
        configs.extend(module.write_fapi_plan_configs().values())
        configs.extend(module.write_fapi_ciba_plan_config().values())
        configs.extend(module.write_fapi_matrix_plan_configs().values())

        self.assertGreaterEqual(len(configs), 20)
        for config in configs:
            self.assertEqual(
                config["server"]["allow_unexpected_metadata_fields"],
                ["native_sso_supported"],
            )


if __name__ == "__main__":
    unittest.main()
