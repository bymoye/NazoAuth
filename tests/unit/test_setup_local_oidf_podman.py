import importlib.util
import unittest
from pathlib import Path
from unittest import mock


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

    def test_dynamic_crypto_plan_has_distinct_alias_and_matrix_expression(self):
        module = load_setup_module()

        config = module.write_dynamic_crypto_plan_config()
        filename = "oidf-oidcc-dynamic-crypto-plan-config.json"
        expressions = module.plan_expressions_for_configs({filename: config})

        self.assertTrue(config["alias"].endswith("-dynamic-crypto"))
        self.assertIn(
            "oidcc-dynamic-certification-test-plan[response_type=code]:"
            "oidcc-userinfo-rs256 "
            + filename,
            expressions,
        )
        dynamic_expression = next(
            expression for expression in expressions if expression.endswith(filename)
        )
        manifest = module.plan_manifest_for_expressions(
            [dynamic_expression], {filename: config}
        )
        self.assertIn("Twenty-one-plan", manifest["description"])

    def test_dynamic_plan_uses_terminal_browser_flow_for_local_redirect_errors(self):
        module = load_setup_module()

        config = module.dynamic_plan_config()

        for module_name in (
            "oidcc-ensure-registered-redirect-uri",
            "oidcc-ensure-redirect-uri-in-authorization-request",
            "oidcc-redirect-uri-query-mismatch",
            "oidcc-redirect-uri-query-added",
        ):
            tasks = config["override"][module_name]["browser"][0]["tasks"]
            self.assertEqual(
                [task["task"] for task in tasks],
                ["Capture authorization error response"],
            )

    def test_plan_partition_is_complete_and_isolates_browser_sensitive_plans(self):
        module = load_setup_module()
        parallel = "oidcc-basic-certification-test-plan basic.json"
        frontchannel = (
            "oidcc-frontchannel-rp-initiated-logout-certification-test-plan "
            "frontchannel.json"
        )
        session = (
            "oidcc-session-management-certification-test-plan session.json"
        )

        concurrent, frontchannel_only, session_only = module.partition_plan_expressions(
            [parallel, frontchannel, session]
        )

        self.assertEqual(concurrent, [parallel])
        self.assertEqual(frontchannel_only, [frontchannel])
        self.assertEqual(session_only, [session])

    def test_all_generated_plans_allow_the_native_sso_metadata_extension(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_dynamic_crypto_plan_config(),
            module.write_oidcc_config_plan_config(),
            module.write_frontchannel_logout_plan_config(),
            module.write_session_management_plan_config(),
        ]
        configs.extend(module.write_fapi_plan_configs().values())
        configs.extend(module.write_fapi_ciba_plan_config().values())
        configs.extend(module.write_fapi_matrix_plan_configs().values())

        self.assertGreaterEqual(len(configs), 21)
        for config in configs:
            self.assertEqual(
                config["server"]["allow_unexpected_metadata_fields"],
                ["native_sso_supported"],
            )

    def test_help_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_cert") as ensure_cert:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        ensure_cert.assert_not_called()

    def test_unknown_argument_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_cert") as ensure_cert:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--not-a-real-option"])

        self.assertEqual(raised.exception.code, 2)
        ensure_cert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
