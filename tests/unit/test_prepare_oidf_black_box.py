import importlib.util
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


def configure_test_secrets(module) -> None:
    reader, writer = os.pipe()
    try:
        os.write(
            writer,
            json.dumps(
                {
                    "oidf_applicant_email": "applicant@example.com",
                    "oidf_applicant_password": "test-applicant-password",
                    "oidf_dynamic_registration_initial_access_token": "test-initial-access-token",
                    "oidf_ciba_automated_decision_token": "test-ciba-decision-token",
                }
            ).encode("utf-8"),
        )
    finally:
        os.close(writer)
    try:
        module.configure_operator_secrets(
            Namespace(secrets_stdin=False, secret_fd=reader, secret_file=None)
        )
    finally:
        os.close(reader)


def load_setup_module(runtime_dir: str | None = None):
    script = Path(__file__).resolve().parents[2] / "scripts" / "prepare_oidf_black_box.py"
    spec = importlib.util.spec_from_file_location("prepare_oidf_black_box", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    environment = {
        "OIDF_TARGET_ISSUER": "https://issuer.example",
        "OIDF_MTLS_TARGET_ISSUER": "https://mtls.issuer.example",
        "OIDF_SUITE_BASE_URL": "https://suite.example",
    }
    if runtime_dir is not None:
        environment["OIDF_RUNTIME_DIR"] = runtime_dir
    with mock.patch.dict("os.environ", environment, clear=True):
        spec.loader.exec_module(module)
        configure_test_secrets(module)
    return module


def load_setup_module_with_suite_base(suite_base_url: str):
    script = Path(__file__).resolve().parents[2] / "scripts" / "prepare_oidf_black_box.py"
    spec = importlib.util.spec_from_file_location("prepare_oidf_black_box", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with mock.patch.dict(
        "os.environ",
        {
            "OIDF_TARGET_ISSUER": "https://issuer.example",
            "OIDF_MTLS_TARGET_ISSUER": "https://mtls.issuer.example",
            "OIDF_SUITE_BASE_URL": suite_base_url,
        },
        clear=True,
    ):
        spec.loader.exec_module(module)
        configure_test_secrets(module)
    return module


class PrepareOidfBlackBoxTests(unittest.TestCase):
    def test_runtime_directory_can_be_isolated_per_run(self):
        with tempfile.TemporaryDirectory() as directory:
            module = load_setup_module(directory)
            self.assertEqual(module.RUNTIME, Path(directory).resolve())

    def test_generated_mtls_ca_has_explicit_ca_signing_constraints(self):
        module = load_setup_module()

        with tempfile.TemporaryDirectory() as directory:
            module.RUNTIME = Path(directory)

            def generate_key(command, **_kwargs):
                Path(command[command.index("-keyout") + 1]).touch()

            with mock.patch.object(
                module.subprocess, "run", side_effect=generate_key
            ) as run:
                module.ensure_mtls_ca()

        command = run.call_args.args[0]
        extensions = [
            command[index + 1]
            for index, argument in enumerate(command[:-1])
            if argument == "-addext"
        ]
        self.assertEqual(
            extensions,
            [
                "basicConstraints=critical,CA:TRUE",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )

    def test_baseline_logout_session_flags_follow_specification_defaults(self):
        module = load_setup_module()

        request = module.base_client_request(
            name="Baseline client",
            auth_method="client_secret_basic",
            redirect_uris=["https://client.example/callback"],
        )

        self.assertFalse(request["frontchannel_logout_session_required"])
        self.assertFalse(request["backchannel_logout_session_required"])

    def test_operator_clients_use_a_stable_non_official_run_namespace(self):
        first = load_setup_module_with_suite_base("https://suite.example")
        second = load_setup_module_with_suite_base("https://other-suite.example")

        self.assertTrue(first.RUN_NAMESPACE.startswith("bb-"))
        self.assertNotEqual(first.RUN_NAMESPACE, second.RUN_NAMESPACE)
        self.assertNotEqual(first.BASIC_CLIENT_ID, "oidf-basic-client")
        self.assertTrue(first.BASIC_CLIENT_ID.startswith(f"oidf-{first.RUN_NAMESPACE}-"))
        self.assertTrue(first.FAPI_CLIENT_PREFIX.startswith(f"oidf-{first.RUN_NAMESPACE}-"))

        self.assertEqual(
            first.onboarding_contract(),
            {
                "schema": 1,
                "onboarding_profile": "operator-black-box",
                "target_issuer": "https://issuer.example",
                "suite_base_url": "https://suite.example",
                "run_namespace": first.RUN_NAMESPACE,
            },
        )

    def test_suite_base_must_be_public_dns_not_local_or_raw_ip(self):
        for suite_base_url in (
            "https://127.0.0.1:8443",
            "https://192.0.2.10:8443",
            "https://localhost:8443",
            "https://suite.local",
        ):
            with self.subTest(suite_base_url=suite_base_url):
                with self.assertRaisesRegex(RuntimeError, "public DNS hostname"):
                    load_setup_module_with_suite_base(suite_base_url)

    def test_every_callback_completion_wait_has_a_thirty_second_floor(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_formpost_plan_config(),
            module.write_third_party_init_plan_config(),
        ]
        commands = [
            command
            for config in configs
            for entry in config.get("browser", [])
            for task in entry.get("tasks", [])
            for command in task.get("commands", [])
        ]
        callback_waits = [
            command
            for command in commands
            if command[:3] == ["wait", "id", "submission_complete"]
        ]

        self.assertTrue(callback_waits)
        self.assertTrue(all(command[3] >= 30 for command in callback_waits))

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

    def test_unbound_logout_confirmation_is_scoped_to_the_rp_initiated_plan(self):
        module = load_setup_module()

        rp = module.write_rp_initiated_logout_plan_config()
        front = module.write_frontchannel_logout_plan_config()

        def logout_tasks(config):
            entry = next(
                item
                for item in config["browser"]
                if item.get("match") == f"{module.ISSUER}/logout*"
            )
            return entry["tasks"]

        rp_tasks = logout_tasks(rp)
        front_tasks = logout_tasks(front)
        self.assertEqual(rp_tasks[0]["task"], "Confirm an unbound logout request")
        self.assertTrue(rp_tasks[0]["optional"])
        self.assertEqual(
            rp_tasks[0]["commands"],
            [["click", "id", "nazo-logout-confirm", "optional"]],
        )
        self.assertEqual(rp_tasks[1]["task"], "Capture local logout result page")
        self.assertTrue(rp_tasks[1]["optional"])
        self.assertEqual(rp_tasks[2]["task"], "Reach post-logout redirect page")
        self.assertTrue(rp_tasks[2]["optional"])
        self.assertEqual(
            [task["task"] for task in front_tasks],
            [
                "Continue after front-channel iframe notification",
                "Reach post-logout redirect page",
            ],
        )
        self.assertEqual(
            front_tasks[0]["commands"],
            [["click", "id", "nazo-frontchannel-logout-continue"]],
        )
        self.assertNotIn("optional", front_tasks[0])
        self.assertNotIn("optional", front_tasks[1])

    def test_generator_does_not_materialize_a_private_product_environment(self):
        source = (Path(__file__).resolve().parents[2] / "scripts" / "prepare_oidf_black_box.py").read_text(
            encoding="utf-8"
        )

        for forbidden in (
            "write_nginx",
            "write_env_yaml",
            "write_ui",
            "ensure_server_oidf_keyset",
            "listen 9443",
            "OIDF_PLAN_CONFIG_JSON=",
        ):
            self.assertNotIn(forbidden, source)

        onboarding_source = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "apply_public_conformance_onboarding.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("OIDF_PLAN_CONFIG_JSON=", onboarding_source)

    def test_fapi_ciba_plans_are_the_orthogonal_supported_combinations(self):
        module = load_setup_module()

        configs = module.write_fapi_ciba_plan_config()
        self.assertEqual(
            {
                (config["nazo"]["client_auth_type"], config["nazo"]["ciba_mode"])
                for config in configs.values()
            },
            {
                ("private_key_jwt", "poll"),
                ("mtls", "poll"),
                ("private_key_jwt", "ping"),
                ("mtls", "ping"),
            },
        )
        for config in configs.values():
            self.assertEqual(config["nazo"]["sender_constrain"], "mtls")
            self.assertIn("mtls", config)
            self.assertIn("mtls2", config)
            self.assertTrue(config["resource"]["resourceUrl"].startswith("https://"))
            for key in ("client", "client2"):
                self.assertEqual(
                    config[key]["backchannel_token_delivery_mode"],
                    config["nazo"]["ciba_mode"],
                )
                self.assertEqual(
                    config[key]["backchannel_authentication_request_signing_alg"],
                    "PS256",
                )
                self.assertEqual(
                    "backchannel_client_notification_endpoint" in config[key],
                    config["nazo"]["ciba_mode"] == "ping",
                )
                if config["nazo"]["ciba_mode"] == "ping":
                    self.assertEqual(
                        config[key]["backchannel_client_notification_endpoint"],
                        f"https://suite.example/test/a/{config['alias']}"
                        "/ciba-notification-endpoint",
                    )

    def test_tls_client_auth_onboarding_narrows_ca_trust_with_leaf_pin(self):
        module = load_setup_module()
        config = {
            "alias": "fapi-mtls",
            "nazo": {
                "client_auth_type": "mtls",
                "sender_constrain": "mtls",
                "fapi_profile": "plain_fapi",
            },
            "client": {"client_id": "mtls-client-1", "scope": "openid", "jwks": {}},
            "client2": {"client_id": "mtls-client-2", "scope": "openid", "jwks": {}},
            "mtls": {"cert": "certificate-1", "ca": "ca-certificate"},
            "mtls2": {"cert": "certificate-2", "ca": "ca-certificate"},
        }

        with (
            mock.patch.object(module, "public_jwks", return_value={"keys": []}),
            mock.patch.object(module, "certificate_subject_dn", return_value="CN=client"),
            mock.patch.object(
                module,
                "certificate_sha256",
                side_effect=("1" * 64, "2" * 64),
            ),
        ):
            clients = module.onboarding_clients({"oidf-fapi-mtls.json": config})

        by_id = {item["logical_client_id"]: item for item in clients}
        self.assertEqual(
            by_id["mtls-client-1"]["request"]["tls_client_auth_cert_sha256"],
            "1" * 64,
        )
        self.assertEqual(
            by_id["mtls-client-2"]["request"]["tls_client_auth_cert_sha256"],
            "2" * 64,
        )
        self.assertEqual(
            by_id["mtls-client-1"]["mtls_trust_anchor_pem"], "ca-certificate"
        )

    def test_plan_manifest_description_uses_the_actual_plan_count(self):
        module = load_setup_module()
        configs = {
            "first.json": {"description": "first"},
            "second.json": {"description": "second"},
        }

        manifest = module.plan_manifest_for_expressions(
            ["first-plan first.json", "second-plan second.json"], configs
        )

        self.assertIn("2-plan", manifest["description"])
        self.assertEqual(len(manifest["plans"]), 2)

    def test_dynamic_op_certification_is_not_in_supported_matrix(self):
        module = load_setup_module()
        configs = {
            "oidf-oidcc-basic-plan-config.json": module.write_basic_plan_config(),
            "oidf-oidcc-dynamic-plan-config.json": module.write_dynamic_plan_config(),
        }
        expressions = module.plan_expressions_for_configs(configs)

        self.assertFalse(
            any("oidcc-dynamic-certification-test-plan" in item for item in expressions)
        )
        self.assertTrue(
            any("client_registration=dynamic_client" in item for item in expressions)
        )

    def test_unsigned_compatibility_skips_are_explicit_and_bounded(self):
        module = load_setup_module()

        skips = module.expected_skips()

        self.assertEqual(len(skips), 8)
        self.assertEqual(
            {item["configuration-filename"] for item in skips},
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-dynamic-plan-config.json",
                "oidf-oidcc-formpost-plan-config.json",
            },
        )
        self.assertEqual({item["variant"] for item in skips}, {"*"})

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
        rp_initiated = (
            "oidcc-rp-initiated-logout-certification-test-plan rp.json"
        )
        backchannel = (
            "oidcc-backchannel-rp-initiated-logout-certification-test-plan "
            "backchannel.json"
        )
        session = (
            "oidcc-session-management-certification-test-plan session.json"
        )
        ciba = "fapi-ciba-id1-test-plan[client_auth_type=mtls] ciba.json"

        (
            concurrent,
            ciba_only,
            rp_initiated_only,
            backchannel_only,
            frontchannel_only,
            session_only,
        ) = module.partition_plan_expressions(
            [parallel, rp_initiated, backchannel, frontchannel, session, ciba]
        )

        self.assertEqual(concurrent, [parallel])
        self.assertEqual(ciba_only, [ciba])
        self.assertEqual(rp_initiated_only, [rp_initiated])
        self.assertEqual(backchannel_only, [backchannel])
        self.assertEqual(frontchannel_only, [frontchannel])
        self.assertEqual(session_only, [session])

    def test_all_generated_plans_allow_the_native_sso_metadata_extension(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_oidcc_config_plan_config(),
            module.write_rp_initiated_logout_plan_config(),
            module.write_backchannel_logout_plan_config(),
            module.write_frontchannel_logout_plan_config(),
            module.write_session_management_plan_config(),
        ]
        configs.extend(module.write_fapi_plan_configs().values())
        configs.extend(module.write_fapi_ciba_plan_config().values())
        configs.extend(module.write_fapi_matrix_plan_configs().values())

        self.assertGreaterEqual(len(configs), 23)
        for config in configs:
            self.assertEqual(
                config["server"]["allow_unexpected_metadata_fields"],
                ["native_sso_supported"],
            )

    def test_bounded_parallel_groups_cover_the_full_matrix_once(self):
        module = load_setup_module()
        configs = {
            "oidf-oidcc-basic-plan-config.json": module.write_basic_plan_config(),
            "oidf-oidcc-dynamic-plan-config.json": module.write_dynamic_plan_config(),
            "oidf-oidcc-formpost-plan-config.json": module.write_formpost_plan_config(),
            "oidf-oidcc-third-party-init-plan-config.json": module.write_third_party_init_plan_config(),
            "oidf-oidcc-config-plan-config.json": module.write_oidcc_config_plan_config(),
            "oidf-oidcc-rp-initiated-logout-plan-config.json": module.write_rp_initiated_logout_plan_config(),
            "oidf-oidcc-backchannel-logout-plan-config.json": module.write_backchannel_logout_plan_config(),
            "oidf-oidcc-frontchannel-logout-plan-config.json": module.write_frontchannel_logout_plan_config(),
            "oidf-oidcc-session-management-plan-config.json": module.write_session_management_plan_config(),
        }
        configs.update(module.write_fapi_ciba_plan_config())
        configs.update(module.write_fapi_matrix_plan_configs())
        plan_set = module.plan_expressions_for_configs(configs)

        groups = module.bounded_parallel_plan_groups(plan_set)

        self.assertEqual(
            list(groups),
            [
                "01-oidc-core.json",
                "02-oidc-formpost-thirdparty-config.json",
                "03a-fapi-ciba-private-key-jwt-poll.json",
                "03b-fapi-ciba-mtls-poll.json",
                "03c-fapi-ciba-private-key-jwt-ping.json",
                "03d-fapi-ciba-mtls-ping.json",
                "04-fapi-message-and-mtls-dpop.json",
                "05-fapi-mtls-mtls.json",
                "06-fapi-private-dpop.json",
                "07-fapi-private-mtls.json",
                "08-rp-initiated.json",
                "09-backchannel.json",
                "10-frontchannel.json",
                "11-session.json",
            ],
        )
        flattened = [plan for group in groups.values() for plan in group]
        self.assertEqual(len(flattened), 27)
        self.assertEqual(sorted(flattened), sorted(plan_set))
        self.assertEqual(len(groups["03a-fapi-ciba-private-key-jwt-poll.json"]), 1)
        self.assertEqual(len(groups["03b-fapi-ciba-mtls-poll.json"]), 1)
        self.assertEqual(len(groups["03c-fapi-ciba-private-key-jwt-ping.json"]), 1)
        self.assertEqual(len(groups["03d-fapi-ciba-mtls-ping.json"]), 1)
        self.assertEqual(len(groups["08-rp-initiated.json"]), 1)
        self.assertEqual(len(groups["09-backchannel.json"]), 1)
        self.assertEqual(len(groups["10-frontchannel.json"]), 1)
        self.assertEqual(len(groups["11-session.json"]), 1)

    def test_logout_plan_contract_uses_authoritative_oidf_names_and_configs(self):
        module = load_setup_module()
        configs = {
            "oidf-oidcc-basic-plan-config.json": module.write_basic_plan_config(),
            "oidf-oidcc-dynamic-plan-config.json": module.write_dynamic_plan_config(),
            "oidf-oidcc-formpost-plan-config.json": module.write_formpost_plan_config(),
            "oidf-oidcc-third-party-init-plan-config.json": module.write_third_party_init_plan_config(),
            "oidf-oidcc-config-plan-config.json": module.write_oidcc_config_plan_config(),
            "oidf-oidcc-rp-initiated-logout-plan-config.json": module.write_rp_initiated_logout_plan_config(),
            "oidf-oidcc-backchannel-logout-plan-config.json": module.write_backchannel_logout_plan_config(),
            "oidf-oidcc-frontchannel-logout-plan-config.json": module.write_frontchannel_logout_plan_config(),
            "oidf-oidcc-session-management-plan-config.json": module.write_session_management_plan_config(),
        }
        configs.update(module.write_fapi_ciba_plan_config())
        configs.update(module.write_fapi_matrix_plan_configs())

        expressions = module.plan_expressions_for_configs(configs)
        manifest = module.plan_manifest_for_expressions(expressions, configs)
        by_config = {plan["config"]: plan for plan in manifest["plans"]}

        self.assertEqual(len(expressions), 27)
        self.assertEqual(
            expressions[5],
            "oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
            "oidf-oidcc-rp-initiated-logout-plan-config.json",
        )
        self.assertEqual(
            expressions[6],
            "oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
            "oidf-oidcc-backchannel-logout-plan-config.json",
        )
        self.assertEqual(
            by_config["oidf-oidcc-rp-initiated-logout-plan-config.json"]["title"],
            "OIDC RP-Initiated Logout OP",
        )
        self.assertEqual(
            by_config["oidf-oidcc-backchannel-logout-plan-config.json"]["title"],
            "OIDC Back-Channel Logout OP",
        )

    def test_help_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_mtls_certs") as ensure_mtls_certs:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        ensure_mtls_certs.assert_not_called()

    def test_unknown_argument_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_mtls_certs") as ensure_mtls_certs:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--not-a-real-option"])

        self.assertEqual(raised.exception.code, 2)
        ensure_mtls_certs.assert_not_called()


if __name__ == "__main__":
    unittest.main()
