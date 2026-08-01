import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Openid4vcOidfTests(unittest.TestCase):
    def test_dataset_fixture_uses_admin_session_csrf_and_is_cleaned_up(self):
        module = load("run_openid4vc_conformance.py")

        class Session:
            def __init__(self):
                self.json_calls = []
                self.calls = []

            def request_json(self, method, path, payload=None, **kwargs):
                self.json_calls.append((method, path, payload, kwargs))
                if path == "/auth/me":
                    return {"admin_level": 1}
                return {"credential_configuration_id": path.rsplit("/", 1)[-1]}

            def request(self, method, path, payload=None, **kwargs):
                self.calls.append((method, path, payload, kwargs))
                return b"", "application/json"

        session = Session()
        config = {
            "target_origin": "https://issuer.example",
            "issuer": {
                "dedicated_conformance_subject": True,
                "subject_id": "00000000-0000-0000-0000-000000000123",
                "credential_datasets": {"pid/1": {"given_name": "Ada"}},
            },
        }
        with (
            patch.dict(
                module.os.environ,
                {"OIDF_ADMIN_EMAIL": "admin@example.test", "OIDF_ADMIN_PASSWORD": "secret"},
                clear=True,
            ),
            patch.object(module.ControlPlaneSession, "login", return_value=session) as login,
        ):
            admin, installed = module.install_credential_datasets(config)
            module.cleanup_credential_datasets(admin, installed)

        login.assert_called_once_with(
            "https://issuer.example", "admin@example.test", "secret"
        )
        put = next(call for call in session.json_calls if call[0] == "PUT")
        self.assertEqual(
            put[1],
            "/admin/openid4vci/credential-datasets/00000000-0000-0000-0000-000000000123/pid%2F1",
        )
        self.assertEqual(put[2], {"claims": {"given_name": "Ada"}})
        self.assertTrue(put[3]["csrf"])
        self.assertEqual(session.calls[0][0], "DELETE")
        self.assertEqual(session.calls[0][1], put[1])
        self.assertTrue(session.calls[0][3]["csrf"])

    def test_dataset_fixture_rejects_non_dedicated_subject_before_login(self):
        module = load("run_openid4vc_conformance.py")
        with (
            patch.object(module.ControlPlaneSession, "login") as login,
            self.assertRaisesRegex(RuntimeError, "dedicated conformance subject"),
        ):
            module.install_credential_datasets(
                {
                    "target_origin": "https://issuer.example",
                    "issuer": {
                        "subject_id": "00000000-0000-0000-0000-000000000123",
                        "credential_datasets": {"pid": {"given_name": "Ada"}},
                    },
                }
            )
        login.assert_not_called()

    def test_openid4vc_driver_requires_authenticated_public_suite_api(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://www.certification.openid.net",
                "aliases": [],
            },
            module.threading.Event(),
        )
        with (
            patch.dict(module.os.environ, {}, clear=True),
            self.assertRaisesRegex(RuntimeError, "API token is required"),
        ):
            driver.drive_once()

    def test_module_entries_merge_runner_exposed_values_with_info_metadata(self):
        module = load("run_openid4vc_conformance.py")
        with (
            patch.object(
                module.oidf,
                "fetch_alias_plans",
                return_value=[
                    {
                        "planName": "oid4vci-1_0-issuer-test-plan",
                        "modules": [{"instances": ["module-id"]}],
                    }
                ],
            ),
            patch.object(
                module.oidf,
                "oidf_api_request",
                side_effect=[
                    (
                        200,
                        {
                            "_id": "module-id",
                            "alias": "issuer-alias",
                            "variant": {
                                "vci_authorization_code_flow_variant": "issuer_initiated"
                            },
                            "status": "WAITING",
                        },
                    ),
                    (
                        200,
                        {
                            "id": "module-id",
                            "exposed": {
                                "credential_offer_endpoint": "https://suite.example/credential_offer"
                            },
                        },
                    ),
                ],
            ) as request,
        ):
            entries = module.module_entries("https://suite.example", None, {"issuer-alias"})

        self.assertEqual(entries[0]["alias"], "issuer-alias")
        self.assertEqual(
            entries[0]["exposed"]["credential_offer_endpoint"],
            "https://suite.example/credential_offer",
        )
        self.assertEqual(
            [call.args[2] for call in request.call_args_list],
            ["api/info/module-id", "api/runner/module-id"],
        )

    def test_module_entries_do_not_fetch_runner_for_non_waiting_modules(self):
        module = load("run_openid4vc_conformance.py")
        with (
            patch.object(
                module.oidf,
                "fetch_alias_plans",
                return_value=[
                    {
                        "planName": "oid4vci-1_0-issuer-test-plan",
                        "modules": [{"instances": ["finished-module"]}],
                    }
                ],
            ),
            patch.object(
                module.oidf,
                "oidf_api_request",
                return_value=(
                    200,
                    {
                        "_id": "finished-module",
                        "alias": "issuer-alias",
                        "status": "FINISHED",
                    },
                ),
            ) as request,
        ):
            entries = module.module_entries("https://suite.example", None, {"issuer-alias"})

        self.assertEqual(entries[0]["_driver_module_id"], "finished-module")
        self.assertEqual(
            [call.args[2] for call in request.call_args_list],
            ["api/info/finished-module"],
        )

    def test_driver_caches_terminal_modules_between_scans(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "test-token",
                "aliases": ["issuer-alias"],
            },
            module.threading.Event(),
        )
        with patch.object(
            module,
            "module_entries",
            return_value=[
                {
                    "_driver_module_id": "finished-module",
                    "_driver_plan": "oid4vci-1_0-issuer-test-plan",
                    "status": "FINISHED",
                }
            ],
        ) as entries:
            driver.drive_once()
            driver.drive_once()

        self.assertEqual(driver.terminal_modules, {"finished-module"})
        self.assertEqual(entries.call_args_list[1].kwargs["ignored_module_ids"], {"finished-module"})

    def test_driver_loop_scans_before_first_sleep(self):
        module = load("run_openid4vc_conformance.py")
        stop = module.threading.Event()
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "test-token",
                "aliases": [],
                "poll_interval_seconds": 60,
            },
            stop,
        )
        calls = 0

        def drive_once() -> None:
            nonlocal calls
            calls += 1
            stop.set()

        with patch.object(driver, "drive_once", side_effect=drive_once):
            driver.run()

        self.assertEqual(calls, 1)

    def test_issuer_driver_delivers_one_offer_for_preauthorized_module(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "test-token",
                "target_origin": "https://issuer.example",
                "aliases": ["issuer-alias"],
                "issuer": {
                    "credential_configuration_ids": {"sd_jwt_vc": "pid"},
                    "management_token": "management-token",
                    "subject_id": "00000000-0000-0000-0000-000000000123",
                    "tx_code": "123456",
                },
            },
            module.threading.Event(),
        )
        with (
            patch.object(
                module,
                "request_json",
                return_value={"credential_offer_uri": "https://issuer.example/offers/one"},
            ) as create_offer,
            patch.object(module, "get_url") as deliver_offer,
        ):
            driver.drive_issuer(
                "module-id",
                {
                    "testName": "oid4vci-1_0-issuer-happy-flow",
                    "exposed": {
                        "credential_offer_endpoint": (
                            "https://suite.example/test/a/issuer/credential_offer"
                        )
                    },
                },
                {
                    "credential_format": "sd_jwt_vc",
                    "vci_grant_type": "pre_authorization_code",
                },
            )

        self.assertEqual(create_offer.call_count, 1)
        self.assertEqual(
            [call.args[0] for call in deliver_offer.call_args_list],
            [
                (
                    "https://suite.example/test/a/issuer/credential_offer?"
                    "credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fone"
                )
            ],
        )
        self.assertEqual(driver.triggered, {"module-id"})

    def test_issuer_driver_does_not_repeat_single_client_offer(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "test-token",
                "target_origin": "https://issuer.example",
                "aliases": ["issuer-alias"],
                "issuer": {
                    "credential_configuration_ids": {"sd_jwt_vc": "pid"},
                    "management_token": "management-token",
                    "subject_id": "00000000-0000-0000-0000-000000000123",
                },
            },
            module.threading.Event(),
        )
        with (
            patch.object(
                module,
                "request_json",
                return_value={"credential_offer_uri": "https://issuer.example/offers/one"},
            ) as create_offer,
            patch.object(module, "get_url"),
        ):
            driver.drive_issuer(
                "module-id",
                {
                    "testName": "oid4vci-1_0-issuer-happy-flow",
                    "exposed": {
                        "credential_offer_endpoint": (
                            "https://suite.example/test/a/issuer/credential_offer"
                        )
                    },
                },
                {"credential_format": "sd_jwt_vc"},
            )

        self.assertEqual(create_offer.call_count, 1)
        self.assertIn("module-id", driver.triggered)

    def test_wrapper_rejects_tokenless_or_insecure_suite_modes(self):
        module = load("run_openid4vc_conformance.py")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as config:
            json.dump({"aliases": []}, config)
            config_path = config.name
        try:
            for forbidden in ("--disable-ssl-verify", "--no-api-token"):
                with (
                    patch(
                        "sys.argv",
                        [
                            "run_openid4vc_conformance.py",
                            "--driver-config-json-file",
                            config_path,
                            "--",
                            forbidden,
                        ],
                    ),
                    self.assertRaisesRegex(SystemExit, "require API authentication"),
                ):
                    module.main()
        finally:
            Path(config_path).unlink(missing_ok=True)

    def test_grouped_openid4vc_runner_filters_expected_records_per_batch(self):
        module = load("run_openid4vc_conformance.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "configs.json"
            plans = root / "plans.json"
            warnings = root / "warnings.json"
            skips = root / "skips.json"
            export = root / "results"
            config.write_text(
                json.dumps({"configs": {"a.json": {"alias": "a"}, "b.json": {"alias": "b"}, "c.json": {"alias": "c"}}}),
                encoding="utf-8",
            )
            plans.write_text(
                json.dumps([
                    "plan-one a.json",
                    "plan-two b.json",
                    "plan-three c.json",
                ]),
                encoding="utf-8",
            )
            warnings.write_text(
                json.dumps([
                    {"configuration-filename": "a.json", "test-name": "warning-a"},
                    {"configuration-filename": "c.json", "test-name": "warning-c"},
                ]),
                encoding="utf-8",
            )
            skips.write_text(
                json.dumps([
                    {"configuration-filename": "b.json", "test-name": "skip-b"},
                    {"configuration-filename": "c.json", "test-name": "skip-c"},
                ]),
                encoding="utf-8",
            )

            invocations = module.grouped_runner_args(
                [
                    "--suite-dir", "suite",
                    "--conformance-server", "https://suite.example",
                    "--config-json-file", str(config),
                    "--plan-set-json-file", str(plans),
                    "--expected-failures-file", str(warnings),
                    "--expected-skips-file", str(skips),
                    "--export-dir", str(export),
                ],
                2,
                root / "groups",
            )

            self.assertEqual(len(invocations), 2)
            first_plan_set = Path(invocations[0][invocations[0].index("--plan-set-json-file") + 1])
            second_plan_set = Path(invocations[1][invocations[1].index("--plan-set-json-file") + 1])
            self.assertEqual(json.loads(first_plan_set.read_text(encoding="utf-8")), ["plan-one a.json", "plan-two b.json"])
            self.assertEqual(json.loads(second_plan_set.read_text(encoding="utf-8")), ["plan-three c.json"])

            first_warnings = Path(invocations[0][invocations[0].index("--expected-failures-file") + 1])
            first_skips = Path(invocations[0][invocations[0].index("--expected-skips-file") + 1])
            second_warnings = Path(invocations[1][invocations[1].index("--expected-failures-file") + 1])
            second_skips = Path(invocations[1][invocations[1].index("--expected-skips-file") + 1])
            self.assertEqual(
                [item["test-name"] for item in json.loads(first_warnings.read_text(encoding="utf-8"))],
                ["warning-a"],
            )
            self.assertEqual(
                [item["test-name"] for item in json.loads(first_skips.read_text(encoding="utf-8"))],
                ["skip-b"],
            )
            self.assertEqual(
                [item["test-name"] for item in json.loads(second_warnings.read_text(encoding="utf-8"))],
                ["warning-c"],
            )
            self.assertEqual(
                [item["test-name"] for item in json.loads(second_skips.read_text(encoding="utf-8"))],
                ["skip-c"],
            )
            self.assertIn(str(export / "group-01"), invocations[0])
            self.assertIn(str(export / "group-02"), invocations[1])

    def test_openid4vc_runner_rejects_stale_or_cross_run_material(self):
        runner = load("run_openid4vc_conformance.py")
        materializer = load("materialize_openid4vc_oidf_config.py")
        cases = materializer.matrix_cases()
        names = [f"openid4vc-{slug}.json" for _, slug, _ in cases]
        aliases = [f"alias-{index}" for index in range(len(cases))]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = root / "configs.json"
            plans = root / "plans.json"
            warnings = root / "warnings.json"
            skips = root / "skips.json"
            configs.write_text(
                json.dumps(
                    {
                        "configs": {
                            name: {
                                "alias": alias,
                                **(
                                    {"vci": {"static_tx_code": "123456"}}
                                    if variants.get("vci_grant_type")
                                    == "pre_authorization_code"
                                    else {}
                                ),
                            }
                            for (_, _, variants), name, alias in reversed(
                                list(zip(cases, names, aliases, strict=True))
                            )
                        }
                    }
                ),
                encoding="utf-8",
            )
            plans.write_text(
                json.dumps(
                    [
                        materializer.plan_expression(plan, variants, name)
                        for (plan, _, variants), name in zip(cases, names, strict=True)
                    ]
                ),
                encoding="utf-8",
            )
            warnings.write_text(
                json.dumps(materializer.expected_problems_for_cases(cases)),
                encoding="utf-8",
            )
            skips.write_text(
                json.dumps(materializer.expected_skips_for_cases(cases)),
                encoding="utf-8",
            )
            arguments = [
                "--config-json-file",
                str(configs),
                "--plan-set-json-file",
                str(plans),
                "--expected-failures-file",
                str(warnings),
                "--expected-skips-file",
                str(skips),
            ]

            runner.validate_materialized_matrix(
                {
                    "aliases": list(reversed(aliases)),
                    "issuer": {"tx_code": "123456"},
                },
                arguments,
            )

            warnings.write_text("[]", encoding="utf-8")
            runner.validate_materialized_matrix(
                {
                    "aliases": list(reversed(aliases)),
                    "issuer": {"tx_code": "123456"},
                },
                arguments,
                require_no_expected_problems=True,
            )
            stale_warning = [
                {
                    "configuration-filename": names[0],
                    "condition": "stale-condition",
                }
            ]
            warnings.write_text(json.dumps(stale_warning), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "expected problems"):
                runner.validate_materialized_matrix(
                    {
                        "aliases": list(reversed(aliases)),
                        "issuer": {"tx_code": "123456"},
                    },
                    arguments,
                )
            with self.assertRaisesRegex(SystemExit, "strict diagnostic"):
                runner.validate_materialized_matrix(
                    {
                        "aliases": list(reversed(aliases)),
                        "issuer": {"tx_code": "123456"},
                    },
                    arguments,
                    require_no_expected_problems=True,
                )

            with self.assertRaisesRegex(SystemExit, "driver aliases"):
                runner.validate_materialized_matrix(
                    {
                        "aliases": [*aliases[:-1], "alias-from-another-run"],
                        "issuer": {"tx_code": "123456"},
                    },
                    arguments,
                )

            mismatched_configs = json.loads(configs.read_text(encoding="utf-8"))
            pre_authorized_name = next(
                name
                for (_, _, variants), name in zip(cases, names, strict=True)
                if variants.get("vci_grant_type") == "pre_authorization_code"
            )
            mismatched_configs["configs"][pre_authorized_name]["vci"][
                "static_tx_code"
            ] = "654321"
            configs.write_text(json.dumps(mismatched_configs), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "transaction codes"):
                runner.validate_materialized_matrix(
                    {"aliases": aliases, "issuer": {"tx_code": "123456"}},
                    arguments,
                )
            mismatched_configs["configs"][pre_authorized_name]["vci"][
                "static_tx_code"
            ] = "123456"
            configs.write_text(json.dumps(mismatched_configs), encoding="utf-8")

            stale_warnings = materializer.expected_problems_for_cases(cases)
            stale_warnings.append(
                {
                    "configuration-filename": names[0],
                    "condition": "stale-condition",
                }
            )
            warnings.write_text(json.dumps(stale_warnings), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "expected problems"):
                runner.validate_materialized_matrix(
                    {"aliases": aliases, "issuer": {"tx_code": "123456"}},
                    arguments,
                )

    def test_openid4vc_wrapper_terminates_the_runner_process_group_on_interruption(self):
        module = load("run_openid4vc_conformance.py")

        class Process:
            pid = 1234

            def __init__(self):
                self.waits = 0

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.waits += 1
                if self.waits == 1:
                    raise KeyboardInterrupt
                return 0

        process = Process()
        with (
            patch.object(module.subprocess, "Popen", return_value=process),
            patch.object(module.os, "killpg", create=True) as killpg,
            self.assertRaises(KeyboardInterrupt),
        ):
            module.run_runner_invocations([["--suite-dir", "suite"]])

        killpg.assert_called_once_with(process.pid, module.signal.SIGTERM)
        self.assertEqual(process.waits, 2)

    def test_official_openid4vc_workflow_uses_bounded_groups(self):
        workflow = (ROOT / ".github" / "workflows" / "openid4vc-conformance.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("--plan-group-size 4", workflow)
        self.assertIn(
            "path: runtime/openid4vc/results/evidence-manifest.json",
            workflow,
        )
        self.assertNotIn("path: runtime/openid4vc/results\n", workflow)

    def test_driver_callback_get_uses_oidf_ssl_context(self):
        module = load("run_openid4vc_conformance.py")
        context = object()
        module.oidf.OIDF_API_SSL_CONTEXT = context

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return b""

        try:
            class Opener:
                def open(self, *_args, **_kwargs):
                    return Response()

            with patch.object(
                module.urllib.request, "build_opener", return_value=Opener()
            ) as build_opener:
                module.get_url("https://suite.example/test/a/alias/callback")

            https_handler = build_opener.call_args.args[0]
            self.assertIs(https_handler._context, context)
        finally:
            module.oidf.OIDF_API_SSL_CONTEXT = None

    def test_wallet_redirect_handler_accepts_only_the_exact_completion_url(self):
        module = load("run_openid4vc_conformance.py")
        expected = (
            "https://issuer.example/openid4vp/complete/"
            "018f0000-0000-7000-8000-000000000001"
        )
        handler = module.ExactRedirectHandler(expected)
        request = module.urllib.request.Request("https://wallet.example/authorize")

        redirected = handler.redirect_request(
            request,
            None,
            303,
            "See Other",
            {},
            expected,
        )
        self.assertEqual(redirected.full_url, expected)
        for code, location in (
            (307, expected),
            (
                303,
                "https://issuer.example/openid4vp/complete/"
                "018f0000-0000-7000-8000-000000000002",
            ),
            (
                303,
                "https://other.example/openid4vp/complete/"
                "018f0000-0000-7000-8000-000000000001",
            ),
        ):
            with self.subTest(code=code, location=location), self.assertRaises(RuntimeError):
                handler.redirect_request(request, None, code, "redirect", {}, location)

    def test_suite_callbacks_are_exact_public_origin_and_never_rewritten(self):
        module = load("run_openid4vc_conformance.py")

        self.assertEqual(
            module.suite_callback_url(
                "https://suite.example",
                "https://suite.example/test/a/issuer/credential_offer",
            ),
            "https://suite.example/test/a/issuer/credential_offer",
        )
        for callback in [
            "https://other.example/test/a/issuer/credential_offer",
            "https://nginx:8443/test/a/issuer/credential_offer",
            "https://suite.example/private/callback",
            "https://suite.example/test/a/issuer/credential_offer?unexpected=1",
        ]:
            with self.assertRaises(RuntimeError):
                module.suite_callback_url("https://suite.example", callback)

    def test_credential_issuer_metadata_is_registered_inside_the_single_well_known_scope(self):
        routes = (ROOT / "crates" / "authorization-server" / "src" / "bootstrap" / "routes.rs").read_text(
            encoding="utf-8"
        )

        self.assertEqual(routes.count('web::scope("/.well-known")'), 1)
        self.assertIn('"/openid-credential-issuer"', routes)
        self.assertNotIn('"/.well-known/openid-credential-issuer"', routes)

    def test_matrix_is_bounded_and_covers_each_final_role_format(self):
        module = load("materialize_openid4vc_oidf_config.py")
        cases = module.matrix_cases()
        self.assertEqual(len(cases), 17)
        self.assertEqual({plan for plan, _, _ in cases}, {
            module.VCI_STANDARD, module.VCI_HAIP, module.VP_STANDARD, module.VP_HAIP
        })
        for plan in (module.VCI_STANDARD, module.VCI_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "mdoc"})
        for plan in (module.VP_STANDARD, module.VP_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "iso_mdl"})
        self.assertFalse(any("wallet" in plan for plan, _, _ in cases))

    def test_registry_is_alpha_evidence_not_certification_claim(self):
        registry = json.loads((ROOT / "tests" / "contracts" / "openid4vc-oidf-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(registry["status"], "alpha-regression-not-certification")
        self.assertEqual(registry["roles"], ["issuer", "verifier"])

    def test_openid4vc_target_boundary_allows_external_attester_role(self):
        module = load("run_oidf_conformance.py")

        module.assert_config_target_boundaries(
            {
                "vci": {"credential_issuer_url": "https://issuer.example"},
                "client_attestation": {
                    "issuer": "https://client-attester.example.org"
                },
            },
            "openid4vc-vci-haip-sd-wallet.json",
            "https://issuer.example",
        )
        module.assert_config_target_boundaries(
            {
                "client": {
                    "client_id": "issuer.example",
                    "request_object_trust_anchor_uri": "https://trust-anchor.example.org/root.pem",
                }
            },
            "openid4vc-vp-haip-sd.json",
            "https://issuer.example",
        )

    def test_openid4vc_target_boundary_rejects_local_targets(self):
        module = load("run_oidf_conformance.py")

        with self.assertRaisesRegex(SystemExit, "non-public URL"):
            module.assert_config_target_boundaries(
                {
                    "vci": {
                        "credential_issuer_url": "https://issuer.example",
                        "credential_offer_endpoint": "https://internal-service:8443/test/a/issuer/offer",
                    }
                },
                "openid4vc-vci-sd-wallet-plain.json",
                "https://issuer.example",
            )

    def test_openid4vc_target_boundary_requires_role_target_binding(self):
        module = load("run_oidf_conformance.py")

        with self.assertRaisesRegex(SystemExit, "credential_issuer_url"):
            module.assert_config_target_boundaries(
                {"vci": {"credential_issuer_url": "https://wrong.example"}},
                "openid4vc-vci-sd-wallet-plain.json",
                "https://issuer.example",
            )
        with self.assertRaisesRegex(SystemExit, "verifier client_id"):
            module.assert_config_target_boundaries(
                {"client": {"client_id": "wrong.example"}},
                "openid4vc-vp-haip-sd.json",
                "https://issuer.example",
            )

    def test_openid4vc_plan_config_writer_does_not_require_oidc_discovery_url(self):
        module = load("run_oidf_conformance.py")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            config_json = root / "configs.json"
            config_json.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-vci-sd-wallet-plain.json": {
                                "alias": "openid4vc-vci-sd-wallet-plain",
                                "vci": {"credential_issuer_url": "https://issuer.example"},
                                "client_attestation": {
                                    "issuer": "https://client-attester.example.org",
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            written, aliases = module.write_plan_configs(
                suite_scripts,
                "ignored.json",
                "OPENID4VC_CONFIGS",
                str(config_json),
                "https://issuer.example",
            )

        self.assertEqual(written, {"openid4vc-vci-sd-wallet-plain.json"})
        self.assertEqual(
            aliases,
            {
                "openid4vc-vci-sd-wallet-plain.json": "openid4vc-vci-sd-wallet-plain"
            },
        )

    def test_openid4vc_issuer_user_reject_module_denies_consent(self):
        module = load("run_oidf_conformance.py")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            config_json = root / "configs.json"
            config_json.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-vci-haip-sd-wallet.json": {
                                "alias": "openid4vc-vci-haip-sd-wallet",
                                "vci": {"credential_issuer_url": "https://issuer.example"},
                                "nazo": {
                                    "oidf_user_email": "user@example.test",
                                    "oidf_user_password": "correct horse battery staple",
                                },
                                "browser": [
                                    {
                                        "match": "https://issuer.example/authorize*",
                                        "tasks": [
                                            {
                                                "task": "Complete login page",
                                                "match": "https://issuer.example/ui/auth*",
                                                "commands": [],
                                            },
                                            {
                                                "task": "Complete consent page",
                                                "match": "https://issuer.example/ui/consent*",
                                                "commands": [],
                                            },
                                        ],
                                    }
                                ],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            module.write_plan_configs(
                suite_scripts,
                "ignored.json",
                "OPENID4VC_CONFIGS",
                str(config_json),
                "https://issuer.example",
            )
            written = json.loads(
                (suite_scripts / "openid4vc-vci-haip-sd-wallet.json").read_text(
                    encoding="utf-8"
                )
            )

        user_reject_override = written["override"][
            "fapi2-security-profile-final-user-rejects-authentication"
        ]["browser"][0]
        deny_task = user_reject_override["tasks"][1]
        self.assertEqual(deny_task["task"], "Deny consent page")
        self.assertIn(["click", "id", "nazo-consent-deny"], deny_task["commands"])

    def test_verifier_driver_emits_format_specific_dcql_meta(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://issuer.example",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        cases = {
            "sd_jwt_vc": ("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}),
            "iso_mdl": ("mso_mdoc", {"doctype_value": "org.iso.18013.5.1.mDL"}),
        }
        for credential_format, (expected_format, expected_meta) in cases.items():
            transaction_id = "018f0000-0000-7000-8000-000000000001"
            with self.subTest(credential_format=credential_format), patch.object(
                module,
                "request_json",
                return_value={
                    "authorization_url": "https://localhost:8443/authorize",
                    "transaction_id": transaction_id,
                },
            ) as request, patch.object(module, "get_url") as get_url:
                driver.drive_verifier(
                    "module-id",
                    {"alias": "vp-alias", "testName": "oid4vp-1final-verifier-happy-flow"},
                    {
                        "credential_format": credential_format,
                        "client_id_prefix": "x509_san_dns",
                        "request_method": "request_uri_signed",
                        "response_mode": "direct_post.jwt",
                    },
                    False,
                )
                payload = request.call_args.args[3]
                credential = payload["dcql_query"]["credentials"][0]
                self.assertEqual(credential["format"], expected_format)
                self.assertEqual(credential["meta"], expected_meta)
                self.assertEqual(payload["request_method"], "request_uri_signed_get")
                get_url.assert_called_once_with(
                    "https://localhost:8443/authorize",
                    expected_redirect_url=(
                        "https://issuer.example/openid4vp/complete/" + transaction_id
                    ),
                )

    def test_verifier_driver_uses_post_only_for_the_post_request_uri_module(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://issuer.example",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        with patch.object(
            module,
            "request_json",
            return_value={
                "authorization_url": "https://localhost:8443/authorize",
                "transaction_id": "018f0000-0000-7000-8000-000000000001",
            },
        ) as request, patch.object(module, "get_url"):
            driver.drive_verifier(
                "module-id",
                {
                    "alias": "vp-alias",
                    "testName": "oid4vp-1final-verifier-request-uri-method-post",
                },
                {
                    "credential_format": "sd_jwt_vc",
                    "request_method": "request_uri_signed",
                },
                False,
            )

        self.assertEqual(request.call_args.args[3]["request_method"], "request_uri_signed_post")

    def test_materializer_creates_unique_aliases_and_exact_plan_count(self):
        module = load("materialize_openid4vc_oidf_config.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            mtls = root / "mtls.json"
            driver = root / "driver.json"
            output = root / "output"
            base.write_text(json.dumps({
                name: {
                    "alias": f"nazo-{name}",
                    **(
                        {
                            "vci": {},
                            "client": {
                                "client_id": "upstream-placeholder",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "EC",
                                            "crv": "P-256",
                                            "kid": "client-key",
                                            "x": "x",
                                            "y": "y",
                                            "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
                                        }
                                    ]
                                },
                            },
                            "client2": {
                                "client_id": "upstream-second-client",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "RSA",
                                            "alg": "PS256",
                                            "n": "modulus",
                                            "e": "AQAB",
                                            "d": "private",
                                        }
                                    ]
                                },
                            },
                        }
                        if name.startswith("vci")
                        else {"client": {"client_id": "{HOSTNAME}"}}
                    ),
                }
                for name in ("vci", "vci_haip", "vp", "vp_haip")
            }), encoding="utf-8")
            mtls.write_text(
                json.dumps(
                    {
                        "ca": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
                        "mtls": {
                            "cert": "-----BEGIN CERTIFICATE-----\none\n-----END CERTIFICATE-----\n",
                            "key": "-----BEGIN PRIVATE KEY-----\none\n-----END PRIVATE KEY-----\n",
                        },
                        "mtls2": {
                            "cert": "-----BEGIN CERTIFICATE-----\ntwo\n-----END CERTIFICATE-----\n",
                            "key": "-----BEGIN PRIVATE KEY-----\ntwo\n-----END PRIVATE KEY-----\n",
                        },
                    }
                ),
                encoding="utf-8",
            )
            driver.write_text(json.dumps({
                "issuer": {
                    "dedicated_conformance_subject": True,
                    "credential_configuration_ids": {
                        "sd_jwt_vc": "pid-sd-jwt",
                        "mdoc": "org.iso.18013.5.1.mDL",
                    },
                    "tx_code": "123456",
                },
                "verifier": {
                    "request_object_trust_anchor_pem": (
                        "-----BEGIN CERTIFICATE-----\n"
                        "test-root\n"
                        "-----END CERTIFICATE-----\n"
                    ),
                    "credential_type_values": {
                        "sd_jwt_vc": "eu.europa.ec.eudi.pid.1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    }
                },
            }), encoding="utf-8")
            with patch("sys.argv", [
                "materialize_openid4vc_oidf_config.py",
                "--base-config-json-file", str(base),
                "--mtls-config-json-file", str(mtls),
                "--driver-config-json-file", str(driver),
                "--credential-datasets-json-file",
                str(
                    Path(__file__).resolve().parents[2]
                    / "tests"
                    / "contracts"
                    / "openid4vc-conformance-datasets.json"
                ),
                "--conformance-server", "https://suite.example",
                "--target-origin", "https://issuer.example",
                "--onboarding-profile", "official",
                "--output-dir", str(output),
            ]):
                self.assertEqual(module.main(), 0)
            plans = json.loads((output / "openid4vc-plan-set.json").read_text(encoding="utf-8"))
            materialized_driver = json.loads((output / "openid4vc-driver.json").read_text(encoding="utf-8"))
            configs = json.loads((output / "openid4vc-plan-configs.json").read_text(encoding="utf-8"))["configs"]
            expected_skips = json.loads((output / "openid4vc-expected-skips.json").read_text(encoding="utf-8"))
            expected_problems = json.loads((output / "openid4vc-expected-problems.json").read_text(encoding="utf-8"))
            self.assertEqual(len(plans), 17)
            self.assertEqual(len(configs), 17)
            self.assertEqual(len(set(materialized_driver["aliases"])), 17)
            self.assertEqual(len(expected_skips), 3)
            self.assertEqual(
                [
                    item for item in expected_skips
                    if item["test-name"] == module.VCI_UNSUPPORTED_ENCRYPTION_MODULE
                ],
                [
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-wallet-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-mdoc-issuer-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-preauth.json",
                    },
                ],
            )
            preauthorized_plans = [
                plan
                for plan in plans
                if "vci_grant_type=pre_authorization_code" in plan
            ]
            self.assertEqual(len(preauthorized_plans), 2)
            self.assertTrue(
                all(
                    module.VCI_MULTIPLE_CLIENTS_MODULE not in plan
                    and all(
                        applicable in plan
                        for applicable in module.VCI_PREAUTHORIZED_APPLICABLE_MODULES
                    )
                    for plan in preauthorized_plans
                )
            )
            self.assertEqual(expected_problems, [])
            for config in configs.values():
                if "vci-" not in config["alias"]:
                    continue
                material = json.loads(mtls.read_text(encoding="utf-8"))
                self.assertEqual(config["mtls"]["ca"], material["ca"])
                self.assertEqual(
                    config["mtls2"]["cert"], material["mtls2"]["cert"]
                )
            self.assertEqual(materialized_driver["target_origin"], "https://issuer.example")
            self.assertEqual(
                materialized_driver["verifier"]["credential_type_values"]["sd_jwt_vc"],
                "urn:eudi:pid:1",
            )
            for filename, config in configs.items():
                if "vp-" in filename:
                    self.assertEqual(config["client"]["client_id"], "issuer.example")
                    if "redirect-query" in filename:
                        self.assertNotIn("request_object_trust_anchor_pem", config["client"])
                    else:
                        self.assertEqual(
                            config["client"]["request_object_trust_anchor_pem"],
                            "-----BEGIN CERTIFICATE-----\n"
                            "test-root\n"
                            "-----END CERTIFICATE-----\n",
                        )
            for filename, config in configs.items():
                if "vci-" not in filename:
                    continue
                self.assertEqual(config["vci"]["credential_issuer_url"], "https://issuer.example")
                expected = "org.iso.18013.5.1.mDL" if "mdoc" in filename else "pid-sd-jwt"
                self.assertEqual(config["vci"]["credential_configuration_id"], expected)
                if "preauth" in filename:
                    self.assertEqual(config["vci"]["static_tx_code"], "123456")
                elif "vci" in config:
                    self.assertNotIn("static_tx_code", config["vci"])
                if "vci-haip-" in filename:
                    self.assertIn("offline_access", config["client"]["scope"].split())
                    self.assertIn("offline_access", config["client2"]["scope"].split())
                client2_keys = config["client2"]["jwks"]["keys"]
                self.assertEqual(
                    {(key["kty"], key["crv"], key["alg"]) for key in client2_keys},
                    {("EC", "P-256", "ES256")},
                )
                self.assertEqual(client2_keys[0]["kid"], "client-key-client2")
                self.assertNotEqual(
                    client2_keys[0]["d"],
                    config["client"]["jwks"]["keys"][0]["d"],
                )
                self.assertNotEqual(client2_keys[0]["x"], "x")
                self.assertNotEqual(client2_keys[0]["y"], "y")
            private_key_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            official_ids = module.vci_client_ids("official", None)
            self.assertEqual(private_key_clients, {official_ids["private_key"]})
            self.assertEqual(attested_clients, {official_ids["attested"]})
            self.assertTrue(private_key_clients.isdisjoint(attested_clients))
            private_key_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            self.assertEqual(private_key_client2, {official_ids["private_key2"]})
            self.assertEqual(attested_client2, {official_ids["attested2"]})
            self.assertTrue(private_key_client2.isdisjoint(attested_client2))
            self.assertEqual(
                json.loads((output / "oidf-onboarding-contract.json").read_text(encoding="utf-8")),
                {
                    "schema": 2,
                    "onboarding_profile": "official",
                    "suite_base_url": "https://suite.example",
                    "target_issuer": "https://issuer.example",
                },
            )

    def test_operator_openid4vc_client_ids_are_namespaced(self):
        module = load("materialize_openid4vc_oidf_config.py")
        ids = module.vci_client_ids("operator-black-box", "bb-example")

        self.assertTrue(all(value.startswith("oidf-bb-example-") for value in ids.values()))
        with self.assertRaisesRegex(SystemExit, "valid client namespace"):
            module.vci_client_ids("operator-black-box", "official")

    def test_operator_subject_id_is_explicitly_bound_to_current_user(self):
        module = load("materialize_openid4vc_oidf_config.py")
        issuer = {"subject_id": "00000000-0000-0000-0000-000000000001"}

        module.bind_subject_id(
            issuer,
            "operator-black-box",
            "00000000-0000-0000-0000-000000000123",
        )

        self.assertEqual(
            issuer["subject_id"],
            "00000000-0000-0000-0000-000000000123",
        )
        with self.assertRaisesRegex(SystemExit, "requires --subject-id"):
            module.bind_subject_id({}, "operator-black-box", None)
        with self.assertRaisesRegex(SystemExit, "must be a UUID"):
            module.bind_subject_id({}, "operator-black-box", "not-a-uuid")

    def test_openid4vc_suite_plan_configs_are_bounded_and_cleaned(self):
        module = load("run_openid4vc_conformance.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            scripts = suite / "scripts"
            scripts.mkdir(parents=True)
            configs = root / "configs.json"
            configs.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-vci.json": {},
                            "openid4vc-vp.json": {},
                        }
                    }
                ),
                encoding="utf-8",
            )

            paths = module.suite_plan_config_paths(
                [
                    "--suite-dir",
                    str(suite),
                    "--config-json-file",
                    str(configs),
                ]
            )
            self.assertEqual(
                [path.name for path in paths],
                ["openid4vc-vci.json", "openid4vc-vp.json"],
            )
            for path in paths:
                path.write_text("{}", encoding="utf-8")
            module.cleanup_suite_plan_configs(paths)
            self.assertTrue(all(not path.exists() for path in paths))

            configs.write_text(
                json.dumps({"configs": {"../outside.json": {}}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "invalid OpenID4VC"):
                module.suite_plan_config_paths(
                    [
                        "--suite-dir",
                        str(suite),
                        "--config-json-file",
                        str(configs),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
