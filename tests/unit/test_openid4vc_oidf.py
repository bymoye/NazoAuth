import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Openid4vcOidfTests(unittest.TestCase):
    def test_admin_credentials_have_only_a_private_file_contract(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "run_openid4vc_conformance.py"
        ).read_text(encoding="utf-8")
        self.assertIn("--operator-credentials-file", source)
        required_fields = re.search(
            r"required_fields\s*=\s*\((?P<body>.*?)\)", source, flags=re.DOTALL
        )
        self.assertIsNotNone(required_fields)
        assert required_fields is not None
        for field in ("admin_email", "admin_password", "admin_mfa_totp_secret"):
            self.assertIn(f'"{field}"', required_fields.group("body"))
        self.assertIn("read_secret_document", source)
        self.assertNotIn("OIDF_ADMIN_EMAIL", source)
        self.assertNotIn("OIDF_ADMIN_PASSWORD", source)

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
        credentials = {
            "admin_email": "admin@example.test",
            "admin_password": "secret",
            "admin_mfa_totp_secret": "123456",
        }
        with patch.object(module.ControlPlaneSession, "login", return_value=session) as login:
            admin, installed = module.install_credential_datasets(
                config,
                credentials,
            )
            module.cleanup_credential_datasets("https://issuer.example", credentials, installed)

        self.assertEqual(login.call_args_list, [
            call(
                "https://issuer.example",
                "admin@example.test",
                "secret",
                mfa_totp_secret="123456",
            ),
            call(
                "https://issuer.example",
                "admin@example.test",
                "secret",
                mfa_totp_secret="123456",
            ),
        ])
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
                },
                {"admin_email": "admin@example.test", "admin_password": "secret"},
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
                            "browser": {
                                "urls": [
                                    "https://issuer.example/authorize?request_uri=urn%3Aexample"
                                ]
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
            entries[0]["browser"]["urls"],
            ["https://issuer.example/authorize?request_uri=urn%3Aexample"],
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
        driver.completed_hosted_authorizations["finished-module"] = {
            "https://issuer.example/authorize?request_uri=old"
        }
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
        self.assertNotIn("finished-module", driver.completed_hosted_authorizations)
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

    def test_issuer_initiated_authorization_code_dispatches_offer_and_hosted_login(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "test-token",
                "aliases": ["issuer-alias"],
            },
            module.threading.Event(),
        )
        info = {
            "_driver_module_id": "module-id",
            "_driver_plan": "oid4vci-1_0-issuer-test-plan",
            "status": "WAITING",
            "variant": {
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_grant_type": "authorization_code",
            },
        }

        def deliver_offer(module_id, *_args):
            driver.triggered.add(module_id)

        with (
            patch.object(module, "module_entries", return_value=[info]) as entries,
            patch.object(driver, "drive_issuer", side_effect=deliver_offer) as drive_issuer,
            patch.object(driver, "drive_wallet_initiated_issuer") as drive_hosted,
        ):
            driver.drive_once()
            driver.drive_once()

        self.assertEqual(
            [call.kwargs["ignored_module_ids"] for call in entries.call_args_list],
            [set(), set()],
        )
        drive_issuer.assert_called_once()
        self.assertEqual(drive_hosted.call_count, 2)
        drive_hosted.assert_called_with("module-id", info)

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

    def test_wallet_initiated_issuer_completes_hosted_authorization(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "suite-token",
                "target_origin": "https://issuer.example",
                "hosted_authorization": {
                    "email": "user@example.test",
                    "password": "correct horse battery staple",
                },
            },
            module.threading.Event(),
        )
        session = Mock()
        session.opener = object()
        session.request_json.return_value = {"csrf_token": "csrf-secret"}
        with (
            patch.object(module.ControlPlaneSession, "login", return_value=session) as login,
            patch.object(module, "capture_control_plane_redirects") as capture_redirects,
            patch.object(module, "mark_suite_browser_url_visited") as mark_visited,
            patch.object(
                module,
                "redirect_location",
                side_effect=[
                    "https://issuer.example/ui/consent?request_id=request-1",
                    "https://suite.example/test/a/issuer/callback?code=one&state=two",
                ],
            ) as redirect,
            patch.object(module, "complete_suite_browser_callback") as complete_callback,
        ):
            driver.drive_wallet_initiated_issuer(
                "module-id",
                {
                    "browser": {
                        "urls": [
                            "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample"
                        ]
                    }
                },
            )

        login.assert_called_once_with(
            "https://issuer.example",
            "user@example.test",
            "correct horse battery staple",
        )
        capture_redirects.assert_called_once_with(session)
        mark_visited.assert_called_once_with(
            "https://suite.example",
            "suite-token",
            "module-id",
            "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample",
        )
        self.assertEqual(
            redirect.call_args_list[0].args[1].full_url,
            "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample",
        )
        session.request_json.assert_called_once_with(
            "GET",
            "/authorize/consent?request_id=request-1",
            expected_status=200,
            csrf=False,
        )
        decision = redirect.call_args_list[1].args[1]
        self.assertEqual(decision.full_url, "https://issuer.example/authorize/decision")
        self.assertEqual(
            module.urllib.parse.parse_qs(decision.data.decode("utf-8")),
            {
                "request_id": ["request-1"],
                "decision": ["approve"],
                "csrf_token": ["csrf-secret"],
            },
        )
        complete_callback.assert_called_once_with(
            "https://suite.example",
            "https://suite.example/test/a/issuer/callback?code=one&state=two",
        )
        self.assertEqual(driver.triggered, set())
        self.assertEqual(
            driver.completed_hosted_authorizations,
            {
                "module-id": {
                    "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample"
                }
            },
        )

    def test_hosted_authorization_preserves_login_cookie_jar_while_capturing_redirects(self):
        module = load("run_openid4vc_conformance.py")
        cookie_jar = module.http.cookiejar.CookieJar()
        session = Mock()
        session.opener = module.urllib.request.build_opener(
            module.urllib.request.HTTPCookieProcessor(cookie_jar)
        )

        module.capture_control_plane_redirects(session)

        processors = [
            handler
            for handler in session.opener.handlers
            if isinstance(handler, module.urllib.request.HTTPCookieProcessor)
        ]
        self.assertEqual(len(processors), 1)
        self.assertIs(processors[0].cookiejar, cookie_jar)
        self.assertTrue(
            any(
                isinstance(handler, module.CaptureRedirectHandler)
                for handler in session.opener.handlers
            )
        )

    def test_hosted_authorization_accepts_direct_suite_error_callback(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "suite-token",
                "target_origin": "https://issuer.example",
                "hosted_authorization": {
                    "email": "user@example.test",
                    "password": "secret",
                },
            },
            module.threading.Event(),
        )
        session = Mock()
        session.opener = object()
        with (
            patch.object(module.ControlPlaneSession, "login", return_value=session),
            patch.object(module, "capture_control_plane_redirects"),
            patch.object(module, "mark_suite_browser_url_visited") as mark_visited,
            patch.object(
                module,
                "redirect_location",
                return_value=(
                    "https://suite.example/test/a/issuer/callback?"
                    "error=invalid_request&state=one"
                ),
            ) as redirect,
            patch.object(module, "complete_suite_browser_callback") as complete_callback,
        ):
            driver.drive_wallet_initiated_issuer(
                "module-id",
                {
                    "testName": "negative-module",
                    "browser": {
                        "urls": [
                            "https://issuer.example/authorize?request_uri=urn%3Ainvalid"
                        ]
                    },
                },
            )

        self.assertEqual(redirect.call_count, 1)
        mark_visited.assert_called_once()
        session.request_json.assert_not_called()
        complete_callback.assert_called_once_with(
            "https://suite.example",
            "https://suite.example/test/a/issuer/callback?error=invalid_request&state=one",
        )
        self.assertEqual(driver.completed_trigger_total, 1)

    def test_reused_request_uri_module_visits_anonymously_before_hosted_login(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "suite-token",
                "target_origin": "https://issuer.example",
                "hosted_authorization": {
                    "email": "user@example.test",
                    "password": "secret",
                },
            },
            module.threading.Event(),
        )
        authorization_url = (
            "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample"
        )
        info = {
            "testName": (
                "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
            ),
            "browser": {"urls": [authorization_url], "visited": []},
        }
        with (
            patch.object(module, "visit_initial_hosted_login_page") as visit_login,
            patch.object(module, "mark_suite_browser_url_visited") as mark_visited,
            patch.object(module.ControlPlaneSession, "login") as login,
        ):
            driver.drive_wallet_initiated_issuer("module-id", info)

        visit_login.assert_called_once_with("https://issuer.example", authorization_url)
        mark_visited.assert_called_once_with(
            "https://suite.example",
            "suite-token",
            "module-id",
            authorization_url,
        )
        login.assert_not_called()
        self.assertEqual(driver.completed_hosted_authorizations, {"module-id": set()})

    def test_consumed_request_uri_module_drives_second_visit_to_error_callback(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://suite.example",
                "conformance_token": "suite-token",
                "target_origin": "https://issuer.example",
                "hosted_authorization": {
                    "email": "user@example.test",
                    "password": "secret",
                },
            },
            module.threading.Event(),
        )
        authorization_url = (
            "https://issuer.example/authorize?client_id=wallet&request_uri=urn%3Aexample"
        )
        driver.completed_hosted_authorizations["module-id"] = {authorization_url}
        session = Mock()
        session.opener = object()
        with (
            patch.object(module.ControlPlaneSession, "login", return_value=session),
            patch.object(module, "capture_control_plane_redirects"),
            patch.object(module, "mark_suite_browser_url_visited") as mark_visited,
            patch.object(
                module,
                "redirect_location",
                return_value=(
                    "https://suite.example/test/a/issuer/callback?"
                    "error=invalid_request_uri&state=one"
                ),
            ) as redirect,
            patch.object(module, "complete_suite_browser_callback") as complete_callback,
        ):
            driver.drive_wallet_initiated_issuer(
                "module-id",
                {
                    "testName": "fapi2-security-profile-final-par-attempt-reuse-request_uri",
                    "browser": {"urls": [authorization_url], "visited": [authorization_url]},
                },
            )

        mark_visited.assert_called_once()
        self.assertEqual(redirect.call_count, 1)
        complete_callback.assert_called_once_with(
            "https://suite.example",
            "https://suite.example/test/a/issuer/callback?error=invalid_request_uri&state=one",
        )
        self.assertEqual(driver.completed_trigger_total, 1)

    def test_initial_anonymous_visit_requires_exact_same_origin_login_route(self):
        module = load("run_openid4vc_conformance.py")
        opener = object()
        with (
            patch.object(module.urllib.request, "build_opener", return_value=opener),
            patch.object(
                module,
                "redirect_location",
                return_value="https://issuer.example/ui/auth?next=%2Fauthorize%3Fclient_id%3Dwallet",
            ) as redirect,
        ):
            module.visit_initial_hosted_login_page(
                "https://issuer.example",
                "https://issuer.example/authorize?client_id=wallet",
            )

        self.assertIs(redirect.call_args.args[0], opener)
        for location in (
            "https://other.example/ui/auth?next=%2Fauthorize",
            "https://issuer.example/ui/consent?next=%2Fauthorize",
            "https://issuer.example/ui/auth?next=one&next=two",
            "https://issuer.example/ui/auth?next=one&extra=two",
        ):
            with (
                self.subTest(location=location),
                patch.object(module.urllib.request, "build_opener", return_value=opener),
                patch.object(module, "redirect_location", return_value=location),
                self.assertRaisesRegex(RuntimeError, "did not reach the login page"),
            ):
                module.visit_initial_hosted_login_page(
                    "https://issuer.example",
                    "https://issuer.example/authorize?client_id=wallet",
                )

    def test_suite_browser_visit_uses_authenticated_official_runner_api(self):
        module = load("run_openid4vc_conformance.py")
        with patch.object(module.oidf, "oidf_api_request") as request:
            module.mark_suite_browser_url_visited(
                "https://suite.example",
                "suite-token",
                "module-id",
                "https://issuer.example/authorize?client_id=wallet",
            )

        request.assert_called_once_with(
            "POST",
            "https://suite.example",
            "api/runner/browser/module-id/visit",
            "suite-token",
            query={"url": "https://issuer.example/authorize?client_id=wallet"},
            expected_statuses={204},
        )

    def test_hosted_authorization_rejects_ambiguous_or_cross_origin_urls(self):
        module = load("run_openid4vc_conformance.py")
        self.assertIsNone(
            module.hosted_authorization_url(
                "https://issuer.example",
                {"urls": ["https://other.example/authorize?request_uri=one"]},
            )
        )
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            module.hosted_authorization_url(
                "https://issuer.example",
                {
                    "urls": [
                        "https://issuer.example/authorize?request_uri=one",
                        "https://issuer.example/authorize?request_uri=two",
                    ]
                },
            )
        self.assertEqual(
            module.hosted_authorization_url(
                "https://issuer.example",
                {
                    "urls": [
                        "https://issuer.example/authorize?request_uri=one",
                        "https://issuer.example/authorize?request_uri=two",
                    ]
                },
                {"https://issuer.example/authorize?request_uri=one"},
            ),
            "https://issuer.example/authorize?request_uri=two",
        )
        for location in (
            "https://other.example/ui/consent?request_id=one",
            "https://issuer.example/ui/consent?request_id=one&request_id=two",
            "https://issuer.example/other?request_id=one",
        ):
            with self.subTest(location=location), self.assertRaises(RuntimeError):
                module.hosted_consent_request_id("https://issuer.example", location)
        with self.assertRaises(RuntimeError):
                module.hosted_suite_callback_url(
                "https://suite.example",
                "https://other.example/test/a/issuer/callback?code=secret",
            )

    def test_hosted_authorization_denies_only_exact_user_reject_modules(self):
        module = load("run_openid4vc_conformance.py")
        for test_name in module.oidf.FAPI_SECURITY_USER_REJECTS_AUTHENTICATION_MODULES:
            with self.subTest(test_name=test_name):
                self.assertEqual(
                    module.hosted_authorization_decision({"testName": test_name}),
                    "deny",
                )
        for test_name in (
            "oid4vci-1_0-issuer-happy-flow",
            "fapi2-security-profile-final-user-rejects-authentication-extra",
            "",
        ):
            with self.subTest(test_name=test_name):
                self.assertEqual(
                    module.hosted_authorization_decision({"testName": test_name}),
                    "approve",
                )

    def test_suite_implicit_submission_is_unique_and_same_origin(self):
        module = load("run_openid4vc_conformance.py")
        html = b"""
            <script>
              xhr.open('POST', "https://suite.example/test/a/issuer/implicit/random123", true);
            </script>
        """
        self.assertEqual(
            module.suite_implicit_submit_url("https://suite.example", html),
            "https://suite.example/test/a/issuer/implicit/random123",
        )
        for invalid in (
            b"<html>missing</html>",
            html + html,
            b"xhr.open('POST', \"https://other.example/test/a/issuer/implicit/random123\", true);",
            b"xhr.open('POST', \"https://suite.example/admin/implicit/random123\", true);",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                module.suite_implicit_submit_url("https://suite.example", invalid)

    def test_suite_browser_callback_posts_empty_fragment_as_text_plain(self):
        module = load("run_openid4vc_conformance.py")
        html = b"""
            <script>
              xhr.open('POST', "https://suite.example/test/a/issuer/implicit/random123", true);
            </script>
        """

        class Response:
            def __init__(self, status, content_type, body):
                self.status = status
                self.headers = {"Content-Type": content_type}
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self, *_):
                return self.body

        class Opener:
            def __init__(self):
                self.requests = []
                self.responses = [
                    Response(200, "text/html; charset=utf-8", html),
                    Response(204, "text/plain", b""),
                ]

            def open(self, request, **_kwargs):
                self.requests.append(request)
                return self.responses.pop(0)

        opener = Opener()
        with patch.object(module.urllib.request, "build_opener", return_value=opener):
            module.complete_suite_browser_callback(
                "https://suite.example",
                "https://suite.example/test/a/issuer/callback?code=one",
            )

        self.assertEqual(opener.requests[0].get_method(), "GET")
        submission = opener.requests[1]
        self.assertEqual(submission.get_method(), "POST")
        self.assertEqual(
            submission.full_url,
            "https://suite.example/test/a/issuer/implicit/random123",
        )
        self.assertEqual(submission.data, b"")
        self.assertEqual(submission.headers["Content-type"], "text/plain")

    def test_wrapper_rejects_tokenless_or_insecure_suite_modes(self):
        module = load("run_openid4vc_conformance.py")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as config:
            json.dump({"aliases": []}, config)
            config_path = config.name
        try:
            for forbidden in ("--disable-ssl-verify", "--no-api-token"):
                with (
                    patch.object(
                        module,
                        "read_secret_document",
                        return_value={
                            "admin_email": "admin@example.test",
                            "admin_password": "secret",
                        },
                    ),
                    patch.object(module, "read_secret_value", return_value="suite-token"),
                    patch.object(module, "read_private_text", return_value='{"aliases":[]}'),
                    patch(
                        "sys.argv",
                        [
                            "run_openid4vc_conformance.py",
                            "--driver-config-json-file",
                            config_path,
                            "--operator-credentials-file",
                            "operator-credentials.json",
                            "--suite-token-file",
                            "suite-token",
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
            patch.object(module.subprocess, "Popen", return_value=process) as popen,
            patch.object(module.os, "killpg", create=True) as killpg,
            self.assertRaises(KeyboardInterrupt),
        ):
            module.run_runner_invocations([["--suite-dir", "suite"]])

        killpg.assert_called_once_with(process.pid, module.signal.SIGTERM)
        self.assertEqual(process.waits, 2)
        self.assertIs(popen.call_args.kwargs["stdout"], module.subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], module.subprocess.DEVNULL)

    def test_openid4vc_wrapper_suppresses_child_output_when_delivering_suite_token(self):
        module = load("run_openid4vc_conformance.py")
        process = Mock()
        process.wait.return_value = 0

        with patch.object(module.subprocess, "Popen", return_value=process) as popen:
            self.assertEqual(
                module.run_runner_invocations(
                    [["--suite-dir", "suite"]],
                    suite_token="private-suite-token",
                ),
                0,
            )

        self.assertEqual(len(popen.call_args.kwargs["pass_fds"]), 1)
        self.assertIs(popen.call_args.kwargs["stdout"], module.subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], module.subprocess.DEVNULL)

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

            def read(self, _size=-1):
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

    def test_driver_callback_get_rejects_oversized_response(self):
        module = load("run_openid4vc_conformance.py")

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self, _size=-1):
                return b"x" * (module.oidf.MAX_OIDF_API_RESPONSE_BYTES + 1)

        class Opener:
            def open(self, *_args, **_kwargs):
                return Response()

        with patch.object(module.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(RuntimeError, "exceeds 1 MiB"):
                module.get_url("https://suite.example/test/a/alias/callback")

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
            with self.subTest(code=code, location=location), self.assertRaises(RuntimeError) as raised:
                handler.redirect_request(
                    request,
                    None,
                    code,
                    "redirect",
                    {},
                    f"{location}?code=redirect-secret-canary",
                )
            self.assertNotIn("redirect-secret-canary", str(raised.exception))

    def test_driver_retry_log_never_renders_exception_details(self):
        module = load("run_openid4vc_conformance.py")
        stop = module.threading.Event()
        driver = module.Openid4vcDriver({"poll_interval_seconds": 1}, stop)

        def fail_once():
            stop.set()
            raise RuntimeError("credential_offer=driver-secret-canary")

        output = io.StringIO()
        with patch.object(driver, "drive_once", side_effect=fail_once), contextlib.redirect_stdout(output):
            driver.run()
        self.assertIn("RuntimeError", output.getvalue())
        self.assertNotIn("driver-secret-canary", output.getvalue())

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

            with patch.object(
                module,
                "read_private_text",
                return_value=config_json.read_text(encoding="utf-8"),
            ):
                written, aliases = module.write_plan_configs(
                    suite_scripts,
                    "ignored.json",
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

            with patch.object(
                module,
                "read_private_text",
                return_value=config_json.read_text(encoding="utf-8"),
            ):
                module.write_plan_configs(
                    suite_scripts,
                    "ignored.json",
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

    def test_operator_plan_aliases_are_namespaced_without_changing_official_aliases(self):
        module = load("materialize_openid4vc_oidf_config.py")

        self.assertEqual(
            module.plan_alias("nazo-openid4vc-vci", "vci-sd-preauth", None),
            "nazo-openid4vc-vci-vci-sd-preauth",
        )
        self.assertEqual(
            module.plan_alias(
                "nazo-openid4vc-vci", "vci-sd-preauth", "stage-84e35c03-0802y"
            ),
            "nazo-openid4vc-vci-stage-84e35c03-0802y-vci-sd-preauth",
        )
        self.assertNotEqual(
            module.plan_alias("nazo-openid4vc-vci", "vci-sd-preauth", "run-a"),
            module.plan_alias("nazo-openid4vc-vci", "vci-sd-preauth", "run-b"),
        )

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
