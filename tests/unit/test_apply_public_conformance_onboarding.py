import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def load_module():
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "apply_public_conformance_onboarding.py"
    )
    spec = importlib.util.spec_from_file_location("apply_public_conformance_onboarding", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ApplyPublicConformanceOnboardingTests(unittest.TestCase):
    def test_raw_request_sets_explicit_content_type_without_json_encoding(self):
        module = load_module()
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"avatar_url":"/auth/me/avatar?v=1"}'
        response.headers = {"Content-Type": "application/json"}
        response.geturl.return_value = "https://issuer.example/auth/me/avatar"
        opener = mock.Mock()
        opener.open.return_value = response
        session = module.ControlPlaneSession(
            origin="https://issuer.example",
            opener=opener,
            csrf_token="csrf-token",
        )

        result = session.request_json(
            "POST",
            "/auth/me/avatar",
            expected_status=200,
            csrf=True,
            raw_body=b"multipart-body",
            content_type="multipart/form-data; boundary=test",
        )

        self.assertEqual(result["avatar_url"], "/auth/me/avatar?v=1")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.data, b"multipart-body")
        self.assertEqual(request.get_header("Content-type"), "multipart/form-data; boundary=test")

    def test_http_failure_does_not_include_response_body_in_error(self):
        module = load_module()
        response_secret = "server-leaked-password"
        http_error = urllib.error.HTTPError(
            "https://issuer.example/admin/users",
            409,
            "Conflict",
            {},
            io.BytesIO(response_secret.encode("utf-8")),
        )
        opener = mock.Mock()
        opener.open.side_effect = http_error
        session = module.ControlPlaneSession(
            origin="https://issuer.example",
            opener=opener,
            csrf_token="csrf-token",
        )

        with self.assertRaises(module.OnboardingHttpError) as raised:
            session.request_json(
                "POST",
                "/admin/users",
                {"email": "applicant@example.test", "password": "request-secret"},
                expected_status=201,
                csrf=True,
            )

        self.assertEqual(str(raised.exception), "POST /admin/users returned HTTP 409")
        self.assertNotIn(response_secret, str(raised.exception))
        self.assertNotIn("request-secret", str(raised.exception))

    def test_credentials_are_read_from_a_bounded_fd_without_environment_fallback(self):
        module = load_module()
        read_fd, write_fd = os.pipe()
        try:
            os.write(
                write_fd,
                json.dumps(
                    {
                        "applicant_email": "applicant@example.com",
                        "applicant_password": "applicant-password",
                        "admin_email": "admin@example.com",
                        "admin_password": "admin-password",
                        "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    }
                ).encode("utf-8"),
            )
        finally:
            os.close(write_fd)
        try:
            credentials = module.read_operator_credentials(
                SimpleNamespace(credentials_stdin=False, credentials_fd=read_fd)
            )
        finally:
            os.close(read_fd)

        self.assertEqual(credentials["admin_email"], "admin@example.com")
        source = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "apply_public_conformance_onboarding.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('os.environ.get("OIDF_APPLICANT_PASSWORD"', source)
        self.assertNotIn('os.environ.get("OIDF_ADMIN_PASSWORD"', source)

    def test_credentials_reject_duplicate_or_unknown_fields(self):
        module = load_module()
        for payload in (
            (
                b'{"applicant_email":"a","applicant_email":"b",'
                b'"applicant_password":"p","admin_email":"c","admin_password":"q"}'
            ),
            (
                b'{"applicant_email":"a","applicant_password":"p",'
                b'"admin_email":"c","admin_password":"q","extra":"x"}'
            ),
        ):
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, payload)
            finally:
                os.close(write_fd)
            try:
                with self.assertRaises(module.OnboardingError):
                    module.read_operator_credentials(
                        SimpleNamespace(credentials_stdin=False, credentials_fd=read_fd)
                    )
            finally:
                os.close(read_fd)

    def test_empty_trust_bundle_is_allowed_without_a_requested_anchor(self):
        module = load_module()

        self.assertEqual(module.validate_trust_bundle(b"", required=False), "")
        with self.assertRaisesRegex(
            module.OnboardingError,
            "approved mTLS trust bundle contains no certificate",
        ):
            module.validate_trust_bundle(b"", required=True)

    def test_login_retries_transport_failure_but_not_http_failure(self):
        module = load_module()

        try:
            raise TimeoutError("temporary connect timeout")
        except TimeoutError as cause:
            transport_error = module.OnboardingError("POST /auth/login failed")
            transport_error.__cause__ = cause

        with (
            mock.patch.object(
                module.ControlPlaneSession,
                "request_json",
                side_effect=[transport_error, {"csrf_token": "csrf-token"}],
            ) as request_json,
            mock.patch.object(module.time, "sleep") as sleep,
        ):
            session = module.ControlPlaneSession.login(
                "https://issuer.example", "operator@example.com", "password"
            )

        self.assertEqual(session.csrf_token, "csrf-token")
        self.assertEqual(request_json.call_count, 2)
        sleep.assert_called_once_with(module.LOGIN_RETRY_BASE_SECONDS)

        http_error = urllib.error.HTTPError(
            "https://issuer.example/auth/login", 401, "Unauthorized", {}, None
        )
        self.addCleanup(http_error.close)
        authentication_error = module.OnboardingError("POST /auth/login returned 401")
        authentication_error.__cause__ = http_error
        with (
            mock.patch.object(
                module.ControlPlaneSession,
                "request_json",
                side_effect=authentication_error,
            ) as request_json,
            mock.patch.object(module.time, "sleep") as sleep,
            self.assertRaises(module.OnboardingError),
        ):
            module.ControlPlaneSession.login(
                "https://issuer.example", "operator@example.com", "wrong-password"
            )
        request_json.assert_called_once()
        sleep.assert_not_called()

    def test_totp_uses_the_rfc6238_sha1_six_digit_profile(self):
        module = load_module()

        self.assertEqual(
            module.totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59),
            "287082",
        )

    def test_login_completes_mfa_challenge_and_refreshes_csrf(self):
        module = load_module()

        with (
            mock.patch.object(
                module.ControlPlaneSession,
                "request_json",
                side_effect=[
                    {"csrf_token": "pending-csrf", "mfa_required": True},
                    {"success": True, "method": "totp"},
                    {"csrf_token": "fresh-csrf"},
                ],
            ) as request_json,
            mock.patch.object(module, "totp_code", return_value="123456"),
        ):
            session = module.ControlPlaneSession.login(
                "https://issuer.example",
                "operator@example.com",
                "password",
                mfa_totp_secret="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            )

        self.assertEqual(session.csrf_token, "fresh-csrf")
        self.assertEqual(request_json.call_count, 3)
        self.assertEqual(request_json.call_args_list[1].args[:2], ("POST", "/auth/mfa/verify"))
        self.assertEqual(request_json.call_args_list[1].args[2]["code"], "123456")
        self.assertEqual(request_json.call_args_list[2].args[:2], ("GET", "/auth/csrf"))

    def test_access_request_site_name_is_stable_unique_and_within_product_limit(self):
        module = load_module()

        first = module.access_request_site_name("logical-client-" + "a" * 500)
        second = module.access_request_site_name("logical-client-" + "b" * 500)

        self.assertEqual(first, module.access_request_site_name("logical-client-" + "a" * 500))
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first.encode("utf-8")), 120)

    def test_delivery_uses_owner_request_id_in_csrf_protected_post(self):
        module = load_module()

        class Session:
            def __init__(self):
                self.calls = []

            def request_json(self, method, path, payload=None, **kwargs):
                self.calls.append((method, path, payload, kwargs))
                if (method, path) == ("GET", "/auth/me/access-requests"):
                    return {
                        "items": [
                            {
                                "id": "request-1",
                                "delivery_available": True,
                            }
                        ]
                    }
                if (method, path) == ("POST", "/auth/me/access-delivery"):
                    return {"client_id": "client-1", "client_secret": "secret-1"}
                raise AssertionError((method, path, payload, kwargs))

        session = Session()
        self.assertEqual(
            module.delivered_client_for_request(session, "request-1"),
            ("client-1", "secret-1"),
        )
        self.assertEqual(
            session.calls[1],
            (
                "POST",
                "/auth/me/access-delivery",
                {"request_id": "request-1"},
                {"expected_status": 200, "csrf": True},
            ),
        )

    def test_apply_journals_partial_state_before_remote_approval_failure(self):
        module = load_module()
        approval_payloads = []

        class Applicant:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me"):
                    return {"id": "applicant", "admin_level": 0}
                if (method, path) == ("POST", "/auth/me/access-requests"):
                    return {"id": "request-1"}
                raise AssertionError((method, path, payload, kwargs))

        class Admin:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me"):
                    return {"id": "admin", "admin_level": 1}
                if method == "POST" and path.endswith("/approve"):
                    approval_payloads.append(payload)
                    raise module.OnboardingError("approval rejected")
                raise AssertionError((method, path, payload, kwargs))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            configs = root / "configs.json"
            plan_set = root / "plans.json"
            plan_manifest = root / "plan-manifest.json"
            state = root / "state.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "suite_base_url": "https://suite.example",
                        "applicant_email": "applicant@example.com",
                        "clients": [
                            {
                                "logical_client_id": "logical-client",
                                "request": {"client_type": "confidential"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            configs.write_text(
                '{"configs":{"plan":{"client_id":"logical-client"}}}', encoding="utf-8"
            )
            plan_set.write_text("[]", encoding="utf-8")
            plan_manifest.write_text("{}", encoding="utf-8")
            args = SimpleNamespace(
                lease_id="018f3f2a-7b55-7a25-8f20-6d526f8f44e1",
                manifest=manifest,
                target_issuer="https://issuer.example",
                state_file=state,
                plan_configs=configs,
                plan_set=plan_set,
                plan_manifest=plan_manifest,
                runner_env=root / "runner.env",
                delivered_client_material=root / "delivered.json",
                no_runner_env=False,
                trust_bundle=root / "trust.pem",
            )

            with (
                mock.patch.object(
                    module,
                    "read_operator_credentials",
                    return_value={
                        "applicant_email": "applicant@example.com",
                        "applicant_password": "applicant-password",
                        "admin_email": "admin@example.com",
                        "admin_password": "admin-password",
                        "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    },
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Applicant(), Admin()],
                ),
            ):
                with self.assertRaisesRegex(module.OnboardingError, "approval rejected"):
                    module.apply_onboarding(args)

            journal = json.loads(state.read_text(encoding="utf-8"))
            self.assertNotIn("complete", journal)
            self.assertEqual(
                journal["conformance_lease_id"],
                "018f3f2a-7b55-7a25-8f20-6d526f8f44e1",
            )
            self.assertEqual(len(journal["manifest_sha256"]), 64)
            self.assertEqual(
                approval_payloads[0]["conformance_lease_id"],
                "018f3f2a-7b55-7a25-8f20-6d526f8f44e1",
            )
            self.assertEqual(
                journal["clients"],
                [
                    {
                        "logical_client_id": "logical-client",
                        "access_request_id": "request-1",
                    }
                ],
            )

    def test_cleanup_rejects_a_journaled_pending_request_without_a_client(self):
        module = load_module()

        class Applicant:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me/access-requests"):
                    return {"items": [{"id": "request-1", "status": 0}]}
                raise AssertionError((method, path, payload, kwargs))

        class Admin:
            def __init__(self):
                self.calls = []

            def request_json(self, method, path, payload=None, **kwargs):
                self.calls.append((method, path, payload, kwargs))
                return {"id": "request-1", "status": 2}

        admin = Admin()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "clients": [
                            {
                                "logical_client_id": "logical-client",
                                "access_request_id": "request-1",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                state_file=state,
                target_issuer="https://issuer.example",
                delivered_client_material=Path(directory) / "delivered.json",
            )
            with (
                mock.patch.object(
                    module,
                    "read_operator_credentials",
                    return_value={
                        "applicant_email": "applicant@example.com",
                        "applicant_password": "applicant-password",
                        "admin_email": "admin@example.com",
                        "admin_password": "admin-password",
                        "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    },
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Applicant(), admin],
                ),
            ):
                self.assertEqual(module.cleanup_onboarding(args), 0)

            self.assertFalse(state.exists())
            self.assertEqual(admin.calls[0][0:2], ("POST", "/admin/access-requests/request-1/reject"))

    def test_cleanup_ignores_a_journal_entry_created_before_the_remote_request(self):
        module = load_module()

        class Session:
            def request_json(self, method, path, payload=None, **kwargs):
                raise AssertionError((method, path, payload, kwargs))

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "clients": [{"logical_client_id": "not-yet-submitted"}],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                state_file=state,
                target_issuer="https://issuer.example",
                delivered_client_material=Path(directory) / "delivered.json",
            )
            with (
                mock.patch.object(
                    module,
                    "read_operator_credentials",
                    return_value={
                        "applicant_email": "applicant@example.com",
                        "applicant_password": "applicant-password",
                        "admin_email": "admin@example.com",
                        "admin_password": "admin-password",
                        "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    },
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Session(), Session()],
                ),
            ):
                self.assertEqual(module.cleanup_onboarding(args), 0)

            self.assertFalse(state.exists())

    def test_target_must_be_an_exact_https_origin(self):
        module = load_module()

        self.assertEqual(
            module.canonical_https_origin("https://issuer.example/", label="issuer"),
            "https://issuer.example",
        )
        for value in (
            "http://issuer.example",
            "https://user:secret@issuer.example",
            "https://issuer.example/path",
            "https://issuer.example?query=1",
            "https://issuer.example/#fragment",
        ):
            with self.subTest(value=value):
                with self.assertRaises(module.OnboardingError):
                    module.canonical_https_origin(value, label="issuer")

    def test_client_rewrite_changes_only_exact_client_id_fields(self):
        module = load_module()
        document = {
            "client": {
                "client_id": "logical-client",
                "client_secret": "old-secret",
                "description": "logical-client",
            },
            "nested": [{"client_id": "another-client"}],
        }

        replacements = module.replace_client_material(
            document, "logical-client", "approved-client", "delivered-secret"
        )

        self.assertEqual(replacements, 1)
        self.assertEqual(document["client"]["client_id"], "approved-client")
        self.assertEqual(document["client"]["client_secret"], "delivered-secret")
        self.assertEqual(document["client"]["description"], "logical-client")
        self.assertEqual(document["nested"][0]["client_id"], "another-client")

    def test_manifest_rejects_duplicate_logical_clients_and_nonconfidential_requests(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                '{"schema":1,"clients":['
                '{"logical_client_id":"same","request":{"client_type":"confidential"}},'
                '{"logical_client_id":"same","request":{"client_type":"public"}}]}'
            )

            with self.assertRaises(module.OnboardingError):
                module.require_manifest(path)

    def test_control_plane_tool_has_no_database_or_server_crate_dependency(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "apply_public_conformance_onboarding.py"
        ).read_text(encoding="utf-8")

        for forbidden in (
            "DATABASE_URL",
            "psycopg",
            "sqlx",
            "nazo_postgres",
            "nazo-oauth-server",
            "INSERT INTO",
            "UPDATE oauth_clients",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "/auth/me/access-requests",
            "/admin/access-requests/",
            "/auth/me/mtls-trust-requests",
            "/admin/mtls-trust-requests/",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
