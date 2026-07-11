import http.client
import importlib.util
import unittest
from pathlib import Path
from unittest import mock


def load_runner_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_oidf_conformance.py"
    spec = importlib.util.spec_from_file_location("run_oidf_conformance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RunOidfConformanceTests(unittest.TestCase):
    def test_oidf_api_request_retries_remote_disconnect(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read():
                return b'{"ok": true}'

        with (
            mock.patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=[http.client.RemoteDisconnected("connection closed"), FakeResponse()],
            ) as urlopen,
            mock.patch.object(module.time, "sleep") as sleep,
        ):
            status, payload = module.oidf_api_request(
                "GET",
                "https://localhost:8443/",
                "api/server",
                None,
                expected_statuses={200},
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_successful_completion_log_allows_browser_script_noise(self):
        module = load_runner_module()

        logs = [
            {"src": "BROWSER", "msg": "Error during JavaScript execution"},
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIsNone(module.oidf_log_failure("module-id", logs))
        self.assertTrue(module.oidf_log_has_successful_completion(logs))

    def test_successful_completion_log_does_not_hide_warning_or_failure(self):
        module = load_runner_module()

        logs = [
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FAILURE", "src": "ValidatePostLogoutRedirect", "msg": "bad state"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIn("FAILURE", module.oidf_log_failure("module-id", logs))
        self.assertTrue(module.oidf_log_has_successful_completion(logs))

    def test_early_monitor_can_defer_result_failure_without_log_failure(self):
        module = load_runner_module()

        info = {
            "_id": "module-id",
            "testName": "oidcc-frontchannel-rp-initiated-logout",
            "status": "FINISHED",
            "result": "FAILED",
        }

        self.assertTrue(module.oidf_info_failure_can_wait_for_final_result(info))

    def test_early_monitor_does_not_defer_status_or_structured_errors(self):
        module = load_runner_module()

        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FAILED", "result": "FAILED"}
            )
        )
        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FINISHED", "result": "FAILED", "error": "runner crashed"}
            )
        )

    def test_ciba_backchannel_log_context_includes_sanitized_response_body(self):
        module = load_runner_module()

        context = module.oidf_log_context(
            [
                {
                    "src": "CallBackchannelAuthenticationEndpoint",
                    "result": "FAILURE",
                    "msg": "MalformedJsonException",
                    "args": {
                        "endpoint": "https://auth.nazo.run/bc-authorize?code=secret",
                        "body": "<html>token=secret</html>",
                        "response_status_code": 404,
                    },
                }
            ]
        )

        self.assertIn("CallBackchannelAuthenticationEndpoint", context)
        self.assertIn("https://auth.nazo.run/bc-authorize?redacted=1", context)
        self.assertIn("response_status_code=404", context)
        self.assertIn("token=<redacted>", context)
        self.assertNotIn("secret", context)

    def test_token_endpoint_log_context_includes_sanitized_response_body(self):
        module = load_runner_module()

        context = module.oidf_log_context(
            [
                {
                    "src": "CallTokenEndpointAndReturnFullResponse",
                    "msg": "HTTP response",
                    "args": {
                        "response_body": {
                            "error": "invalid_client",
                            "error_description": "token=secret",
                        },
                        "response_status_code": 401,
                    },
                }
            ]
        )

        self.assertIn("CallTokenEndpointAndReturnFullResponse", context)
        self.assertIn("invalid_client", context)
        self.assertIn("response_status_code=401", context)
        self.assertIn("token=<redacted>", context)
        self.assertNotIn("secret", context)

    def test_plan_expression_config_names_are_selected_exactly(self):
        module = load_runner_module()

        selected = module.config_names_from_plan_expressions(
            [
                "oidcc-basic-certification-test-plan[client_registration=static_client] oidf-oidcc-basic-plan-config.json",
                "oidcc-session-management-certification-test-plan[client_registration=static_client] oidf-oidcc-session-management-plan-config.json",
            ],
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-session-management-plan-config.json",
                "oidf-oidcc-frontchannel-logout-plan-config.json",
            },
        )

        self.assertEqual(
            selected,
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-session-management-plan-config.json",
            },
        )


if __name__ == "__main__":
    unittest.main()
