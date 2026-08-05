import importlib.util
import unittest
import uuid
from pathlib import Path
from unittest import mock


def load_module():
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "provision_public_oidf_applicant.py"
    )
    spec = importlib.util.spec_from_file_location(
        "provision_public_oidf_applicant_test", script
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicApplicantProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.credentials = {
            "applicant_email": "applicant@example.test",
            "applicant_password": "applicant-password",
            "admin_email": "admin@example.test",
            "admin_password": "administrator-password",
            "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        }
        self.account = {
            "id": str(uuid.uuid4()),
            "email": "applicant@example.test",
            "role": "user",
            "admin_level": 0,
            "is_active": True,
        }

    def test_created_account_is_verified_by_public_applicant_login(self):
        administrator = mock.Mock()
        administrator.request_json.return_value = self.account
        applicant = mock.Mock()
        applicant.request_json.return_value = self.module.OIDF_PROFILE | {
            "avatar_url": "/auth/me/avatar?v=existing"
        }
        with mock.patch.object(
            self.module.ControlPlaneSession,
            "login",
            side_effect=[administrator, applicant],
        ) as login:
            result = self.module.provision(
                "https://issuer.example", self.credentials
            )

        self.assertEqual(result, {"status": "created", "user_id": self.account["id"]})
        self.assertEqual(login.call_count, 2)
        payload = administrator.request_json.call_args.args[2]
        self.assertEqual(payload["password"], self.credentials["applicant_password"])
        applicant.request_json.assert_called_once_with(
            "GET", "/auth/me", expected_status=200
        )

    def test_conflict_is_idempotent_only_when_existing_account_and_login_validate(self):
        administrator = mock.Mock()
        administrator.request_json.side_effect = [
            self.module.OnboardingHttpError("POST", "/admin/users", 409),
            {"total": 1, "items": [self.account]},
        ]
        applicant = mock.Mock()
        applicant.request_json.side_effect = [
            {},
            self.module.OIDF_PROFILE | {"avatar_url": None},
            {"avatar_url": "/auth/me/avatar?v=created"},
        ]
        with mock.patch.object(
            self.module.ControlPlaneSession,
            "login",
            side_effect=[administrator, applicant],
        ):
            result = self.module.provision(
                "https://issuer.example", self.credentials
            )

        self.assertEqual(result, {"status": "existing", "user_id": self.account["id"]})
        patch_call = applicant.request_json.call_args_list[1]
        self.assertEqual(patch_call.args, ("PATCH", "/auth/me", self.module.OIDF_PROFILE))
        self.assertEqual(patch_call.kwargs, {"expected_status": 200, "csrf": True})
        avatar_call = applicant.request_json.call_args_list[2]
        self.assertEqual(avatar_call.args, ("POST", "/auth/me/avatar"))
        self.assertEqual(avatar_call.kwargs["expected_status"], 200)
        self.assertTrue(avatar_call.kwargs["csrf"])
        self.assertEqual(
            avatar_call.kwargs["content_type"],
            "multipart/form-data; boundary=nazo-oidf-applicant-avatar",
        )
        self.assertIn(self.module.AVATAR_PNG, avatar_call.kwargs["raw_body"])

    def test_conflict_fails_closed_when_requested_account_is_not_visible(self):
        administrator = mock.Mock()
        administrator.request_json.side_effect = [
            self.module.OnboardingHttpError("POST", "/admin/users", 409),
            {"total": 0, "items": []},
        ]
        with (
            mock.patch.object(
                self.module.ControlPlaneSession,
                "login",
                return_value=administrator,
            ),
            self.assertRaisesRegex(self.module.ProvisioningError, "not visible") as raised,
        ):
            self.module.provision("https://issuer.example", self.credentials)

        message = str(raised.exception)
        self.assertNotIn(self.credentials["applicant_email"], message)
        self.assertNotIn(self.credentials["applicant_password"], message)

    def test_applicant_and_approver_must_be_distinct(self):
        credentials = self.credentials | {"applicant_email": "ADMIN@example.test"}
        with self.assertRaisesRegex(self.module.ProvisioningError, "distinct"):
            self.module.provision("https://issuer.example", credentials)


if __name__ == "__main__":
    unittest.main()
