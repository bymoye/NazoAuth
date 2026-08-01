#!/usr/bin/env python3
"""Provision one OIDF applicant through the public authenticated admin API."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_public_conformance_onboarding import (  # noqa: E402
    ControlPlaneSession,
    OnboardingError,
    OnboardingHttpError,
)
from oidf_secret_input import (  # noqa: E402
    SecretInputError,
    add_secret_source_arguments,
    read_secret_document,
)


REQUIRED_FIELDS = (
    "applicant_email",
    "applicant_password",
    "admin_email",
    "admin_password",
)
MAX_USERS_TO_INSPECT = 10_000


class ProvisioningError(RuntimeError):
    pass


def https_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
        raise ProvisioningError("--target-issuer must be an HTTPS origin without a path")
    return parsed._replace(path="", query="", fragment="").geturl()


def validate_user(value: object, expected_email: str) -> str:
    if not isinstance(value, dict):
        raise ProvisioningError("public admin user response must be a JSON object")
    identifier = value.get("id")
    email = value.get("email")
    if not isinstance(identifier, str):
        raise ProvisioningError("public admin user response has an invalid identifier")
    try:
        uuid.UUID(identifier)
    except (ValueError, AttributeError) as error:
        raise ProvisioningError("public admin user response has an invalid identifier") from error
    if not isinstance(email, str) or email.strip().casefold() != expected_email.strip().casefold():
        raise ProvisioningError("public admin user response does not identify the requested account")
    if value.get("role") != "user" or value.get("admin_level") != 0:
        raise ProvisioningError("OIDF applicant must be a non-administrator account")
    if value.get("is_active") is not True:
        raise ProvisioningError("OIDF applicant account must be active")
    return identifier


def find_existing_applicant(
    administrator: ControlPlaneSession,
    applicant_email: str,
) -> dict[str, object] | None:
    page_size = 100
    for page in range(1, MAX_USERS_TO_INSPECT // page_size + 1):
        body = administrator.request_json(
            "GET",
            f"/admin/users?page={page}&page_size={page_size}",
            expected_status=200,
        )
        total = body.get("total")
        items = body.get("items")
        if not isinstance(total, int) or total < 0 or not isinstance(items, list):
            raise ProvisioningError("public admin user list response is malformed")
        for item in items:
            if (
                isinstance(item, dict)
                and isinstance(item.get("email"), str)
                and item["email"].strip().casefold() == applicant_email.strip().casefold()
            ):
                return item
        if page * page_size >= total:
            return None
    raise ProvisioningError("public admin user list exceeds the bounded inspection limit")


def provision(origin: str, credentials: dict[str, str]) -> dict[str, str]:
    if credentials["applicant_email"].strip().casefold() == credentials[
        "admin_email"
    ].strip().casefold():
        raise ProvisioningError("OIDF applicant and approver must be distinct accounts")
    administrator = ControlPlaneSession.login(
        origin,
        credentials["admin_email"],
        credentials["admin_password"],
    )
    status = "created"
    try:
        account = administrator.request_json(
            "POST",
            "/admin/users",
            {
                "email": credentials["applicant_email"],
                "password": credentials["applicant_password"],
            },
            expected_status=201,
            csrf=True,
        )
    except OnboardingHttpError as error:
        if error.status != 409:
            raise
        account = find_existing_applicant(administrator, credentials["applicant_email"])
        if account is None:
            raise ProvisioningError(
                "public API reported an account conflict but the account is not visible"
            ) from error
        status = "existing"
    identifier = validate_user(account, credentials["applicant_email"])
    # A conflict is idempotent only if the supplied credentials still identify
    # the same usable applicant.  This also closes the freshly-created flow.
    ControlPlaneSession.login(
        origin,
        credentials["applicant_email"],
        credentials["applicant_password"],
    )
    return {"status": status, "user_id": identifier}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-issuer", required=True)
    add_secret_source_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        credentials = read_secret_document(args, required_fields=REQUIRED_FIELDS)
        result = provision(https_origin(args.target_issuer), credentials)
    except (SecretInputError, ProvisioningError, OnboardingError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
