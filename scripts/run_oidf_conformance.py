#!/usr/bin/env python3
"""Run OpenID Foundation conformance plans with repository-owned input checks."""

from __future__ import annotations

import argparse
import copy
import http.client
import json
import os
import re
import shlex
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


OIDCC_CONFIG_FILE = "oidf-oidcc-plan-config.json"
FAPI_CONFIG_FILE = "oidf-fapi-plan-config.json"
OIDCC_BASIC_CONFIG_FILE = "oidf-oidcc-basic-plan-config.json"
OIDCC_DYNAMIC_CONFIG_FILE = "oidf-oidcc-dynamic-plan-config.json"
OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE = "oidf-oidcc-dynamic-crypto-plan-config.json"
OIDCC_CONFIG_CONFIG_FILE = "oidf-oidcc-config-plan-config.json"
FAPI_SECURITY_FINAL_CONFIG_FILE = "oidf-fapi-security-final-plan-config.json"
FAPI_MESSAGE_FINAL_CONFIG_FILE = "oidf-fapi-message-final-plan-config.json"
FAPI_SECURITY_ID2_CONFIG_FILE = "oidf-fapi-security-id2-plan-config.json"
FAPI_MESSAGE_ID1_CONFIG_FILE = "oidf-fapi-message-id1-plan-config.json"
FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-final-user-rejects-authentication"
)
FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-id2-user-rejects-authentication"
)
FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-id2-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_USER_REJECTS_AUTHENTICATION_MODULES = (
    FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION,
    FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION,
)
FAPI_SECURITY_PAR_REUSE_BEFORE_AUTH_MODULES = (
    FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH,
    FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH,
)
OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES = (
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)
NAZO_AUTHORIZATION_ERROR_RESPONSE_TASK = "Capture authorization error response"
NAZO_AUTHORIZATION_ERROR_PAGE_TASK = "Capture authorization error page"
NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN = (
    r'("error"\s*:\s*"(invalid_request|invalid_request_object|access_denied|login_required|server_error)"'
    r"|invalid_request|invalid_request_object|access_denied|login_required|server_error)"
)
OIDF_BAD_FINAL_RESULTS = {"FAILED", "INTERRUPTED", "WARNING"}
OIDF_BAD_STATUS_VALUES = {"FAILED", "INTERRUPTED"}
OIDF_BAD_LOG_RESULTS = {"FAILURE", "WARNING"}
OIDF_LOG_CONTEXT_SOURCES = {
    "BROWSER",
    "CallBackchannelAuthenticationEndpoint",
    "CallTokenEndpointAndReturnFullResponse",
    "WebRunner",
}
OIDF_LOG_CONTEXT_FIELDS = (
    "src",
    "result",
    "msg",
    "browser",
    "task",
    "url",
    "endpoint",
    "uri",
    "request_uri",
    "match",
    "element_type",
    "target",
    "code",
    "status",
    "body",
    "response_body",
    "response_status_code",
    "response_status_text",
    "content_type",
    "backchannel_authentication_endpoint_response",
    "backchannel_authentication_endpoint_response_http_status",
    "backchannel_authentication_endpoint_response_headers",
)
OIDF_SENSITIVE_LOG_FIELDS = {
    "authorization",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "code",
    "password",
    "client_secret",
    "request_uri",
}
OIDF_ALLOWED_REVIEW_CONTEXTS_BY_CONFIG = {
    OIDCC_BASIC_CONFIG_FILE: (
        "oidcc-basic-certification-test-plan",
        frozenset({
            "oidcc-prompt-login",
            "oidcc-max-age-1",
            "oidcc-ensure-registered-redirect-uri",
        }),
    ),
    OIDCC_DYNAMIC_CONFIG_FILE: (
        "oidcc-basic-certification-test-plan",
        frozenset({
            "oidcc-prompt-login",
            "oidcc-max-age-1",
            "oidcc-ensure-registered-redirect-uri",
        }),
    ),
}
OIDF_CALLBACK_PATH_PATTERN = re.compile(r"/test/a/[^/]+/callback")
OIDF_API_SSL_CONTEXT: ssl.SSLContext | None = None
NAZO_PUBLIC_ISSUER_ORIGIN = "https://auth.nazo.run"
NAZO_RUN_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9.-]*nazo\.run(?::\d+)?(?:/[^\s\"'<>)]*)?")
NAZO_LOGIN_EMAIL_ID = "nazo-login-email"
NAZO_LOGIN_PASSWORD_ID = "nazo-login-password"
NAZO_LOGIN_SUBMIT_ID = "nazo-login-submit"
NAZO_LOGIN_SUBMIT_READY_SELECTOR = f"#{NAZO_LOGIN_SUBMIT_ID}:not([disabled])"
NAZO_CONSENT_APPROVE_ID = "nazo-consent-approve"
NAZO_CONSENT_DENY_ID = "nazo-consent-deny"
NAZO_CONSENT_PAGE_PATTERN = r"(Review authorization|Requested permissions)"

DEFAULT_PLAN_EXPRESSIONS = [
    f"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] {OIDCC_CONFIG_FILE}",
    f"oidcc-config-certification-test-plan {OIDCC_CONFIG_FILE}",
    f"fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-security-profile-id2-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
    f"fapi2-message-signing-id1-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_CONFIG_FILE}",
]
PER_PLAN_CONFIG_EXPRESSIONS = [
    f"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] {OIDCC_BASIC_CONFIG_FILE}",
    f"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] {OIDCC_DYNAMIC_CONFIG_FILE}",
    f"oidcc-dynamic-certification-test-plan[response_type=code]:oidcc-userinfo-rs256 {OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE}",
    f"oidcc-config-certification-test-plan {OIDCC_CONFIG_CONFIG_FILE}",
    f"fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_SECURITY_FINAL_CONFIG_FILE}",
    f"fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_MESSAGE_FINAL_CONFIG_FILE}",
    f"fapi2-security-profile-id2-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] {FAPI_SECURITY_ID2_CONFIG_FILE}",
    f"fapi2-message-signing-id1-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] {FAPI_MESSAGE_ID1_CONFIG_FILE}",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def non_empty_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        fail(f"{name} is required")
    return value


def non_empty_file(path: str, label: str) -> str:
    if not path.strip():
        fail(f"{label} path must not be empty")
    try:
        value = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"failed to read {label} {path}: {exc}")
    if value.strip() == "":
        fail(f"{label} {path} must not be empty")
    return value


def validate_config_file_name(file_name: str) -> None:
    if "/" in file_name or "\\" in file_name or Path(file_name).name != file_name:
        fail("--config-file-name must be a file name, not a path")
    if Path(file_name).suffix.lower() != ".json":
        fail("--config-file-name must use the .json extension")


def atomic_write_json_file(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True)
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            text=True,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def issuer_from_discovery_url(discovery_url: str) -> str | None:
    suffix = "/.well-known/openid-configuration"
    if not discovery_url.endswith(suffix):
        return None
    issuer = discovery_url[: -len(suffix)].rstrip("/")
    if not issuer:
        return None
    parsed = urlparse(issuer)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return None
    return issuer


def config_requires_browser_automation(config_name: str) -> bool:
    return config_name != OIDCC_CONFIG_CONFIG_FILE


def validate_browser_automation(config_name: str, config_value: dict[str, object]) -> None:
    if not config_requires_browser_automation(config_name):
        return

    server = config_value.get("server")
    if not isinstance(server, dict):
        return
    discovery_url = server.get("discoveryUrl")
    if not isinstance(discovery_url, str):
        return
    issuer = issuer_from_discovery_url(discovery_url)
    if issuer is None:
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list) or not browser:
        fail(
            f"{config_name} must include browser automation for {issuer}/authorize; "
            "OIDF OP modules otherwise remain in WAITING until they time out"
        )

    authorization_prefix = f"{issuer}/authorize"
    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not isinstance(match, str):
            continue
        if match.startswith(authorization_prefix) or "/authorize" in match:
            return

    fail(
        f"{config_name} browser automation must match the authorization endpoint "
        f"{authorization_prefix}; matching only frontend pages does not start OIDF OP modules"
    )


def issuer_from_config(config_value: dict[str, object]) -> str | None:
    server = config_value.get("server")
    if not isinstance(server, dict):
        return None
    discovery_url = server.get("discoveryUrl")
    if not isinstance(discovery_url, str):
        return None
    return issuer_from_discovery_url(discovery_url)


def nazo_public_issuer_origin(config_value: dict[str, object]) -> str:
    return issuer_from_config(config_value) or NAZO_PUBLIC_ISSUER_ORIGIN


def nazo_authorization_prefix(config_value: dict[str, object]) -> str:
    return f"{nazo_public_issuer_origin(config_value).rstrip('/')}/authorize"


def nazo_ui_match(config_value: dict[str, object], path: str) -> str:
    return f"{nazo_public_issuer_origin(config_value).rstrip('/')}/ui/{path.lstrip('/')}*"


def is_hosted_authorization_match(match: object, config_value: dict[str, object]) -> bool:
    return isinstance(match, str) and match.startswith(nazo_authorization_prefix(config_value))


def uses_public_nazo_ui(config_value: dict[str, object]) -> bool:
    return nazo_public_issuer_origin(config_value).rstrip("/") == NAZO_PUBLIC_ISSUER_ORIGIN


def non_empty_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def nazo_automation_credentials(config_value: dict[str, object]) -> tuple[str, str]:
    nazo = config_value.get("nazo")
    nazo_object = nazo if isinstance(nazo, dict) else {}
    email = (
        non_empty_string(nazo_object.get("oidf_user_email"))
        or non_empty_string(nazo_object.get("user_email"))
        or non_empty_string(nazo_object.get("login_email"))
        or non_empty_string(os.environ.get("OIDF_USER_EMAIL"))
    )
    password = (
        non_empty_string(nazo_object.get("oidf_user_password"))
        or non_empty_string(nazo_object.get("user_password"))
        or non_empty_string(nazo_object.get("login_password"))
        or non_empty_string(os.environ.get("OIDF_USER_PASSWORD"))
    )
    if not email or not password:
        fail(
            "Nazo user-facing /ui browser automation requires OIDF_USER_EMAIL and "
            "OIDF_USER_PASSWORD secrets, or matching nazo.oidf_user_* fields in the plan config"
        )
    return email, password


def nazo_login_page_commands(
    config_value: dict[str, object],
    *,
    capture_placeholder: bool = False,
) -> list[list[object]]:
    email, password = nazo_automation_credentials(config_value)
    commands: list[list[object]] = [
        ["wait-element-visible", "id", NAZO_LOGIN_EMAIL_ID, 30],
        ["wait-element-visible", "id", NAZO_LOGIN_PASSWORD_ID, 30],
        ["text", "id", NAZO_LOGIN_EMAIL_ID, email],
        ["text", "id", NAZO_LOGIN_PASSWORD_ID, password],
        ["wait-element-visible", "id", NAZO_LOGIN_SUBMIT_ID, 30],
        ["wait-element-visible", "css", NAZO_LOGIN_SUBMIT_READY_SELECTOR, 30],
        ["click", "id", NAZO_LOGIN_SUBMIT_ID],
        ["wait", "contains", "/ui/consent", 30],
    ]
    if capture_placeholder:
        commands.insert(
            0,
            ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*", "update-image-placeholder-optional"],
        )
    return commands


def nazo_consent_approve_commands(config_value: dict[str, object]) -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_APPROVE_ID, 30],
        ["click", "id", NAZO_CONSENT_APPROVE_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", 10],
    ]


def nazo_consent_deny_commands(config_value: dict[str, object]) -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_DENY_ID, 30],
        ["click", "id", NAZO_CONSENT_DENY_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", 10],
    ]


def nazo_login_observation_commands(config_value: dict[str, object]) -> list[list[object]]:
    return [
        [
            "wait",
            "id",
            NAZO_LOGIN_EMAIL_ID,
            30,
            ".*",
            "update-image-placeholder-optional",
        ]
    ]


def normalized_origin(value: str) -> str:
    parsed = urlparse(value.strip().rstrip("/"))
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.path:
        fail(f"target issuer must be an origin URL without a path: {value}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin != NAZO_PUBLIC_ISSUER_ORIGIN:
        fail(f"target issuer must be {NAZO_PUBLIC_ISSUER_ORIGIN}")
    return origin


def assert_only_auth_nazo_run_urls(value: object, config_name: str) -> None:
    if isinstance(value, list):
        for item in value:
            assert_only_auth_nazo_run_urls(item, config_name)
    elif isinstance(value, dict):
        for item in value.values():
            assert_only_auth_nazo_run_urls(item, config_name)
    elif isinstance(value, str):
        for match in NAZO_RUN_URL_PATTERN.finditer(value):
            url = match.group(0)
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin != NAZO_PUBLIC_ISSUER_ORIGIN:
                fail(
                    f"{config_name} contains unsupported Nazo URL {url}; "
                    f"use {NAZO_PUBLIC_ISSUER_ORIGIN} only"
                )


def config_alias(config_value: dict[str, object]) -> str | None:
    alias = config_value.get("alias")
    if isinstance(alias, str) and alias.strip():
        return alias.strip()
    return None


def normalize_oidf_callback_waits(config_value: dict[str, object]) -> None:
    alias = config_alias(config_value)
    if alias is None:
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    expected_callback_path = f"/test/a/{alias}/callback"
    for entry in browser:
        normalize_oidf_callback_waits_in_value(entry, expected_callback_path)

    override = config_value.get("override")
    if isinstance(override, dict):
        for override_value in override.values():
            normalize_oidf_callback_waits_in_value(override_value, expected_callback_path)


def normalize_oidf_callback_waits_in_value(value: object, expected_callback_path: str) -> None:
    if isinstance(value, list):
        if (
            len(value) >= 3
            and value[0] == "wait"
            and value[1] == "contains"
            and isinstance(value[2], str)
        ):
            value[2] = OIDF_CALLBACK_PATH_PATTERN.sub(
                lambda _: expected_callback_path,
                value[2],
            )
        for item in value:
            normalize_oidf_callback_waits_in_value(item, expected_callback_path)
    elif isinstance(value, dict):
        for key, item in list(value.items()):
            if isinstance(item, str):
                value[key] = OIDF_CALLBACK_PATH_PATTERN.sub(
                    lambda _: expected_callback_path,
                    item,
                )
            else:
                normalize_oidf_callback_waits_in_value(item, expected_callback_path)


def config_uses_nazo_hosted_conformance_ui(config_value: dict[str, object]) -> bool:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return False

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if is_hosted_authorization_match(match, config_value):
            return True
    return False


def nazo_user_reject_browser_automation(config_value: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "comment": (
                "Nazo OAuth hosted UI signs in after explicit browser automation, "
                "then lets this negative module choose deny before the default approval."
            ),
            "match": f"{nazo_authorization_prefix(config_value)}*",
            "tasks": [
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": nazo_ui_match(config_value, "auth"),
                    "commands": nazo_login_page_commands(config_value),
                },
                {
                    "task": "Deny consent page",
                    "match": nazo_ui_match(config_value, "consent"),
                    "commands": nazo_consent_deny_commands(config_value),
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [["wait", "id", "submission_complete", 10]],
                },
            ],
        }
    ]


def authorization_error_response_task(config_value: dict[str, object]) -> dict[str, object]:
    commands = [
        [
            "wait",
            "css",
            "body",
            10,
            NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN,
            "update-image-placeholder-optional",
        ]
    ]
    return {
        "task": NAZO_AUTHORIZATION_ERROR_RESPONSE_TASK,
        "optional": True,
        "match": f"{nazo_authorization_prefix(config_value)}*",
        "commands": commands,
    }


def login_page_wait_command(command: object) -> bool:
    return (
        isinstance(command, list)
        and len(command) >= 5
        and command[:5] == ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*"]
    )


def login_page_visible_wait_command(command: object) -> bool:
    return (
        isinstance(command, list)
        and len(command) >= 4
        and command[:4] == ["wait-element-visible", "id", NAZO_LOGIN_EMAIL_ID, 30]
    )


def login_page_click_command(command: object) -> bool:
    return (
        isinstance(command, list)
        and len(command) >= 3
        and command[:3] == ["click", "id", NAZO_LOGIN_SUBMIT_ID]
    )


def add_login_page_click(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return
    if any(login_page_click_command(command) for command in commands):
        return

    for index, command in enumerate(commands):
        if login_page_wait_command(command):
            commands.insert(index + 1, ["click", "id", NAZO_LOGIN_SUBMIT_ID])
            return


def task_matches_hosted_ui(task: dict[str, object], config_value: dict[str, object], path: str) -> bool:
    match = task.get("match")
    if not isinstance(match, str):
        return False
    expected = nazo_ui_match(config_value, path)
    return match == expected


def use_nazo_user_facing_task_commands(config_value: dict[str, object], task: object) -> None:
    if not isinstance(task, dict):
        return
    if task_matches_hosted_ui(task, config_value, "auth"):
        if task.get("task") == "Observe first login page without authentication":
            task["commands"] = nazo_login_observation_commands(config_value)
            return
        commands = task.get("commands")
        captures_placeholder = isinstance(commands, list) and any(
            isinstance(command, list)
            and "update-image-placeholder-optional" in command
            for command in commands
        )
        updated_commands = nazo_login_page_commands(config_value)
        if captures_placeholder and updated_commands:
            updated_commands.insert(
                0,
                [
                    "wait",
                    "id",
                    NAZO_LOGIN_EMAIL_ID,
                    30,
                    ".*",
                    "update-image-placeholder-optional",
                ],
            )
        task["commands"] = updated_commands
    elif task_matches_hosted_ui(task, config_value, "consent"):
        commands = task.get("commands")
        has_deny_command = isinstance(commands, list) and any(
            isinstance(command, list)
            and len(command) >= 3
            and command[0] == "click"
            and command[1] == "id"
            and command[2] == NAZO_CONSENT_DENY_ID
            for command in commands
        )
        if task.get("task") == "Deny consent page" or has_deny_command:
            task["commands"] = nazo_consent_deny_commands(config_value)
        else:
            task["commands"] = nazo_consent_approve_commands(config_value)


def use_nazo_user_facing_browser_commands(config_value: dict[str, object]) -> None:
    if not uses_public_nazo_ui(config_value):
        return

    browser = config_value.get("browser")
    if isinstance(browser, list):
        for entry in browser:
            if not isinstance(entry, dict):
                continue
            match = entry.get("match")
            if not is_hosted_authorization_match(match, config_value):
                continue
            tasks = entry.get("tasks")
            if not isinstance(tasks, list):
                continue
            for task in tasks:
                use_nazo_user_facing_task_commands(config_value, task)

    override = config_value.get("override")
    if isinstance(override, dict):
        for override_value in override.values():
            if not isinstance(override_value, dict):
                continue
            override_browser = override_value.get("browser")
            if not isinstance(override_browser, list):
                continue
            for entry in override_browser:
                if not isinstance(entry, dict):
                    continue
                match = entry.get("match")
                if not is_hosted_authorization_match(match, config_value):
                    continue
                tasks = entry.get("tasks")
                if not isinstance(tasks, list):
                    continue
                for task in tasks:
                    use_nazo_user_facing_task_commands(config_value, task)


def add_login_page_clicks(config_value: dict[str, object]) -> None:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not is_hosted_authorization_match(match, config_value):
            continue
        tasks = entry.get("tasks")
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            add_login_page_click(task)


def add_authorization_error_response_capture(config_value: dict[str, object]) -> None:
    normalize_authorization_error_response_capture(config_value, config_value.get("browser"))

    override = config_value.get("override")
    if not isinstance(override, dict):
        return

    for override_value in override.values():
        if isinstance(override_value, dict):
            normalize_authorization_error_response_capture(
                config_value,
                override_value.get("browser"),
            )


def normalize_authorization_error_response_capture(
    config_value: dict[str, object],
    browser: object,
) -> None:
    if not isinstance(browser, list):
        return
    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not is_hosted_authorization_match(match, config_value):
            continue
        tasks = entry.setdefault("tasks", [])
        if not isinstance(tasks, list):
            continue
        normalized_tasks: list[object] = []
        has_error_response_task = False
        for task in tasks:
            if isinstance(task, dict) and task.get("task") in {
                NAZO_AUTHORIZATION_ERROR_PAGE_TASK,
                NAZO_AUTHORIZATION_ERROR_RESPONSE_TASK,
            }:
                if not has_error_response_task:
                    normalized_tasks.append(authorization_error_response_task(config_value))
                    has_error_response_task = True
                continue
            normalized_tasks.append(task)
        if not has_error_response_task:
            normalized_tasks.insert(0, authorization_error_response_task(config_value))
        tasks[:] = normalized_tasks


def remove_login_page_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 6:
            continue
        if not login_page_wait_command(command):
            continue
        if command[5] == "update-image-placeholder-optional":
            command.pop(5)


def remove_default_login_page_placeholder_updates(config_value: dict[str, object]) -> None:
    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    for entry in browser:
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        if not is_hosted_authorization_match(match, config_value):
            continue
        tasks = entry.get("tasks")
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            remove_login_page_placeholder_update(task)


def mark_login_page_wait_as_placeholder_update(
    config_value: dict[str, object],
    task: object,
) -> None:
    if not isinstance(task, dict):
        return
    if task_matches_hosted_ui(task, config_value, "auth"):
        task["commands"] = nazo_login_page_commands(
            config_value,
            capture_placeholder=True,
        )
        return

    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for index, command in enumerate(commands):
        if not isinstance(command, list) or len(command) < 5:
            continue
        if not login_page_wait_command(command):
            continue
        if len(command) == 5:
            command.append("update-image-placeholder-optional")
        elif command[5] is None or command[5] == "":
            command[5] = "update-image-placeholder-optional"
        return

    for index, command in enumerate(commands):
        if not login_page_visible_wait_command(command):
            continue
        commands.insert(
            index,
            ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*", "update-image-placeholder-optional"],
        )
        return


def browser_automation_with_second_login_placeholder(
    config_value: dict[str, object],
    browser: list[object],
) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not is_hosted_authorization_match(match, config_value):
            automation.append(copy.deepcopy(entry))
            continue

        first_authorization = copy.deepcopy(entry)
        first_authorization["match-limit"] = 1
        automation.append(first_authorization)

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        tasks = second_authorization.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                mark_login_page_wait_as_placeholder_update(config_value, task)
        automation.append(second_authorization)

    return automation


def first_login_observation_automation(
    config_value: dict[str, object],
    browser: list[object],
) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not is_hosted_authorization_match(match, config_value):
            automation.append(copy.deepcopy(entry))
            continue

        first_authorization = {
            "comment": (
                "This module requires the first authorization endpoint visit to stop at "
                "the login page without authenticating."
            ),
            "match": match,
            "match-limit": 1,
            "tasks": [
                {
                    "task": "Observe first login page without authentication",
                    "match": nazo_ui_match(config_value, "auth"),
                    "commands": nazo_login_observation_commands(config_value),
                }
            ],
        }
        automation.append(first_authorization)

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        automation.append(second_authorization)

    return automation


def add_nazo_second_login_placeholder_overrides(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")

    browser_override = browser_automation_with_second_login_placeholder(config_value, browser)
    for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES:
        override.setdefault(module_name, {"browser": copy.deepcopy(browser_override)})


def add_nazo_par_reuse_before_auth_override(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    browser = config_value.get("browser")
    if not isinstance(browser, list):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")

    browser_override = first_login_observation_automation(config_value, browser)
    for module_name in FAPI_SECURITY_PAR_REUSE_BEFORE_AUTH_MODULES:
        override.setdefault(module_name, {"browser": copy.deepcopy(browser_override)})


def add_nazo_user_reject_override(config_value: dict[str, object]) -> None:
    if not config_uses_nazo_hosted_conformance_ui(config_value):
        return

    override = config_value.setdefault("override", {})
    if not isinstance(override, dict):
        fail("OIDF plan config override must be a JSON object when present")
    browser_override = nazo_user_reject_browser_automation(config_value)
    for module_name in FAPI_SECURITY_USER_REJECTS_AUTHENTICATION_MODULES:
        override.setdefault(module_name, {"browser": copy.deepcopy(browser_override)})


def add_nazo_browser_overrides(config_value: dict[str, object]) -> None:
    normalize_oidf_callback_waits(config_value)
    remove_default_login_page_placeholder_updates(config_value)
    add_login_page_clicks(config_value)
    add_authorization_error_response_capture(config_value)
    add_nazo_second_login_placeholder_overrides(config_value)
    add_nazo_par_reuse_before_auth_override(config_value)
    add_nazo_user_reject_override(config_value)
    use_nazo_user_facing_browser_commands(config_value)
    config_value.pop("nazo", None)


def write_plan_configs(
    suite_scripts: Path,
    file_name: str,
    env_name: str,
    config_json_file: str,
    target_issuer: str,
) -> tuple[set[str], dict[str, str]]:
    validate_config_file_name(file_name)
    raw_config = (
        non_empty_file(config_json_file, "--config-json-file")
        if config_json_file
        else non_empty_env(env_name)
    )
    try:
        parsed = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        source = config_json_file if config_json_file else env_name
        fail(f"{source} is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        source = config_json_file if config_json_file else env_name
        fail(f"{source} must contain a JSON object")

    configs = parsed.get("configs")
    if configs is None:
        if target_issuer:
            assert_only_auth_nazo_run_urls(parsed, file_name)
        add_nazo_browser_overrides(parsed)
        if target_issuer:
            assert_only_auth_nazo_run_urls(parsed, file_name)
        validate_browser_automation(file_name, parsed)
        target = suite_scripts / file_name
        atomic_write_json_file(target, parsed)
        aliases_by_config = {file_name: alias} if (alias := config_alias(parsed)) else {}
        return {file_name}, aliases_by_config

    if not isinstance(configs, dict) or not configs:
        fail(f"{env_name}.configs must contain a non-empty JSON object")

    written: set[str] = set()
    aliases_by_config: dict[str, str] = {}
    for config_name, config_value in configs.items():
        if not isinstance(config_name, str) or not config_name.strip():
            fail(f"{env_name}.configs contains an invalid file name")
        validate_config_file_name(config_name)
        if not isinstance(config_value, dict):
            fail(f"{env_name}.configs.{config_name} must contain a JSON object")
        if target_issuer:
            assert_only_auth_nazo_run_urls(config_value, config_name)
        add_nazo_browser_overrides(config_value)
        if target_issuer:
            assert_only_auth_nazo_run_urls(config_value, config_name)
        validate_browser_automation(config_name, config_value)
        alias = config_alias(config_value)
        if alias:
            aliases_by_config[config_name] = alias
        target = suite_scripts / config_name
        atomic_write_json_file(target, config_value)
        written.add(config_name)
    return written, aliases_by_config


def api_url(base_url: str, path: str, query: dict[str, str | int] | None = None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if query:
        return f"{url}?{urllib.parse.urlencode(query)}"
    return url


def oidf_api_request(
    method: str,
    base_url: str,
    path: str,
    token: str | None,
    *,
    query: dict[str, str | int] | None = None,
    expected_statuses: set[int],
) -> tuple[int, object | None]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        api_url(base_url, path, query),
        method=method,
        headers=headers,
    )
    attempts = 3
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(
                request,
                timeout=30,
                context=OIDF_API_SSL_CONTEXT,
            ) as response:
                status = response.status
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
            if status < 500 or attempt == attempts:
                break
            time.sleep(attempt * 2)
            continue
        except (urllib.error.URLError, http.client.RemoteDisconnected) as exc:
            last_error = exc
            if attempt == attempts:
                fail(f"OIDF API {method} {path} failed: {exc}")
            time.sleep(attempt * 2)
            continue
        break
    else:
        fail(f"OIDF API {method} {path} failed: {last_error}")

    if status not in expected_statuses:
        text = body.decode("utf-8", "replace")[:300] if body else ""
        fail(f"OIDF API {method} {path} failed with HTTP {status}: {text}")

    if not body:
        return status, None
    try:
        return status, json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return status, None


def is_runner_finalisation_error(payload: object | None) -> bool:
    if not isinstance(payload, dict):
        return False

    fields = [
        payload.get("message"),
        payload.get("error"),
        payload.get("exception"),
        payload.get("trace"),
    ]
    text = "\n".join(value for value in fields if isinstance(value, str))
    return "runInBackground called after runFinalisationTaskInBackground()" in text


def module_ids_from_plan(plan: dict[str, object]) -> set[str]:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return set()

    module_ids: set[str] = set()
    for module in modules:
        if not isinstance(module, dict):
            continue
        instances = module.get("instances")
        if not isinstance(instances, list):
            continue
        for instance_id in instances:
            if isinstance(instance_id, str) and instance_id:
                module_ids.add(instance_id)
    return module_ids


def plan_id(plan: dict[str, object]) -> str | None:
    value = plan.get("_id")
    return value if isinstance(value, str) and value else None


def plan_ids_from_aliases(base_url: str, token: str, aliases: set[str]) -> set[str]:
    return {
        value
        for plan in fetch_alias_plans(base_url, token, aliases)
        if (value := plan_id(plan)) is not None
    }


def value_as_upper(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().upper()


def redact_url_query_and_fragment(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    query = "redacted=1" if parsed.query else ""
    fragment = "redacted" if parsed.fragment else ""
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, query, fragment)
    )


def redact_log_text(value: str) -> str:
    redacted = re.sub(
        r"https?://[^\s\"'<>]+",
        lambda match: redact_url_query_and_fragment(match.group(0)),
        value,
    )
    return re.sub(
        r"(?i)\b(access_token|refresh_token|id_token|token|code|password|client_secret|request_uri|authorization)=([^&\s;]+)",
        lambda match: f"{match.group(1)}=<redacted>",
        redacted,
    )


def module_name_without_variant(test_name: str) -> str:
    return test_name.split("[", 1)[0]


def allowed_review_contexts_by_alias(
    aliases_by_config: dict[str, str],
) -> dict[str, tuple[str, frozenset[str]]]:
    return {
        alias: OIDF_ALLOWED_REVIEW_CONTEXTS_BY_CONFIG[config_name]
        for config_name, alias in aliases_by_config.items()
        if config_name in OIDF_ALLOWED_REVIEW_CONTEXTS_BY_CONFIG
    }


def is_allowed_review_module(
    test_name: str,
    alias: object,
    plan_name: object,
    allowed_reviews_by_alias: dict[str, tuple[str, frozenset[str]]],
) -> bool:
    if not isinstance(alias, str) or not isinstance(plan_name, str):
        return False
    allowed_context = allowed_reviews_by_alias.get(alias)
    if allowed_context is None:
        return False
    allowed_plan_name, allowed_modules = allowed_context
    return (
        plan_name == allowed_plan_name
        and module_name_without_variant(test_name) in allowed_modules
    )


def oidf_module_failure(
    info: object,
    allowed_reviews_by_alias: dict[str, tuple[str, frozenset[str]]] | None = None,
    plan_name: str | None = None,
) -> str | None:
    if not isinstance(info, dict):
        return None

    module_id = info.get("_id") or info.get("testId") or info.get("id") or "<unknown>"
    test_name_value = info.get("testName") or info.get("name") or "<unknown>"
    test_name = test_name_value if isinstance(test_name_value, str) else "<unknown>"
    status = value_as_upper(info.get("status"))
    result = value_as_upper(info.get("result"))
    error = info.get("error")

    if isinstance(error, str) and error.strip():
        return f"{test_name} {module_id} reported error: {error.strip()[:300]}"
    if isinstance(error, dict) and error:
        return f"{test_name} {module_id} reported a structured error"
    if status in OIDF_BAD_STATUS_VALUES:
        return f"{test_name} {module_id} status {status}"
    if result in OIDF_BAD_FINAL_RESULTS:
        return f"{test_name} {module_id} result {result}"
    if result == "REVIEW" and not is_allowed_review_module(
        test_name,
        info.get("alias"),
        plan_name,
        allowed_reviews_by_alias or {},
    ):
        return f"{test_name} {module_id} result REVIEW"

    return None


def oidf_info_failure_can_wait_for_final_result(info: object) -> bool:
    if not isinstance(info, dict):
        return False

    error = info.get("error")
    if isinstance(error, str) and error.strip():
        return False
    if isinstance(error, dict) and error:
        return False

    status = value_as_upper(info.get("status"))
    if status in OIDF_BAD_STATUS_VALUES:
        return False

    result = value_as_upper(info.get("result"))
    if result in OIDF_BAD_FINAL_RESULTS:
        return True

    return result == "REVIEW"


def oidf_log_failure(module_id: str, logs: object) -> str | None:
    if not isinstance(logs, list):
        return None

    for entry in logs:
        if not isinstance(entry, dict):
            continue
        result = value_as_upper(entry.get("result"))
        if result not in OIDF_BAD_LOG_RESULTS:
            continue
        src = entry.get("src")
        msg = entry.get("msg")
        src_text = src if isinstance(src, str) and src else "<unknown>"
        msg_text = msg if isinstance(msg, str) and msg else "<no message>"
        return f"{module_id} log {result} at {src_text}: {msg_text[:300]}"
    return None


def oidf_log_context(logs: object, *, max_entries: int = 6) -> str:
    if not isinstance(logs, list):
        return ""

    interesting: list[str] = []
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        src = entry.get("src")
        result = value_as_upper(entry.get("result"))
        if src not in OIDF_LOG_CONTEXT_SOURCES and result not in OIDF_BAD_LOG_RESULTS:
            continue

        parts: list[str] = []
        for key, value in oidf_log_context_values(entry):
            text = oidf_log_context_text(key, value)
            if text:
                parts.append(f"{key}={text[:180]}")
        if parts:
            interesting.append("; ".join(parts))

    if not interesting:
        return ""
    return " | ".join(interesting[-max_entries:])


def oidf_log_context_values(entry: dict[str, object]) -> list[tuple[str, object]]:
    values: list[tuple[str, object]] = []
    for key in OIDF_LOG_CONTEXT_FIELDS:
        if key in entry:
            values.append((key, entry[key]))

    args = entry.get("args")
    if isinstance(args, dict):
        for key in OIDF_LOG_CONTEXT_FIELDS:
            if key in args:
                values.append((key, args[key]))
    return values


def oidf_log_context_text(key: str, value: object) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    elif isinstance(value, (str, int, float, bool)):
        text = str(value)
    else:
        return ""

    text = text.replace("\n", " ").strip()
    if not text:
        return ""
    if key.lower() in OIDF_SENSITIVE_LOG_FIELDS:
        return "<redacted>"
    return redact_log_text(text)


def oidf_failure_with_log_context(module_id: str, failure: str, logs: object) -> str:
    context = oidf_log_context(logs)
    if not context:
        return failure
    return f"{failure}; recent log context: {context[:1200]}"


def fetch_alias_plans(base_url: str, token: str, aliases: set[str]) -> list[dict[str, object]]:
    if not aliases:
        return []

    start = 0
    length = 200
    matched: list[dict[str, object]] = []
    while True:
        _, payload = oidf_api_request(
            "GET",
            base_url,
            "api/plan",
            token,
            query={"start": start, "length": length},
            expected_statuses={200},
        )
        if not isinstance(payload, dict):
            return matched

        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            return matched

        for plan in plans:
            if not isinstance(plan, dict):
                continue
            config = plan.get("config")
            alias = config.get("alias") if isinstance(config, dict) else None
            if alias in aliases:
                matched.append(plan)

        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            return matched


def inspect_oidf_state(
    base_url: str,
    token: str,
    aliases: set[str],
    *,
    final: bool,
    ignored_plan_ids: set[str] | None = None,
    allowed_reviews_by_alias: dict[str, tuple[str, frozenset[str]]] | None = None,
) -> str | None:
    ignored = ignored_plan_ids or set()
    plans = [
        plan
        for plan in fetch_alias_plans(base_url, token, aliases)
        if plan_id(plan) not in ignored
    ]
    if not plans:
        return "OIDF monitor found no plan for current aliases" if final else None

    module_ids: set[str] = set()
    module_plan_names: dict[str, str] = {}
    for plan in plans:
        plan_module_ids = module_ids_from_plan(plan)
        module_ids.update(plan_module_ids)
        plan_name = plan.get("planName")
        if isinstance(plan_name, str):
            for module_id in plan_module_ids:
                existing_plan_name = module_plan_names.get(module_id)
                if existing_plan_name is not None and existing_plan_name != plan_name:
                    return f"{module_id} belongs to multiple OIDF plans"
                module_plan_names[module_id] = plan_name

    if not module_ids:
        return "OIDF monitor found no module instances for current plan" if final else None

    review_counts: dict[tuple[str, str, str], int] = {}
    for module_id in sorted(module_ids):
        status_code, info = oidf_api_request(
            "GET",
            base_url,
            f"api/info/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        if status_code == 200 and info is not None:
            result = value_as_upper(info.get("result")) if isinstance(info, dict) else ""
            if result == "REVIEW" and isinstance(info, dict):
                alias = info.get("alias")
                test_name_value = info.get("testName") or info.get("name") or "<unknown>"
                test_name = (
                    module_name_without_variant(test_name_value)
                    if isinstance(test_name_value, str)
                    else "<unknown>"
                )
                plan_name = module_plan_names.get(module_id)
                if isinstance(alias, str) and isinstance(plan_name, str):
                    review_key = (alias, plan_name, test_name)
                    review_counts[review_key] = review_counts.get(review_key, 0) + 1
                    if review_counts[review_key] > 1:
                        return (
                            f"{test_name} review baseline exceeded for {plan_name} "
                            f"alias {alias}: "
                            f"{review_counts[review_key]} instances"
                        )

            failure = oidf_module_failure(
                info,
                allowed_reviews_by_alias,
                module_plan_names.get(module_id),
            )
            if failure:
                _, logs = oidf_api_request(
                    "GET",
                    base_url,
                    f"api/log/{module_id}",
                    token,
                    expected_statuses={200, 404},
                )
                if oidf_log_failure(module_id, logs):
                    return oidf_failure_with_log_context(module_id, failure, logs)
                if not final and oidf_info_failure_can_wait_for_final_result(info):
                    continue
                return oidf_failure_with_log_context(module_id, failure, logs)
            status = value_as_upper(info.get("status")) if isinstance(info, dict) else ""
            if final and status and status != "FINISHED":
                return f"{module_id} ended with non-final status {status}"

        status_code, logs = oidf_api_request(
            "GET",
            base_url,
            f"api/log/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        if status_code == 200:
            failure = oidf_log_failure(module_id, logs)
            if failure:
                return failure

    return None


def ciba_config_has_automated_approval_url(config_json_file: str, env_name: str) -> bool:
    raw_config = (
        non_empty_file(config_json_file, "--config-json-file")
        if config_json_file
        else os.environ.get(env_name, "")
    )
    if not raw_config.strip():
        return False
    try:
        parsed = json.loads(raw_config)
    except json.JSONDecodeError:
        return False
    configs = parsed.get("configs") if isinstance(parsed, dict) else None
    candidates = configs.values() if isinstance(configs, dict) else [parsed]
    for value in candidates:
        if not isinstance(value, dict):
            continue
        alias = config_alias(value) or ""
        if "ciba" not in alias:
            continue
        automated_url = value.get("automated_ciba_approval_url")
        if isinstance(automated_url, str) and automated_url.strip():
            return True
    return False


def cancel_alias_plan_instances(
    base_url: str,
    token: str,
    aliases: set[str],
    ignored_plan_ids: set[str] | None = None,
) -> None:
    ignored = ignored_plan_ids or set()
    for plan in fetch_alias_plans(base_url, token, aliases):
        if plan_id(plan) in ignored:
            continue
        cancel_plan_module_instances(base_url, token, plan)


class OidfEarlyStopMonitor:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        aliases: set[str],
        interval_seconds: int,
        ignored_plan_ids: set[str],
        allowed_reviews_by_alias: dict[str, tuple[str, frozenset[str]]],
    ) -> None:
        self.base_url = base_url
        self.token = token
        self.aliases = aliases
        self.interval_seconds = interval_seconds
        self.ignored_plan_ids = ignored_plan_ids
        self.allowed_reviews_by_alias = allowed_reviews_by_alias
        self.stop_requested = threading.Event()
        self.failure_message: str | None = None
        self.consecutive_errors = 0

    def run(self, process: subprocess.Popen[bytes]) -> None:
        while not self.stop_requested.wait(self.interval_seconds):
            if process.poll() is not None:
                return

            try:
                failure = inspect_oidf_state(
                    self.base_url,
                    self.token,
                    self.aliases,
                    final=False,
                    ignored_plan_ids=self.ignored_plan_ids,
                    allowed_reviews_by_alias=self.allowed_reviews_by_alias,
                )
                self.consecutive_errors = 0
            except SystemExit as exc:
                self.consecutive_errors += 1
                print(f"OIDF early-stop monitor API error: {exc}", flush=True)
                if self.consecutive_errors < 3:
                    continue
                failure = "OIDF early-stop monitor could not read suite state after 3 attempts"

            if failure:
                self.failure_message = failure
                print(f"OIDF early stop: {failure}", flush=True)
                terminate_runner(process)
                try:
                    cancel_alias_plan_instances(
                        self.base_url,
                        self.token,
                        self.aliases,
                        ignored_plan_ids=self.ignored_plan_ids,
                    )
                except SystemExit as exc:
                    print(f"OIDF early-stop cleanup error: {exc}", flush=True)
                return

    def stop(self) -> None:
        self.stop_requested.set()


def alias_plan_matches(alias: str, plan: object) -> bool:
    if not isinstance(plan, dict):
        return False
    config = plan.get("config")
    plan_alias = config.get("alias") if isinstance(config, dict) else None
    return plan_alias == alias and plan.get("immutable") is not True


def cancel_plan_module_instances(base_url: str, token: str, plan: dict[str, object]) -> None:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return
    for module in modules:
        if not isinstance(module, dict):
            continue
        instances = module.get("instances")
        if not isinstance(instances, list):
            continue
        for instance_id in instances:
            if not isinstance(instance_id, str) or not instance_id:
                continue
            status, payload = oidf_api_request(
                "DELETE",
                base_url,
                f"api/runner/{instance_id}",
                token,
                expected_statuses={200, 404, 500},
            )
            if status == 200:
                print(f"Cancelled stale OIDF module instance {instance_id}", flush=True)
            elif status == 500:
                if not is_runner_finalisation_error(payload):
                    fail(f"OIDF API DELETE api/runner/{instance_id} failed with unexpected HTTP 500")
                print(
                    "Skipped stale OIDF module instance "
                    f"{instance_id}: conformance suite rejected runner cancellation",
                    flush=True,
                )


def cleanup_existing_alias_plans(base_url: str, token: str, aliases: set[str]) -> None:
    if not aliases:
        return

    while True:
        deleted = cleanup_existing_alias_plans_pass(base_url, token, aliases)
        if deleted == 0:
            return


def cleanup_existing_alias_plans_pass(base_url: str, token: str, aliases: set[str]) -> int:
    start = 0
    length = 200
    deleted = 0
    while True:
        _, payload = oidf_api_request(
            "GET",
            base_url,
            "api/plan",
            token,
            query={"start": start, "length": length},
            expected_statuses={200},
        )
        if not isinstance(payload, dict):
            return deleted

        plans = payload.get("data")
        if not isinstance(plans, list) or not plans:
            return deleted

        for plan in plans:
            if cleanup_alias_plan(base_url, token, aliases, plan):
                deleted += 1

        start += len(plans)
        total = payload.get("recordsTotal")
        if isinstance(total, int) and start >= total:
            return deleted


def cleanup_alias_plan(
    base_url: str,
    token: str,
    aliases: set[str],
    plan: object,
) -> bool:
    if not isinstance(plan, dict):
        return False
    config = plan.get("config")
    alias = config.get("alias") if isinstance(config, dict) else None
    plan_id = plan.get("_id")
    if alias not in aliases or not isinstance(plan_id, str):
        return False
    if plan.get("immutable") is True:
        print(f"Skipping immutable OIDF plan {plan_id} for alias {alias}", flush=True)
        return False

    status, _ = oidf_api_request(
        "DELETE",
        base_url,
        f"api/plan/{plan_id}",
        token,
        expected_statuses={200, 204, 404, 405},
    )
    if status in {200, 204}:
        print(f"Deleted stale mutable OIDF plan {plan_id} for alias {alias}", flush=True)
        return True

    cancel_plan_module_instances(base_url, token, plan)
    status, _ = oidf_api_request(
        "DELETE",
        base_url,
        f"api/plan/{plan_id}",
        token,
        expected_statuses={200, 204, 404, 405},
    )
    if status in {200, 204}:
        print(f"Deleted stale mutable OIDF plan {plan_id} for alias {alias}", flush=True)
        return True
    if status == 405:
        print(f"Skipped non-deletable OIDF plan {plan_id} for alias {alias}", flush=True)
    return False


def default_plan_expressions(config_names: set[str], fallback_config_name: str) -> list[str]:
    per_plan_config_names = {
        OIDCC_BASIC_CONFIG_FILE,
        OIDCC_DYNAMIC_CONFIG_FILE,
        OIDCC_CONFIG_CONFIG_FILE,
        FAPI_SECURITY_FINAL_CONFIG_FILE,
        FAPI_MESSAGE_FINAL_CONFIG_FILE,
        FAPI_SECURITY_ID2_CONFIG_FILE,
        FAPI_MESSAGE_ID1_CONFIG_FILE,
    }
    if per_plan_config_names.issubset(config_names):
        return PER_PLAN_CONFIG_EXPRESSIONS
    if {OIDCC_CONFIG_FILE, FAPI_CONFIG_FILE}.issubset(config_names):
        return DEFAULT_PLAN_EXPRESSIONS
    return [
        expression.replace(OIDCC_CONFIG_FILE, fallback_config_name).replace(
            FAPI_CONFIG_FILE, fallback_config_name
        )
        for expression in DEFAULT_PLAN_EXPRESSIONS
    ]


def plan_expressions(
    raw_expression: str,
    env_name: str,
    plan_set_json_file: str,
    config_names: set[str],
    fallback_config_name: str,
) -> list[str]:
    raw_plan_set = (
        non_empty_file(plan_set_json_file, "--plan-set-json-file")
        if plan_set_json_file
        else os.environ.get(env_name, "")
    ).strip()
    if raw_expression.strip():
        expressions = [raw_expression.strip()]
    elif raw_plan_set:
        try:
            parsed = json.loads(raw_plan_set)
        except json.JSONDecodeError as exc:
            source = plan_set_json_file if plan_set_json_file else env_name
            fail(f"{source} is not valid JSON: {exc}")
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            source = plan_set_json_file if plan_set_json_file else env_name
            fail(f"{source} must contain a JSON array of plan expression strings")
        expressions = [item.strip() for item in parsed if item.strip()]
    else:
        expressions = default_plan_expressions(config_names, fallback_config_name)

    if not expressions:
        fail("at least one OIDF plan expression is required")
    for expression in expressions:
        parts = shlex.split(expression)
        if not parts:
            fail("OIDF plan expression must not be empty")
        if not any(config_name in parts for config_name in config_names):
            fail(
                "OIDF plan expression must reference one of "
                f"{sorted(config_names)}: {expression}"
            )
    return expressions


def config_names_from_plan_expressions(
    expressions: list[str],
    config_names: set[str],
) -> set[str]:
    selected: set[str] = set()
    for expression in expressions:
        parts = shlex.split(expression)
        selected.update(config_name for config_name in config_names if config_name in parts)
    return selected


def validate_rerun_argument(value: str) -> None:
    for item in value.split(","):
        item = item.strip()
        if not item:
            fail("--rerun must contain comma-separated plan numbers or plan:module selectors")

        if ":" not in item:
            if not item.isdigit():
                fail(f"--rerun selector must be a positive integer plan number: {item}")
            continue

        plan_number, module_number = item.split(":", 1)
        if not plan_number.isdigit() or not module_number.isdigit():
            fail(
                "--rerun module selector must use the official plan:module syntax, "
                f"for example 1:41; ranges such as {item} are not supported"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute the official OpenID Foundation conformance-suite runner."
    )
    parser.add_argument("--suite-dir", required=True, help="Path to the cloned conformance-suite repository")
    parser.add_argument("--conformance-server", required=True, help="Base URL of the conformance suite")
    parser.add_argument("--plan-expression", default="", help="single run-test-plan.py plan expression")
    parser.add_argument("--plan-set-env", default="OIDF_PLAN_SET_JSON")
    parser.add_argument(
        "--plan-set-json-file",
        default="",
        help="read the JSON array of plan expressions from this file instead of --plan-set-env",
    )
    parser.add_argument("--config-env", default="OIDF_PLAN_CONFIG_JSON")
    parser.add_argument(
        "--config-json-file",
        default="",
        help="read the plan configuration JSON object from this file instead of --config-env",
    )
    parser.add_argument("--config-file-name", default="oidf-plan-config.json")
    parser.add_argument(
        "--target-issuer",
        default=os.environ.get("OIDF_TARGET_ISSUER", ""),
        help=f"expected issuer origin; Nazo URLs must use {NAZO_PUBLIC_ISSUER_ORIGIN}",
    )
    parser.add_argument("--token-env", default="OIDF_CONFORMANCE_TOKEN")
    parser.add_argument(
        "--no-api-token",
        action="store_true",
        help=(
            "do not send a conformance API bearer token; intended only for "
            "local devmode conformance-suite instances"
        ),
    )
    parser.add_argument("--export-dir", default="")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--disable-ssl-verify", action="store_true")
    parser.add_argument("--no-parallel", action="store_true")
    parser.add_argument(
        "--expected-failures-file",
        default="",
        help="pass through the official runner expected failures/warnings JSON file",
    )
    parser.add_argument(
        "--expected-skips-file",
        default="",
        help="pass through the official runner expected skipped tests JSON file",
    )
    parser.add_argument(
        "--rerun",
        default="",
        help=(
            "pass through the official runner --rerun filter; use plan numbers "
            "or plan:module selectors, for example 1 or 1:41 or 1:41,1:42"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=10_800,
        help="maximum runtime for the official conformance runner",
    )
    parser.add_argument(
        "--monitor-interval-seconds",
        type=int,
        default=60,
        help="poll OIDF APIs at this interval and stop early on failed module state; set 0 to disable",
    )
    parser.add_argument("--list", action="store_true", help="list selected plans without running them")
    return parser.parse_args()


def run_official_runner(
    command: list[str],
    expressions: list[str],
    suite_scripts: Path,
    env: dict[str, str],
    timeout_seconds: int,
    conformance_server: str,
    aliases: set[str],
    token: str | None,
    monitor_interval_seconds: int,
    allowed_reviews_by_alias: dict[str, tuple[str, frozenset[str]]],
) -> int:
    if timeout_seconds <= 0:
        fail("--timeout-seconds must be greater than zero")
    if monitor_interval_seconds < 0:
        fail("--monitor-interval-seconds must be zero or greater")

    print("OIDF selected plan expressions:", flush=True)
    for index, expression in enumerate(expressions, start=1):
        print(f"  {index}. {expression}", flush=True)
    print("OIDF official runner argv:", flush=True)
    for index, argument in enumerate(command):
        print(f"  argv[{index}]: {argument}", flush=True)
    print(f"OIDF official runner timeout: {timeout_seconds} seconds", flush=True)

    ignored_plan_ids = plan_ids_from_aliases(conformance_server, token, aliases) if aliases else set()
    process = subprocess.Popen(
        command,
        cwd=suite_scripts,
        env=env,
        start_new_session=True,
    )
    monitor: OidfEarlyStopMonitor | None = None
    monitor_thread: threading.Thread | None = None
    if aliases and monitor_interval_seconds > 0:
        monitor = OidfEarlyStopMonitor(
            conformance_server,
            token,
            aliases,
            monitor_interval_seconds,
            ignored_plan_ids,
            allowed_reviews_by_alias,
        )
        monitor_thread = threading.Thread(
            target=monitor.run,
            args=(process,),
            name="oidf-early-stop-monitor",
            daemon=True,
        )
        print(
            f"OIDF early-stop monitor interval: {monitor_interval_seconds} seconds",
            flush=True,
        )
        monitor_thread.start()
    elif aliases:
        print("OIDF early-stop monitor disabled", flush=True)

    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print("OIDF official runner timed out; terminating process group", flush=True)
        terminate_runner(process)
        return 124
    finally:
        if monitor is not None:
            monitor.stop()
        if monitor_thread is not None:
            monitor_thread.join(timeout=5)

    if monitor is not None and monitor.failure_message:
        return 1

    if exit_code != 0:
        return exit_code

    if aliases:
        final_failure = inspect_oidf_state(
            conformance_server,
            token,
            aliases,
            final=exit_code == 0,
            ignored_plan_ids=ignored_plan_ids,
            allowed_reviews_by_alias=allowed_reviews_by_alias,
        )
        if final_failure:
            print(f"OIDF final state check failed: {final_failure}", flush=True)
            return 1

    return exit_code


def terminate_runner(process: subprocess.Popen[bytes]) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
            return
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return

    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def ensure_pinned_oidf_runner(suite_dir: Path) -> None:
    patcher = Path(__file__).resolve().with_name("apply_oidf_runner_patch.py")
    subprocess.run(
        [sys.executable, str(patcher), "--suite-dir", str(suite_dir)],
        check=True,
    )


def official_runner_command(suite_scripts: Path, runner: Path) -> list[str]:
    bootstrap = (
        "import runpy,sys,sysconfig;"
        "paths=sysconfig.get_paths();"
        "sys.path.extend(dict.fromkeys([paths['purelib'],paths['platlib']]));"
        "suite_scripts=sys.argv.pop(1);runner=sys.argv.pop(1);"
        "sys.path.insert(0,suite_scripts);sys.argv[0]=runner;"
        "runpy.run_path(runner,run_name='__main__')"
    )
    return [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-u",
        "-c",
        bootstrap,
        str(suite_scripts),
        str(runner),
    ]


def sanitized_runner_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("PYTHON")
    }


def main() -> int:
    global OIDF_API_SSL_CONTEXT
    args = parse_args()
    if args.rerun:
        validate_rerun_argument(args.rerun)
    if args.disable_ssl_verify:
        OIDF_API_SSL_CONTEXT = ssl._create_unverified_context()
    target_issuer = normalized_origin(args.target_issuer) if args.target_issuer.strip() else ""

    suite_dir = Path(args.suite_dir).resolve()
    ensure_pinned_oidf_runner(suite_dir)
    suite_scripts = suite_dir / "scripts"
    runner = suite_scripts / "run-test-plan.py"
    if not runner.is_file():
        fail(f"official runner not found: {runner}")

    config_names, aliases_by_config = write_plan_configs(
        suite_scripts,
        args.config_file_name,
        args.config_env,
        args.config_json_file,
        target_issuer,
    )
    expressions = plan_expressions(
        args.plan_expression,
        args.plan_set_env,
        args.plan_set_json_file,
        config_names,
        args.config_file_name,
    )
    selected_config_names = config_names_from_plan_expressions(expressions, config_names)
    aliases = {
        alias
        for config_name, alias in aliases_by_config.items()
        if config_name in selected_config_names
    }

    env = sanitized_runner_environment()
    env["CONFORMANCE_SERVER"] = args.conformance_server
    token = None if args.no_api_token else non_empty_env(args.token_env)
    if token is not None:
        env["CONFORMANCE_TOKEN"] = token
    else:
        env.pop("CONFORMANCE_TOKEN", None)
        env["CONFORMANCE_DEV_MODE"] = "1"
    if args.disable_ssl_verify:
        env["DISABLE_SSL_VERIFY"] = "1"

    if not args.list and not args.rerun:
        cleanup_existing_alias_plans(args.conformance_server, token, aliases)

    command = official_runner_command(suite_scripts, runner)
    if args.list:
        command.append("--list")
    if args.no_parallel:
        command.append("--no-parallel")
    if args.rerun:
        command.extend(["--rerun", args.rerun])
    if args.expected_failures_file:
        expected_failures_file = Path(args.expected_failures_file).resolve()
        command.extend(["--expected-failures-file", str(expected_failures_file)])
    if args.expected_skips_file:
        expected_skips_file = Path(args.expected_skips_file).resolve()
        command.extend(["--expected-skips-file", str(expected_skips_file)])
    if args.export_dir:
        export_dir = Path(args.export_dir).resolve()
        export_dir.mkdir(parents=True, exist_ok=True)
        command.extend(["--export-dir", str(export_dir)])
    if args.verbose:
        command.append("--verbose")
    for expression in expressions:
        command.extend(shlex.split(expression))

    monitor_aliases = set() if args.list else aliases
    if monitor_aliases and any("ciba" in alias for alias in monitor_aliases):
        if not ciba_config_has_automated_approval_url(args.config_json_file, args.config_env):
            fail(
                "FAPI-CIBA conformance automation requires automated_ciba_approval_url "
                "so the official suite controls approve/deny timing"
            )

    return run_official_runner(
        command,
        expressions,
        suite_scripts,
        env,
        args.timeout_seconds,
        args.conformance_server,
        monitor_aliases,
        token,
        args.monitor_interval_seconds,
        allowed_review_contexts_by_alias(aliases_by_config),
    )


if __name__ == "__main__":
    raise SystemExit(main())
