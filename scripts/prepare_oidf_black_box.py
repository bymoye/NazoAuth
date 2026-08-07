#!/usr/bin/env python3
"""Materialize runner inputs for public black-box OIDF conformance."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import copy
import base64
import hashlib
import ipaddress
import re
import secrets
import ssl
import sys
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from oidf_secret_input import (  # noqa: E402
    SecretInputError,
    add_secret_source_arguments,
    read_secret_document,
)


PREPARATION_SECRET_FIELDS = (
    "oidf_applicant_email",
    "oidf_applicant_password",
    "oidf_dynamic_registration_initial_access_token",
    "oidf_ciba_automated_decision_token",
)


def configure_operator_secrets(args: argparse.Namespace) -> None:
    global USER_EMAIL
    global USER_PASSWORD
    global CLIENT_SECRET
    global DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN
    global OIDF_CIBA_AUTOMATED_DECISION_TOKEN

    operator_secrets = read_secret_document(
        args,
        required_fields=PREPARATION_SECRET_FIELDS,
    )
    USER_EMAIL = operator_secrets["oidf_applicant_email"]
    USER_PASSWORD = operator_secrets["oidf_applicant_password"]
    CLIENT_SECRET = secrets.token_urlsafe(32)
    DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN = operator_secrets[
        "oidf_dynamic_registration_initial_access_token"
    ]
    OIDF_CIBA_AUTOMATED_DECISION_TOKEN = operator_secrets[
        "oidf_ciba_automated_decision_token"
    ]


def runtime_directory() -> Path:
    configured = os.environ.get("OIDF_RUNTIME_DIR", "").strip()
    return Path(configured).resolve() if configured else ROOT / "runtime" / "oidf"


RUNTIME = runtime_directory()


def required_origin_env(name: str) -> str:
    value = os.environ.get(name, "").strip().rstrip("/")
    if not value:
        raise RuntimeError(f"{name} is required; do not rely on a repository default issuer")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
        raise RuntimeError(f"{name} must be an HTTPS origin without a path")
    return value


ISSUER = required_origin_env("OIDF_TARGET_ISSUER")
MTLS_ISSUER = os.environ.get("OIDF_MTLS_TARGET_ISSUER", ISSUER).strip().rstrip("/")
parsed_mtls = urllib.parse.urlsplit(MTLS_ISSUER)
if parsed_mtls.scheme != "https" or not parsed_mtls.netloc or parsed_mtls.path not in ("", "/"):
    raise RuntimeError("OIDF_MTLS_TARGET_ISSUER must be an HTTPS origin without a path")
SUITE_BASE_URL = (
    os.environ.get("OIDF_SUITE_BASE_URL")
    or ""
).strip().rstrip("/")
if not SUITE_BASE_URL:
    raise RuntimeError(
        "OIDF_SUITE_BASE_URL is required; suite-private hostnames are not repository defaults"
    )
parsed_suite = urllib.parse.urlsplit(SUITE_BASE_URL)
if parsed_suite.scheme != "https" or not parsed_suite.netloc or parsed_suite.path not in ("", "/"):
    raise RuntimeError("OIDF_SUITE_BASE_URL must be an HTTPS origin without a path")
suite_host = parsed_suite.hostname or ""
try:
    ipaddress.ip_address(suite_host)
except ValueError:
    if suite_host.lower() == "localhost" or suite_host.lower().endswith(".local"):
        raise RuntimeError("OIDF_SUITE_BASE_URL must use a public DNS hostname")
else:
    raise RuntimeError("OIDF_SUITE_BASE_URL must use a public DNS hostname, not a raw IP")
SUITE_ORIGIN = urllib.parse.urlsplit(SUITE_BASE_URL)._replace(path="", query="", fragment="").geturl()
ISSUER_HOST = urllib.parse.urlsplit(ISSUER).hostname
if not ISSUER_HOST:
    raise RuntimeError("OIDF_TARGET_ISSUER must be an HTTPS origin with a hostname")
def oidf_run_namespace() -> str:
    explicit = os.environ.get("OIDF_RUN_NAMESPACE", "").strip().lower()
    namespace = explicit or f"bb-{hashlib.sha256(SUITE_ORIGIN.encode('utf-8')).hexdigest()[:12]}"
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", namespace):
        raise RuntimeError(
            "OIDF_RUN_NAMESPACE must contain 1-32 lowercase letters, digits, or internal hyphens"
        )
    if namespace in {"official", "oidf", "production"}:
        raise RuntimeError("OIDF_RUN_NAMESPACE is reserved and cannot identify an operator run")
    return namespace


RUN_NAMESPACE = oidf_run_namespace()
OIDF_CLIENT_PREFIX = f"oidf-{RUN_NAMESPACE}"
BASIC_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-basic-client"
BASIC_CLIENT2_ID = f"{OIDF_CLIENT_PREFIX}-basic-client-2"
FORMPOST_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-post-client"
RP_INITIATED_LOGOUT_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-rp-initiated-logout-client"
BACKCHANNEL_LOGOUT_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-backchannel-logout-client"
FRONTCHANNEL_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-frontchannel-client"
SESSION_CLIENT_ID = f"{OIDF_CLIENT_PREFIX}-session-client"
BASIC_ALIAS = os.environ.get(
    "OIDF_BASIC_ALIAS", f"nazo-oauth-oidf-{RUN_NAMESPACE}"
)


def run_scoped_alias(slug: str) -> str:
    """Return a plan alias owned by this isolated conformance run."""
    return f"nazo-oauth-oidf-{RUN_NAMESPACE}-{slug}"


USER_EMAIL = ""
USER_PASSWORD = ""
CLIENT_SECRET = ""
DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN = ""
OIDF_CIBA_AUTOMATED_DECISION_TOKEN = ""
FAPI_CLIENT_PREFIX = os.environ.get(
    "OIDF_FAPI_CLIENT_PREFIX", f"{OIDF_CLIENT_PREFIX}-fapi"
)
OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES = (
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)
OIDCC_AUTHORIZATION_ERROR_MODULES = (
    "oidcc-ensure-registered-redirect-uri",
    "oidcc-ensure-redirect-uri-in-authorization-request",
    "oidcc-redirect-uri-query-mismatch",
    "oidcc-redirect-uri-query-added",
)
FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-id2-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-final-user-rejects-authentication"
)
FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-id2-user-rejects-authentication"
)
PLAN_CONFIG_FILES = (
    "oidf-oidcc-basic-plan-config.json",
    "oidf-oidcc-dynamic-plan-config.json",
    "oidf-oidcc-formpost-plan-config.json",
    "oidf-oidcc-third-party-init-plan-config.json",
    "oidf-oidcc-config-plan-config.json",
    "oidf-oidcc-rp-initiated-logout-plan-config.json",
    "oidf-oidcc-backchannel-logout-plan-config.json",
    "oidf-oidcc-frontchannel-logout-plan-config.json",
    "oidf-oidcc-session-management-plan-config.json",
    "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json",
    "oidf-fapi-ciba-plain-mtls-poll-plan-config.json",
    "oidf-fapi-ciba-plain-private-key-jwt-ping-plan-config.json",
    "oidf-fapi-ciba-plain-mtls-ping-plan-config.json",
    "oidf-fapi-security-final-plan-config.json",
    "oidf-fapi-message-final-plan-config.json",
    "oidf-fapi-security-id2-plan-config.json",
    "oidf-fapi-message-id1-plan-config.json",
)
FAPI_MATRIX_CLIENT_AUTHS = ("private_key_jwt", "mtls")
FAPI_MATRIX_SENDER_CONSTRAINS = ("dpop", "mtls")
FAPI_MATRIX_OPENID_MODES = ("plain_oauth", "openid_connect")
NAZO_LOGIN_EMAIL_ID = "nazo-login-email"
NAZO_LOGIN_PASSWORD_ID = "nazo-login-password"
NAZO_LOGIN_SUBMIT_ID = "nazo-login-submit"
NAZO_LOGIN_SUBMIT_READY_SELECTOR = f"#{NAZO_LOGIN_SUBMIT_ID}:not([disabled])"
NAZO_CONSENT_APPROVE_ID = "nazo-consent-approve"
NAZO_CONSENT_DENY_ID = "nazo-consent-deny"
OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS = max(
    30,
    int(os.environ.get("OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS", "30")),
)
NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN = (
    r'("error"\s*:\s*"(invalid_request|invalid_request_object|access_denied|login_required|server_error)"'
    r"|invalid_request|invalid_request_object|access_denied|login_required|server_error)"
)


def login_commands(*, capture_placeholder: bool = False) -> list[list[object]]:
    commands: list[list[object]] = [
        ["wait-element-visible", "id", NAZO_LOGIN_EMAIL_ID, 30],
        ["wait-element-visible", "id", NAZO_LOGIN_PASSWORD_ID, 30],
        ["text", "id", NAZO_LOGIN_EMAIL_ID, USER_EMAIL],
        ["text", "id", NAZO_LOGIN_PASSWORD_ID, USER_PASSWORD],
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


def consent_approve_commands() -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_APPROVE_ID, 30],
        ["click", "id", NAZO_CONSENT_APPROVE_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS],
    ]


def consent_deny_commands() -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_DENY_ID, 30],
        ["click", "id", NAZO_CONSENT_DENY_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS],
    ]


def write_text(path: Path, body: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def ensure_mtls_ca() -> None:
    cert_dir = RUNTIME / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "mtls-ca.key"
    ca_cert = cert_dir / "mtls-ca.crt"
    if not ca_key.is_file() or not ca_cert.is_file():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-subj",
                "/CN=Nazo OAuth OIDF mTLS CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ca_key.chmod(0o600)


def ensure_mtls_certs() -> None:
    ensure_mtls_ca()
    for name in ("mtls-client-1", "mtls-client-2"):
        ensure_mtls_client_cert(name)


def ensure_mtls_client_cert(name: str) -> None:
    ensure_mtls_ca()
    cert_dir = RUNTIME / "certs"
    ca_key = cert_dir / "mtls-ca.key"
    ca_cert = cert_dir / "mtls-ca.crt"
    key = cert_dir / f"{name}.key"
    csr = cert_dir / f"{name}.csr"
    cert = cert_dir / f"{name}.crt"
    if key.is_file() and cert.is_file():
        return
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={name}",
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "3650",
            "-out",
            str(cert),
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    csr.unlink(missing_ok=True)


def mtls_config(index: int) -> dict[str, str]:
    return mtls_named_config(f"mtls-client-{index}")


def mtls_client_cert_name(client_id: str) -> str:
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:24]
    return f"mtls-{digest}"


def mtls_named_config(name: str) -> dict[str, str]:
    ensure_mtls_client_cert(name)
    cert_dir = RUNTIME / "certs"
    return {
        "cert": (cert_dir / f"{name}.crt").read_text(encoding="utf-8"),
        "key": (cert_dir / f"{name}.key").read_text(encoding="utf-8"),
        "ca": (cert_dir / "mtls-ca.crt").read_text(encoding="utf-8"),
    }


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def openssl_hex_field(text: str, label: str) -> bytes:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{label}:":
            hex_lines: list[str] = []
            for candidate in lines[index + 1 :]:
                stripped = candidate.strip()
                if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2})*:?", stripped):
                    break
                hex_lines.append(stripped)
            if not hex_lines:
                break
            raw = bytes.fromhex("".join(line.replace(":", "") for line in hex_lines))
            return raw[1:] if len(raw) > 1 and raw[0] == 0 else raw
    else:
        raise RuntimeError(f"openssl rsa output is missing {label}")
    raise RuntimeError(f"openssl rsa output is missing {label}")


def openssl_public_exponent(text: str) -> bytes:
    match = re.search(r"publicExponent:\s+(\d+)", text)
    if match is None:
        raise RuntimeError("openssl rsa output is missing publicExponent")
    return int(match.group(1)).to_bytes(3, "big")


def generate_rsa_jwk(kid: str) -> dict[str, str]:
    key_dir = RUNTIME / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    pem = key_dir / f"{kid}.pem"
    if not pem.is_file():
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(pem),
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pem.chmod(0o600)
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(pem), "-text", "-noout"],
        check=True,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    text = result.stdout
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "PS256",
        "n": b64url(openssl_hex_field(text, "modulus")),
        "e": b64url(openssl_public_exponent(text)),
        "d": b64url(openssl_hex_field(text, "privateExponent")),
        "p": b64url(openssl_hex_field(text, "prime1")),
        "q": b64url(openssl_hex_field(text, "prime2")),
        "dp": b64url(openssl_hex_field(text, "exponent1")),
        "dq": b64url(openssl_hex_field(text, "exponent2")),
        "qi": b64url(openssl_hex_field(text, "coefficient")),
    }


def client_private_jwks(client_id: str) -> dict[str, object]:
    path = RUNTIME / "keys" / f"{client_id}-jwks.json"
    jwks = {"keys": [generate_rsa_jwk(f"{client_id}-ps256")]}
    write_text(path, json.dumps(jwks, indent=2) + "\n", 0o600)
    return jwks


def public_jwks(private_jwks: dict[str, object]) -> dict[str, object]:
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    keys = []
    for key in private_jwks.get("keys", []):
        if isinstance(key, dict):
            keys.append({name: value for name, value in key.items() if name not in private_fields})
    return {"keys": keys}


def certificate_subject_dn(certificate_pem: str) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
        input=certificate_pem,
        check=True,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    subject = result.stdout.strip()
    if subject.startswith("subject="):
        subject = subject[len("subject=") :].strip()
    if not subject or "\n" in subject or "\r" in subject:
        raise RuntimeError("generated mTLS certificate has no canonical subject DN")
    return subject


def certificate_sha256(certificate_pem: str) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(certificate_pem)
    except ValueError as error:
        raise RuntimeError(f"OIDF mTLS client certificate is malformed: {error}") from error
    return hashlib.sha256(der).hexdigest()


def base_client_request(
    *,
    name: str,
    auth_method: str,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str] | None = None,
    scopes: list[str] | None = None,
    grant_types: list[str] | None = None,
) -> dict[str, object]:
    return {
        "client_name": name,
        "client_type": "confidential",
        "redirect_uris": sorted(set(redirect_uris)),
        "post_logout_redirect_uris": sorted(set(post_logout_redirect_uris or [])),
        "scopes": scopes
        or ["openid", "profile", "email", "address", "phone", "offline_access"],
        "allowed_audiences": sorted(
            {
                "resource://default",
                f"{ISSUER}/userinfo",
                f"{ISSUER}/fapi/resource",
                f"{MTLS_ISSUER}/fapi/resource",
            }
        ),
        "grant_types": grant_types or ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": auth_method,
        "require_dpop_bound_tokens": False,
        "require_mtls_bound_tokens": False,
        "allow_client_assertion_audience_array": False,
        "allow_client_assertion_endpoint_audience": False,
        "require_par_request_object": False,
        "backchannel_token_delivery_mode": "poll",
        "backchannel_user_code_parameter": False,
        # Both OpenID Connect logout specifications define false as the
        # default when the related session-required metadata is omitted.
        "backchannel_logout_session_required": False,
        "frontchannel_logout_session_required": False,
        # OIDC Core does not require PKCE for a confidential client. These
        # clients are short-lived and lease-owned; production clients retain
        # the secure PKCE-required default unless an operator explicitly opts
        # them into the same compatibility policy.
        "security_policy": {
            "version": 1,
            "allow_confidential_oidc_without_pkce": True,
        },
        "jwks": None,
    }


def onboarding_clients(configs: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    requests: dict[str, dict[str, object]] = {}

    def add(logical_client_id: str, request: dict[str, object], ca_pem: str | None = None) -> None:
        candidate = {
            "logical_client_id": logical_client_id,
            "request": request,
            "mtls_trust_anchor_pem": ca_pem,
        }
        previous = requests.get(logical_client_id)
        if previous is not None and previous != candidate:
            raise RuntimeError(f"conflicting onboarding policy for {logical_client_id}")
        requests[logical_client_id] = candidate

    basic_aliases = [BASIC_ALIAS, f"{BASIC_ALIAS}-formpost"]
    basic_callbacks = [callback_for(alias) for alias in basic_aliases]
    add(
        BASIC_CLIENT_ID,
        base_client_request(
            name="OIDF Basic Client",
            auth_method="client_secret_basic",
            redirect_uris=basic_callbacks,
        ),
    )
    add(
        BASIC_CLIENT2_ID,
        base_client_request(
            name="OIDF Basic Client 2",
            auth_method="client_secret_basic",
            redirect_uris=basic_callbacks,
        ),
    )
    add(
        FORMPOST_CLIENT_ID,
        base_client_request(
            name="OIDF Form Post Client",
            auth_method="client_secret_post",
            redirect_uris=basic_callbacks,
        ),
    )

    rp_initiated_alias = f"{BASIC_ALIAS}-rp-initiated-logout"
    add(
        RP_INITIATED_LOGOUT_CLIENT_ID,
        base_client_request(
            name="OIDF RP-Initiated Logout Client",
            auth_method="client_secret_basic",
            redirect_uris=[callback_for(rp_initiated_alias)],
            post_logout_redirect_uris=[
                test_endpoint_for(rp_initiated_alias, "post_logout_redirect")
            ],
        ),
    )

    backchannel_alias = f"{BASIC_ALIAS}-backchannel-logout"
    backchannel_request = base_client_request(
        name="OIDF Back-Channel Logout Client",
        auth_method="client_secret_basic",
        redirect_uris=[callback_for(backchannel_alias)],
        post_logout_redirect_uris=[
            test_endpoint_for(backchannel_alias, "post_logout_redirect")
        ],
    )
    backchannel_request["backchannel_logout_uri"] = test_endpoint_for(
        backchannel_alias, "backchannel_logout"
    )
    backchannel_request["backchannel_logout_session_required"] = True
    add(BACKCHANNEL_LOGOUT_CLIENT_ID, backchannel_request)

    frontchannel_alias = f"{BASIC_ALIAS}-frontchannel-logout"
    frontchannel_request = base_client_request(
        name="OIDF Front-Channel Logout Client",
        auth_method="client_secret_basic",
        redirect_uris=[callback_for(frontchannel_alias)],
        post_logout_redirect_uris=[test_endpoint_for(frontchannel_alias, "post_logout_redirect")],
    )
    frontchannel_request["frontchannel_logout_uri"] = test_endpoint_for(
        frontchannel_alias, "frontchannel_logout"
    )
    frontchannel_request["frontchannel_logout_session_required"] = True
    add(FRONTCHANNEL_CLIENT_ID, frontchannel_request)

    session_alias = f"{BASIC_ALIAS}-session-management"
    session_request = base_client_request(
        name="OIDF Session Management Client",
        auth_method="client_secret_basic",
        redirect_uris=[callback_for(session_alias)],
        post_logout_redirect_uris=[test_endpoint_for(session_alias, "post_logout_redirect")],
    )
    session_request["security_policy"]["session_management"] = True
    add(SESSION_CLIENT_ID, session_request)

    for file_name, config in sorted(configs.items()):
        if not file_name.startswith("oidf-fapi-"):
            continue
        nazo = config.get("nazo")
        if not isinstance(nazo, dict):
            raise RuntimeError(f"{file_name}.nazo is required for FAPI onboarding")
        alias = str(config["alias"])
        ciba = file_name.startswith("oidf-fapi-ciba-")
        auth_type = str(nazo.get("client_auth_type", "private_key_jwt"))
        sender_constrain = str(nazo.get("sender_constrain", "mtls" if ciba else "dpop"))
        fapi_profile = str(nazo.get("fapi_profile", "plain_fapi"))
        response_mode = str(nazo.get("fapi_response_mode", "plain_response"))
        auth_method = "tls_client_auth" if auth_type == "mtls" else "private_key_jwt"
        for key, mtls_key in (("client", "mtls"), ("client2", "mtls2")):
            client = config.get(key)
            mtls = config.get(mtls_key)
            if not isinstance(client, dict) or not isinstance(mtls, dict):
                raise RuntimeError(f"{file_name} is missing {key}/{mtls_key} material")
            logical_client_id = str(client["client_id"])
            callback = callback_for(alias)
            request = base_client_request(
                name=f"OIDF FAPI Client {logical_client_id}",
                auth_method=auth_method,
                redirect_uris=[callback, f"{callback}?dummy1=lorem&dummy2=ipsum"],
                scopes=str(client.get("scope", "")).split(),
                grant_types=(
                    ["client_credentials"]
                    if fapi_profile == "fapi_client_credentials_grant"
                    else ["urn:openid:params:grant-type:ciba", "refresh_token"]
                    if ciba
                    else ["authorization_code", "refresh_token"]
                ),
            )
            request["jwks"] = public_jwks(client["jwks"])
            request["require_dpop_bound_tokens"] = sender_constrain == "dpop"
            request["require_mtls_bound_tokens"] = sender_constrain == "mtls"
            request["allow_client_assertion_audience_array"] = "-id" in file_name
            request["allow_client_assertion_endpoint_audience"] = (
                ciba and auth_method == "private_key_jwt"
            )
            request["require_par_request_object"] = (
                ciba
                or "-message-" in file_name
                or nazo.get("fapi_request_method") is not None
            )
            request["authorization_signed_response_alg"] = (
                "PS256" if response_mode == "jarm" else None
            )
            request["backchannel_token_delivery_mode"] = str(
                client.get("backchannel_token_delivery_mode", "poll")
            )
            request["backchannel_client_notification_endpoint"] = client.get(
                "backchannel_client_notification_endpoint"
            )
            request["backchannel_authentication_request_signing_alg"] = client.get(
                "backchannel_authentication_request_signing_alg"
            )
            request["security_policy"] = {
                "version": 1,
                "assurance": "fapi2",
                "require_signed_authorization_request": "-message-" in file_name,
                "require_signed_authorization_response": response_mode == "jarm",
                "allow_cross_device_flows": ciba,
            }
            certificate_pem = str(mtls["cert"])
            ca_pem = str(mtls["ca"])
            if auth_method == "tls_client_auth":
                request["tls_client_auth_subject_dn"] = certificate_subject_dn(certificate_pem)
                request["tls_client_auth_cert_sha256"] = certificate_sha256(certificate_pem)
            add(
                logical_client_id,
                request,
                ca_pem if auth_method == "tls_client_auth" or sender_constrain == "mtls" else None,
            )
    return [requests[key] for key in sorted(requests)]


def callback_for(alias: str) -> str:
    return test_endpoint_for(alias, "callback")


def test_endpoint_for(alias: str, endpoint: str) -> str:
    return f"{SUITE_BASE_URL}/test/a/{alias}/{endpoint.lstrip('/')}"


def mark_login_page_wait_as_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    if task.get("match") == f"{ISSUER}/ui/auth*":
        task["commands"] = login_commands(capture_placeholder=True)
        return

    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 5:
            continue
        if command[:5] != ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*"]:
            continue
        if len(command) == 5:
            command.append("update-image-placeholder-optional")
        elif command[5] in {None, ""}:
            command[5] = "update-image-placeholder-optional"


def browser_automation_with_second_login_placeholder(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
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
                mark_login_page_wait_as_placeholder_update(task)
        automation.append(second_authorization)

    return automation


def first_login_observation_automation(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
            automation.append(copy.deepcopy(entry))
            continue

        automation.append(
            {
                "comment": (
                    "This module requires the first authorization endpoint visit to stop "
                    "at the login page without authenticating."
                ),
                "match": match,
                "match-limit": 1,
                "tasks": [
                    {
                        "task": "Observe first login page without authentication",
                        "match": f"{ISSUER}/ui/auth*",
                        "commands": [
                            [
                                "wait",
                                "id",
                                NAZO_LOGIN_EMAIL_ID,
                                30,
                                ".*",
                                "update-image-placeholder-optional",
                            ]
                        ],
                    }
                ],
            }
        )

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        automation.append(second_authorization)

    return automation


def user_reject_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": (
                "NazoAuth conformance automation signs in after an explicit browser click, "
                "then lets this negative module deny consent before auto-approval."
            ),
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": login_commands(),
                },
                {
                    "task": "Deny consent page",
                    "match": f"{ISSUER}/ui/consent*",
                    "commands": consent_deny_commands(),
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "submission_complete",
                            OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS,
                        ]
                    ],
                },
            ],
        }
    ]


def browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "NazoAuth conformance browser automation.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error response",
                    "optional": True,
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "css",
                            "body",
                            10,
                            NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN,
                            "update-image-placeholder-optional",
                        ]
                    ],
                },
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": login_commands(),
                },
                {
                    "task": "Complete consent page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/consent*",
                    "commands": consent_approve_commands(),
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [
                        [
                            "wait",
                            "id",
                            "submission_complete",
                            OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS,
                        ]
                    ],
                },
            ],
        },
        {
            "comment": "NazoAuth post-logout redirect browser automation.",
            "match": f"{ISSUER}/logout*",
            "tasks": [
                {
                    "task": "Reach post-logout redirect page",
                    "match": "*/test/*/post_logout_redirect*",
                    "commands": [["wait", "contains", "/post_logout_redirect", 10]],
                },
            ],
        },
        {
            "comment": "NazoAuth OIDC Session Management first verification automation.",
            "match": "*/test/*/session_verify*",
            "tasks": [
                {
                    "task": "Wait for unchanged session management result",
                    "match": "*/test/*/session_verify*",
                    "commands": [["wait", "contains", "/session_result?state=unchanged", 30]],
                },
            ],
        },
        {
            "comment": "NazoAuth OIDC Session Management second verification automation.",
            "match": "*/test/*/second_session_verify*",
            "tasks": [
                {
                    "task": "Wait for changed session management result",
                    "match": "*/test/*/second_session_verify*",
                    "commands": [["wait", "contains", "/second_session_result?state=changed", 30]],
                },
            ],
        },
    ]


def rp_initiated_logout_browser_automation() -> list[dict[str, object]]:
    browser = browser_automation()
    logout_entry = next(
        entry for entry in browser if str(entry.get("match", "")).endswith("/logout*")
    )
    tasks = logout_entry["tasks"]
    for task in tasks:
        if task.get("task") == "Reach post-logout redirect page":
            task["optional"] = True
    tasks.insert(
        0,
        {
            "task": "Confirm an unbound logout request",
            "optional": True,
            "match": f"{ISSUER}/logout*",
            "commands": [["click", "id", "nazo-logout-confirm", "optional"]],
        },
    )
    tasks.insert(
        1,
        {
            "task": "Capture local logout result page",
            "optional": True,
            "match": f"{ISSUER}/logout*",
            "commands": [
                [
                    "wait",
                    "id",
                    "nazo-logout-success",
                    30,
                    ".*",
                    "update-image-placeholder-optional",
                ],
            ],
        },
    )
    return browser


def frontchannel_logout_browser_automation() -> list[dict[str, object]]:
    browser = browser_automation()
    logout_entry = next(
        entry for entry in browser if str(entry.get("match", "")).endswith("/logout*")
    )
    logout_entry["tasks"].insert(
        0,
        {
            "task": "Continue after front-channel iframe notification",
            "match": f"{ISSUER}/logout*",
            "commands": [["click", "id", "nazo-frontchannel-logout-continue"]],
        },
    )
    return browser


def redirect_error_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "Capture the local authorization error response for redirect_uri rejection.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error response",
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "css",
                            "body",
                            10,
                            NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN,
                            "update-image-placeholder-optional",
                        ]
                    ],
                }
            ],
        }
    ]


def fapi_overrides(browser: list[object], include_id2: bool) -> dict[str, object]:
    override: dict[str, object] = {
        module_name: {
            "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
        }
        for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
    }
    override[FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH] = {
        "browser": first_login_observation_automation(browser)
    }
    override[FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION] = {
        "browser": user_reject_browser_automation()
    }
    if include_id2:
        override[FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH] = {
            "browser": first_login_observation_automation(browser)
        }
        override[FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION] = {
            "browser": user_reject_browser_automation()
        }
    return override


def write_plan_config(name: str, config: dict[str, object]) -> None:
    write_text(RUNTIME / name, json.dumps(config, indent=2) + "\n", 0o600)


def oidf_server_config() -> dict[str, object]:
    return {
        "discoveryUrl": f"{ISSUER}/.well-known/openid-configuration",
        "allow_unexpected_metadata_fields": ["native_sso_supported"],
    }


def nazo_login_metadata() -> dict[str, str]:
    return {
        "oidf_user_email": USER_EMAIL,
        "oidf_user_password": USER_PASSWORD,
    }


def write_basic_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": BASIC_ALIAS,
        "description": "OIDC Basic OP: discovery and authorization-code interoperability.",
        "server": oidf_server_config(),
        "client": {
            "client_id": BASIC_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client2": {
            "client_id": BASIC_CLIENT2_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client_secret_post": {
            "client_id": FORMPOST_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
        "override": {
            module_name: {
                "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
            }
            for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
        },
    }
    for module_name in OIDCC_AUTHORIZATION_ERROR_MODULES:
        config["override"][module_name] = {
            "browser": redirect_error_browser_automation()
        }
    write_plan_config("oidf-oidcc-basic-plan-config.json", config)
    return config


def dynamic_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-dynamic",
        "description": "OIDC Basic OP: RFC 7591 dynamic client registration.",
        "server": oidf_server_config(),
        "client": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "client2": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "client_secret_post": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
        "override": {
            module_name: {
                "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
            }
            for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
        },
    }
    for module_name in OIDCC_AUTHORIZATION_ERROR_MODULES:
        config["override"][module_name] = {
            "browser": redirect_error_browser_automation()
        }
    return config


def write_dynamic_plan_config() -> dict[str, object]:
    config = dynamic_plan_config()
    write_plan_config("oidf-oidcc-dynamic-plan-config.json", config)
    return config


def write_formpost_plan_config() -> dict[str, object]:
    config = copy.deepcopy(write_basic_plan_config())
    config["alias"] = f"{BASIC_ALIAS}-formpost"
    config["description"] = "OIDC Form Post OP certification coverage."
    write_plan_config("oidf-oidcc-formpost-plan-config.json", config)
    return config


def write_third_party_init_plan_config() -> dict[str, object]:
    config = copy.deepcopy(dynamic_plan_config())
    config["alias"] = f"{BASIC_ALIAS}-third-party-init"
    config["description"] = "OIDC third-party initiated login registration coverage."
    write_plan_config("oidf-oidcc-third-party-init-plan-config.json", config)
    return config


def fapi_client_config(client_id: str, private_jwks: dict[str, object], scope: str) -> dict[str, object]:
    return {
        "client_id": client_id,
        "jwks": private_jwks,
        "scope": scope,
        "dpop_signing_alg": "ES256",
    }


def fapi_scope(openid: str, fapi_profile: str) -> str:
    if fapi_profile == "fapi_client_credentials_grant":
        return "accounts"
    if openid == "openid_connect":
        return "openid profile email offline_access"
    return "accounts offline_access"


def display_value(value: str) -> str:
    return {
        "dpop": "DPoP",
        "fapi_client_credentials_grant": "client credentials",
        "jarm": "JARM",
        "message-final": "FAPI2 Message Signing Final",
        "mtls": "mTLS",
        "openid_connect": "OpenID Connect",
        "plain_fapi": "authorization code",
        "plain_oauth": "plain OAuth",
        "plain_response": "plain response",
        "private_key_jwt": "private_key_jwt",
        "security-final": "FAPI2 Security Profile Final",
        "signed_non_repudiation": "signed request object",
    }.get(value, value.replace("_", " "))


def fapi_plan_title(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    fapi_profile: str,
    fapi_response_mode: str,
) -> str:
    parts = [
        display_value(plan_kind),
        display_value(client_auth_type),
        display_value(sender_constrain),
        display_value(openid),
        display_value(fapi_profile),
    ]
    if plan_kind == "message-final":
        parts.append(display_value(fapi_response_mode))
    return " / ".join(parts)


def fapi_plan_description(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    fapi_profile: str,
    fapi_response_mode: str,
) -> str:
    flow = (
        "client credentials flow"
        if fapi_profile == "fapi_client_credentials_grant"
        else "authorization code flow"
    )
    mode = "OpenID Connect responses" if openid == "openid_connect" else "OAuth resource access"
    response_mode = "JARM" if fapi_response_mode == "jarm" else "plain"
    response = f" with {response_mode} authorization responses" if plan_kind == "message-final" else ""
    return (
        f"Covers {display_value(plan_kind)} for the {flow} using "
        f"{display_value(client_auth_type)} client authentication, "
        f"{display_value(sender_constrain)} sender constraint, and {mode}{response}."
    )


def fapi_plan_focus(plan_kind: str, fapi_profile: str, fapi_response_mode: str) -> list[str]:
    focus = [
        "discovery metadata",
        "PAR request_uri lifetime and replay handling",
        "authorization request parameter binding",
        "PKCE and redirect URI enforcement",
        "client assertion validation",
    ]
    if fapi_profile == "fapi_client_credentials_grant":
        focus.append("client credentials token issuance")
    else:
        focus.extend(["authorization code replay rejection", "refresh token behavior"])
    if plan_kind == "message-final":
        focus.extend(["signed request objects", "JAR"])
        if fapi_response_mode == "jarm":
            focus.append("JARM")
    return focus


def write_oidcc_config_plan_config() -> dict[str, object]:
    config = {
        "alias": run_scoped_alias("config"),
        "description": "OIDC Config OP: provider metadata accuracy for the public issuer.",
        "server": oidf_server_config(),
    }
    write_plan_config("oidf-oidcc-config-plan-config.json", config)
    return config


def write_frontchannel_logout_plan_config() -> dict[str, object]:
    browser = frontchannel_logout_browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-frontchannel-logout",
        "description": "OIDC Front-Channel Logout OP: RP-initiated logout, frontchannel iframe notification, and post-logout redirect validation.",
        "server": oidf_server_config(),
        "client": {
            "client_id": FRONTCHANNEL_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
    }
    write_plan_config("oidf-oidcc-frontchannel-logout-plan-config.json", config)
    return config


def write_rp_initiated_logout_plan_config() -> dict[str, object]:
    config = {
        "alias": f"{BASIC_ALIAS}-rp-initiated-logout",
        "description": "OIDC RP-Initiated Logout OP: exact redirect validation, invalid hint handling, explicit End-User confirmation, and logout state continuity.",
        "server": oidf_server_config(),
        "client": {
            "client_id": RP_INITIATED_LOGOUT_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": rp_initiated_logout_browser_automation(),
    }
    write_plan_config("oidf-oidcc-rp-initiated-logout-plan-config.json", config)
    return config


def write_backchannel_logout_plan_config() -> dict[str, object]:
    config = {
        "alias": f"{BASIC_ALIAS}-backchannel-logout",
        "description": "OIDC Back-Channel Logout OP: signed explicitly typed Logout Token delivery with sid/sub, events, audience, expiry, and RP callback validation.",
        "server": oidf_server_config(),
        "client": {
            "client_id": BACKCHANNEL_LOGOUT_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser_automation(),
    }
    write_plan_config("oidf-oidcc-backchannel-logout-plan-config.json", config)
    return config


def write_session_management_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-session-management",
        "description": "OIDC Session Management OP: check_session_iframe, session_state, and RP-initiated logout state transition validation.",
        "server": oidf_server_config(),
        "client": {
            "client_id": SESSION_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
    }
    write_plan_config("oidf-oidcc-session-management-plan-config.json", config)
    return config


def fapi_client_ids(plan_slug: str) -> tuple[str, str]:
    return (
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-1",
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-2",
    )


def fapi_plan_config(
    alias: str,
    description: str,
    plan_slug: str,
    include_id2_overrides: bool,
    *,
    client_auth_type: str = "private_key_jwt",
    sender_constrain: str = "dpop",
    openid: str = "openid_connect",
    fapi_profile: str = "plain_fapi",
    fapi_response_mode: str = "plain_response",
    fapi_request_method: str | None = None,
) -> dict[str, object]:
    browser = browser_automation()
    client1_id, client2_id = fapi_client_ids(plan_slug)
    client1_jwks = client_private_jwks(client1_id)
    client2_jwks = client_private_jwks(client2_id)
    scope = fapi_scope(openid, fapi_profile)
    resource_base_url = MTLS_ISSUER if sender_constrain == "mtls" else ISSUER
    config: dict[str, object] = {
        "alias": alias,
        "description": description,
        "server": oidf_server_config(),
        "resource": {
            "resourceUrl": f"{resource_base_url}/fapi/resource",
            "resourceMethod": "GET",
            "resourceMediaType": "application/json",
            "resourceRequestBody": "",
        },
        "client": fapi_client_config(client1_id, client1_jwks, scope),
        "client2": fapi_client_config(client2_id, client2_jwks, scope),
        "mtls": mtls_named_config(mtls_client_cert_name(client1_id)),
        "mtls2": mtls_named_config(mtls_client_cert_name(client2_id)),
        "nazo": {
            **nazo_login_metadata(),
            "client_auth_type": client_auth_type,
            "sender_constrain": sender_constrain,
            "openid": openid,
            "fapi_profile": fapi_profile,
            "fapi_response_mode": fapi_response_mode,
        },
        "browser": browser,
        "override": fapi_overrides(browser, include_id2_overrides),
    }
    if fapi_request_method is not None:
        config["nazo"]["fapi_request_method"] = fapi_request_method
    return config


def fapi_matrix_plan_config(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    *,
    fapi_profile: str = "plain_fapi",
    fapi_response_mode: str = "plain_response",
    fapi_request_method: str | None = None,
) -> tuple[str, dict[str, object]]:
    slug = "-".join(
        value.replace("_", "-")
        for value in [
            plan_kind,
            client_auth_type,
            sender_constrain,
            openid,
            fapi_profile,
            fapi_response_mode,
        ]
    )
    name = f"oidf-fapi-matrix-{slug}-plan-config.json"
    title = fapi_plan_title(
        plan_kind,
        client_auth_type,
        sender_constrain,
        openid,
        fapi_profile,
        fapi_response_mode,
    )
    description = fapi_plan_description(
        plan_kind,
        client_auth_type,
        sender_constrain,
        openid,
        fapi_profile,
        fapi_response_mode,
    )
    config = fapi_plan_config(
        run_scoped_alias(slug),
        description,
        slug,
        False,
        client_auth_type=client_auth_type,
        sender_constrain=sender_constrain,
        openid=openid,
        fapi_profile=fapi_profile,
        fapi_response_mode=fapi_response_mode,
        fapi_request_method=fapi_request_method,
    )
    nazo = config["nazo"]
    assert isinstance(nazo, dict)
    nazo["matrix_title"] = title
    nazo["matrix_description"] = description
    nazo["matrix_focus"] = fapi_plan_focus(plan_kind, fapi_profile, fapi_response_mode)
    return name, config


def write_fapi_plan_configs() -> dict[str, dict[str, object]]:
    configs = {
        "oidf-fapi-security-final-plan-config.json": fapi_plan_config(
            run_scoped_alias("fapi-security-final"),
            "NazoAuth FAPI2 Security Final conformance configuration",
            "security-final",
            False,
        ),
        "oidf-fapi-message-final-plan-config.json": fapi_plan_config(
            run_scoped_alias("fapi-message-final"),
            "NazoAuth FAPI2 Message Signing Final conformance configuration",
            "message-final",
            False,
        ),
        "oidf-fapi-security-id2-plan-config.json": fapi_plan_config(
            run_scoped_alias("fapi-security-id2"),
            "NazoAuth FAPI2 Security ID2 conformance configuration",
            "security-id2",
            True,
        ),
        "oidf-fapi-message-id1-plan-config.json": fapi_plan_config(
            run_scoped_alias("fapi-message-id1"),
            "NazoAuth FAPI2 Message Signing ID1 conformance configuration",
            "message-id1",
            True,
        ),
    }
    for name, config in configs.items():
        write_plan_config(name, config)
    return configs


def write_fapi_ciba_plan_config() -> dict[str, dict[str, object]]:
    configs: dict[str, dict[str, object]] = {}
    for client_auth_type, ciba_mode in (
        ("private_key_jwt", "poll"),
        ("mtls", "poll"),
        ("private_key_jwt", "ping"),
        ("mtls", "ping"),
    ):
        auth_slug = "private-key-jwt" if client_auth_type == "private_key_jwt" else "mtls"
        slug = f"fapi-ciba-plain-{auth_slug}-{ciba_mode}"
        client1_id, client2_id = fapi_client_ids(slug)
        client1_jwks = client_private_jwks(client1_id)
        client2_jwks = client_private_jwks(client2_id)
        alias = run_scoped_alias(slug)
        notification_endpoint = test_endpoint_for(alias, "ciba-notification-endpoint")

        def ciba_client(client_id: str, jwks: dict[str, object]) -> dict[str, object]:
            client = {
                **fapi_client_config(
                    client_id,
                    jwks,
                    "openid profile email offline_access",
                ),
                "acr_value": "1",
                "backchannel_token_delivery_mode": ciba_mode,
                "backchannel_authentication_request_signing_alg": "PS256",
                "backchannel_user_code_parameter": False,
            }
            if ciba_mode == "ping":
                client["backchannel_client_notification_endpoint"] = notification_endpoint
            return client

        nazo = {
            **nazo_login_metadata(),
            "client_auth_type": client_auth_type,
            "openid": "openid_connect",
            "fapi_profile": "plain_fapi",
            "fapi_ciba_profile": "plain_fapi",
            "ciba_mode": ciba_mode,
            "matrix_title": (
                f"FAPI-CIBA ID1 / {client_auth_type} / {ciba_mode} / plain FAPI"
            ),
            "matrix_description": (
                "Covers FAPI-CIBA discovery, backchannel authentication, "
                f"{ciba_mode} delivery, token exchange, negative handling, and resource access."
            ),
            "matrix_focus": [
                "CIBA discovery metadata",
                "backchannel authentication endpoint",
                f"{client_auth_type} client authentication",
                f"{ciba_mode} mode token issuance",
                "FAPI-CIBA request-object and error handling",
            ],
        }
        # FAPI-CIBA ID1 separates client authentication from token sender
        # constraint. Both private_key_jwt and mTLS authenticated CIBA clients
        # receive mTLS holder-of-key access tokens.
        nazo["sender_constrain"] = "mtls"

        config = {
            "alias": alias,
            "description": (
                "FAPI-CIBA ID1 AS: plain FAPI profile with "
                f"{client_auth_type} client authentication and {ciba_mode} delivery mode."
            ),
            "server": oidf_server_config(),
            "resource": {
                "resourceUrl": f"{MTLS_ISSUER}/fapi/resource",
                "resourceMethod": "GET",
                "resourceMediaType": "application/json",
                "resourceRequestBody": "",
            },
            "automated_ciba_approval_url": (
                f"{ISSUER}/auth/ciba-automated-decision"
                f"?token={{auth_req_id}}&type={{action}}"
                f"&decision_token={OIDF_CIBA_AUTOMATED_DECISION_TOKEN}"
            ),
            "client": {
                **ciba_client(client1_id, client1_jwks),
                "hint_type": "login_hint",
                "hint_value": USER_EMAIL,
            },
            "client2": ciba_client(client2_id, client2_jwks),
            "mtls": mtls_named_config(mtls_client_cert_name(client1_id)),
            "mtls2": mtls_named_config(mtls_client_cert_name(client2_id)),
            "nazo": nazo,
            "browser": browser_automation(),
        }
        name = f"oidf-{slug}-plan-config.json"
        write_plan_config(name, config)
        configs[name] = config
    return configs


def write_fapi_matrix_plan_configs() -> dict[str, dict[str, object]]:
    configs: dict[str, dict[str, object]] = {}
    for client_auth_type in FAPI_MATRIX_CLIENT_AUTHS:
        for sender_constrain in FAPI_MATRIX_SENDER_CONSTRAINS:
            for openid in FAPI_MATRIX_OPENID_MODES:
                name, config = fapi_matrix_plan_config(
                    "security-final",
                    client_auth_type,
                    sender_constrain,
                    openid,
                )
                configs[name] = config

    for response_mode in ("plain_response", "jarm"):
        name, config = fapi_matrix_plan_config(
            "message-final",
            "private_key_jwt",
            "dpop",
            "openid_connect",
            fapi_response_mode=response_mode,
            fapi_request_method="signed_non_repudiation",
        )
        configs[name] = config

    for client_auth_type in FAPI_MATRIX_CLIENT_AUTHS:
        for sender_constrain in FAPI_MATRIX_SENDER_CONSTRAINS:
            name, config = fapi_matrix_plan_config(
                "security-final",
                client_auth_type,
                sender_constrain,
                "plain_oauth",
                fapi_profile="fapi_client_credentials_grant",
            )
            configs[name] = config

    for name, config in configs.items():
        write_plan_config(name, config)
    return configs


def write_all_plan_configs() -> None:
    configs: dict[str, dict[str, object]] = {
        "oidf-oidcc-basic-plan-config.json": write_basic_plan_config(),
        "oidf-oidcc-dynamic-plan-config.json": write_dynamic_plan_config(),
        "oidf-oidcc-formpost-plan-config.json": write_formpost_plan_config(),
        "oidf-oidcc-third-party-init-plan-config.json": write_third_party_init_plan_config(),
        "oidf-oidcc-config-plan-config.json": write_oidcc_config_plan_config(),
        "oidf-oidcc-rp-initiated-logout-plan-config.json": write_rp_initiated_logout_plan_config(),
        "oidf-oidcc-backchannel-logout-plan-config.json": write_backchannel_logout_plan_config(),
        "oidf-oidcc-frontchannel-logout-plan-config.json": write_frontchannel_logout_plan_config(),
        "oidf-oidcc-session-management-plan-config.json": write_session_management_plan_config(),
    }
    configs.update(write_fapi_plan_configs())
    configs.update(write_fapi_ciba_plan_config())
    configs.update(write_fapi_matrix_plan_configs())
    plan_set = plan_expressions_for_configs(configs)
    concurrent, ciba, rp_initiated, backchannel, frontchannel, session = partition_plan_expressions(
        plan_set
    )
    if any(len(group) != 1 for group in (rp_initiated, backchannel, frontchannel, session)):
        raise RuntimeError(
            "OIDF full matrix must contain exactly one plan for each OIDC logout profile"
        )
    if len(ciba) != 4:
        raise RuntimeError("OIDF full matrix must contain exactly four FAPI-CIBA plans")
    plan_manifest = plan_manifest_for_expressions(plan_set, configs)
    write_text(RUNTIME / "oidf-plan-configs.json", json.dumps({"configs": configs}, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "oidf-plan-set.json", json.dumps(plan_set, indent=2) + "\n", 0o600)
    write_text(
        RUNTIME / "oidf-plan-set-concurrent.json",
        json.dumps(concurrent, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-ciba.json",
        json.dumps(ciba, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-rp-initiated.json",
        json.dumps(rp_initiated, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-backchannel.json",
        json.dumps(backchannel, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-frontchannel.json",
        json.dumps(frontchannel, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-session.json",
        json.dumps(session, indent=2) + "\n",
        0o600,
    )
    for file_name, group in bounded_parallel_plan_groups(plan_set).items():
        write_text(RUNTIME / file_name, json.dumps(group, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "oidf-plan-set-manifest.json", json.dumps(plan_manifest, indent=2) + "\n", 0o600)
    write_text(
        RUNTIME / "oidf-runner.env",
        "\n".join(
            [
                "# Secret-free path hints; pass these files explicitly to the runner.",
                "OIDF_PLAN_CONFIG_FILE=oidf-plan-configs.json",
                "OIDF_PLAN_SET_FILE=oidf-plan-set.json",
                "OIDF_PLAN_MANIFEST_FILE=oidf-plan-set-manifest.json",
                "",
            ]
        ),
        0o600,
    )
    callbacks = {
        name: callback_for(str(config["alias"]))
        for name, config in configs.items()
        if name != "oidf-oidcc-config-plan-config.json"
    }
    write_text(RUNTIME / "callbacks.json", json.dumps(callbacks, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "callback.txt", callback_for(BASIC_ALIAS) + "\n")
    write_text(
        RUNTIME / "oidf-onboarding-manifest.json",
        json.dumps(
            {
                "schema": 1,
                "target_issuer": ISSUER,
                "suite_base_url": SUITE_ORIGIN,
                "applicant_email": USER_EMAIL,
                "clients": onboarding_clients(configs),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        0o600,
    )
    write_onboarding_contract()
    write_expected_skips()


def onboarding_contract() -> dict[str, object]:
    return {
        "schema": 1,
        "onboarding_profile": "operator-black-box",
        "target_issuer": ISSUER,
        "suite_base_url": SUITE_ORIGIN,
        "run_namespace": RUN_NAMESPACE,
    }


def write_onboarding_contract() -> None:
    write_text(
        RUNTIME / "oidf-onboarding-contract.json",
        json.dumps(onboarding_contract(), indent=2, sort_keys=True) + "\n",
        0o600,
    )


def expected_skips() -> list[dict[str, str]]:
    return [
        {
            "test-name": "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-basic-plan-config.json",
        },
        {
            "test-name": "oidcc-ensure-request-object-with-redirect-uri",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-basic-plan-config.json",
        },
        {
            "test-name": "oidcc-idtoken-unsigned",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
        {
            "test-name": "oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
        {
            "test-name": "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
        {
            "test-name": "oidcc-ensure-request-object-with-redirect-uri",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
        {
            "test-name": "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-formpost-plan-config.json",
        },
        {
            "test-name": "oidcc-ensure-request-object-with-redirect-uri",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-formpost-plan-config.json",
        },
    ]


def write_expected_skips() -> None:
    write_text(
        RUNTIME / "oidf-expected-skips.json",
        json.dumps(expected_skips(), indent=2) + "\n",
        0o600,
    )


def plan_expressions_for_configs(configs: dict[str, dict[str, object]]) -> list[str]:
    expressions = [
        "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] "
        "oidf-oidcc-basic-plan-config.json",
        "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] "
        "oidf-oidcc-dynamic-plan-config.json",
        "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] "
        "oidf-oidcc-formpost-plan-config.json",
        "oidcc-3rdparty-init-login-certification-test-plan[response_type=code] "
        "oidf-oidcc-third-party-init-plan-config.json",
        "oidcc-config-certification-test-plan oidf-oidcc-config-plan-config.json",
        "oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-rp-initiated-logout-plan-config.json",
        "oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-backchannel-logout-plan-config.json",
        "oidcc-frontchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-frontchannel-logout-plan-config.json",
        "oidcc-session-management-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-session-management-plan-config.json",
    ]
    for name, config in sorted(configs.items()):
        if name.startswith("oidf-fapi-ciba-"):
            nazo = config.get("nazo")
            if not isinstance(nazo, dict):
                continue
            expressions.append(
                "fapi-ciba-id1-test-plan"
                f"[client_auth_type={nazo['client_auth_type']}]"
                "[fapi_ciba_profile=plain_fapi]"
                f"[ciba_mode={nazo['ciba_mode']}]"
                "[client_registration=static_client] "
                f"{name}"
            )
            continue
        if name.startswith("oidf-fapi-matrix-"):
            nazo = config.get("nazo")
            if not isinstance(nazo, dict):
                continue
            plan_kind = "fapi2-message-signing-final-test-plan" if "message-final" in name else "fapi2-security-profile-final-test-plan"
            variants = [
                f"client_auth_type={nazo['client_auth_type']}",
                f"fapi_profile={nazo['fapi_profile']}",
            ]
            if plan_kind == "fapi2-message-signing-final-test-plan":
                variants.append(f"fapi_request_method={nazo.get('fapi_request_method', 'signed_non_repudiation')}")
                variants.append(f"fapi_response_mode={nazo['fapi_response_mode']}")
            variants.append(f"sender_constrain={nazo['sender_constrain']}")
            variants.append(f"openid={nazo['openid']}")
            expressions.append(f"{plan_kind}[{']['.join(variants)}] {name}")
    return expressions


def partition_plan_expressions(
    expressions: list[str],
) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str]]:
    ciba = [
        expression for expression in expressions if "fapi-ciba-id1-test-plan" in expression
    ]
    frontchannel = [
        expression
        for expression in expressions
        if "frontchannel-rp-initiated-logout" in expression
    ]
    rp_initiated = [
        expression
        for expression in expressions
        if "oidcc-rp-initiated-logout-certification-test-plan" in expression
    ]
    backchannel = [
        expression
        for expression in expressions
        if "backchannel-rp-initiated-logout" in expression
    ]
    session = [
        expression
        for expression in expressions
        if "session-management-certification-test-plan" in expression
    ]
    isolated = set(ciba + rp_initiated + backchannel + frontchannel + session)
    concurrent = [
        expression for expression in expressions if expression not in isolated
    ]
    return concurrent, ciba, rp_initiated, backchannel, frontchannel, session


def bounded_parallel_plan_groups(expressions: list[str]) -> dict[str, list[str]]:
    def matches(*needles: str) -> list[str]:
        return [
            expression
            for expression in expressions
            if all(needle in expression for needle in needles)
        ]

    return {
        "01-oidc-core.json": matches("oidcc-basic-certification-test-plan"),
        "02-oidc-formpost-thirdparty-config.json": [
            *matches("oidcc-formpost-basic-certification-test-plan"),
            *matches("oidcc-3rdparty-init-login-certification-test-plan"),
            *matches("oidcc-config-certification-test-plan"),
        ],
        "03a-fapi-ciba-private-key-jwt-poll.json": matches(
            "fapi-ciba-id1-test-plan",
            "client_auth_type=private_key_jwt",
            "ciba_mode=poll",
        ),
        "03b-fapi-ciba-mtls-poll.json": matches(
            "fapi-ciba-id1-test-plan",
            "client_auth_type=mtls",
            "ciba_mode=poll",
        ),
        "03c-fapi-ciba-private-key-jwt-ping.json": matches(
            "fapi-ciba-id1-test-plan",
            "client_auth_type=private_key_jwt",
            "ciba_mode=ping",
        ),
        "03d-fapi-ciba-mtls-ping.json": matches(
            "fapi-ciba-id1-test-plan",
            "client_auth_type=mtls",
            "ciba_mode=ping",
        ),
        "04-fapi-message-and-mtls-dpop.json": [
            *matches("fapi2-message-signing-final-test-plan"),
            *matches("fapi2-security-profile-final-test-plan", "client_auth_type=mtls", "sender_constrain=dpop"),
        ],
        "05-fapi-mtls-mtls.json": matches(
            "fapi2-security-profile-final-test-plan",
            "client_auth_type=mtls",
            "sender_constrain=mtls",
        ),
        "06-fapi-private-dpop.json": matches(
            "fapi2-security-profile-final-test-plan",
            "client_auth_type=private_key_jwt",
            "sender_constrain=dpop",
        ),
        "07-fapi-private-mtls.json": matches(
            "fapi2-security-profile-final-test-plan",
            "client_auth_type=private_key_jwt",
            "sender_constrain=mtls",
        ),
        "08-rp-initiated.json": matches(
            "oidcc-rp-initiated-logout-certification-test-plan"
        ),
        "09-backchannel.json": matches("backchannel-rp-initiated-logout"),
        "10-frontchannel.json": matches("frontchannel-rp-initiated-logout"),
        "11-session.json": matches("session-management-certification-test-plan"),
    }


def plan_manifest_for_expressions(
    expressions: list[str], configs: dict[str, dict[str, object]]
) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    oidc_titles = {
        "oidf-oidcc-basic-plan-config.json": "OIDC Basic OP",
        "oidf-oidcc-dynamic-plan-config.json": "OIDC Basic OP Dynamic Registration",
        "oidf-oidcc-formpost-plan-config.json": "OIDC Form Post OP",
        "oidf-oidcc-third-party-init-plan-config.json": "OIDC Third-Party Initiated Login OP",
        "oidf-oidcc-config-plan-config.json": "OIDC Config OP",
        "oidf-oidcc-rp-initiated-logout-plan-config.json": "OIDC RP-Initiated Logout OP",
        "oidf-oidcc-backchannel-logout-plan-config.json": "OIDC Back-Channel Logout OP",
        "oidf-oidcc-frontchannel-logout-plan-config.json": "OIDC Front-Channel Logout OP",
        "oidf-oidcc-session-management-plan-config.json": "OIDC Session Management OP",
    }
    oidc_focus = {
        "oidf-oidcc-basic-plan-config.json": [
            "discovery metadata",
            "authorization code flow",
            "static client registration",
            "userinfo and ID token interoperability",
        ],
        "oidf-oidcc-dynamic-plan-config.json": [
            "RFC 7591 dynamic client registration",
            "registration endpoint metadata",
            "authorization code flow",
            "userinfo and ID token interoperability",
        ],
        "oidf-oidcc-formpost-plan-config.json": [
            "response_mode=form_post",
            "successful and error authorization responses",
            "browser auto-submission interoperability",
        ],
        "oidf-oidcc-third-party-init-plan-config.json": [
            "initiate_login_uri registration round-trip",
            "HTTPS metadata enforcement",
            "invalid_client_metadata rejection",
        ],
        "oidf-oidcc-config-plan-config.json": [
            "provider metadata accuracy",
            "endpoint advertisement",
            "supported algorithms and response metadata",
        ],
        "oidf-oidcc-rp-initiated-logout-plan-config.json": [
            "end_session_endpoint metadata",
            "GET and form POST logout requests",
            "id_token_hint and client_id binding",
            "exact post_logout_redirect_uri validation",
            "End-User confirmation for unbound requests",
        ],
        "oidf-oidcc-backchannel-logout-plan-config.json": [
            "backchannel logout discovery metadata",
            "signed and explicitly typed Logout Token",
            "iss, aud, iat, exp, jti, events, sid, and sub claims",
            "form-encoded RP callback delivery",
        ],
        "oidf-oidcc-frontchannel-logout-plan-config.json": [
            "frontchannel_logout_supported metadata",
            "RP-initiated logout",
            "frontchannel logout iframe notification",
            "post_logout_redirect_uri validation",
        ],
        "oidf-oidcc-session-management-plan-config.json": [
            "check_session_iframe metadata",
            "session_state authorization response",
            "RP-initiated logout",
            "session state transition after logout",
        ],
    }
    for index, expression in enumerate(expressions, 1):
        config_name = expression.rsplit(" ", 1)[1]
        config = configs[config_name]
        nazo = config.get("nazo")
        title = oidc_titles.get(config_name)
        description = config.get("description")
        focus = oidc_focus.get(config_name, [])
        if isinstance(nazo, dict) and "matrix_title" in nazo:
            title = str(nazo["matrix_title"])
            description = str(nazo["matrix_description"])
            focus = list(nazo["matrix_focus"])
        plans.append(
            {
                "index": index,
                "title": title,
                "description": description,
                "expression": expression,
                "config": config_name,
                "coverage_focus": focus,
            }
        )
    return {
        "name": "NazoAuth OIDF full conformance matrix",
        "description": (
            f"{len(plans)}-plan OpenID Foundation regression matrix for the public issuer. "
            "Targeted TP/PS checks are mapped onto these plans instead of being run as a separate matrix."
        ),
        "plans": plans,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize runner inputs for a caller-supplied public issuer and suite origin."
    )
    add_secret_source_arguments(parser)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        configure_operator_secrets(args)
    except SecretInputError as error:
        raise SystemExit(str(error)) from error
    ensure_mtls_certs()
    write_all_plan_configs()
    print(f"Prepared public black-box runner inputs under {RUNTIME}")
    print(f"Issuer: {ISSUER}")
    print(f"Suite callback base: {SUITE_BASE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
