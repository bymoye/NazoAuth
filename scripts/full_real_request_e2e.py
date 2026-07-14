#!/usr/bin/env python3
"""Full real HTTP request gate for nazo-oauth-server.

The script is intentionally black-box at the HTTP boundary. It seeds only
prerequisite state that has no public bootstrap endpoint, then exercises every
declared Actix route through real requests against a running server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from email import message_from_bytes
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from full_real_request_source_policy import (
    RuntimeCaseEvidence,
    execute_case_registry,
    validate_case_registry,
)


HTTP_SIGNATURE_REQUIRED_E2E_CASES = frozenset(
    {
        "fapi_http_signature_signed_get",
        "fapi_http_signature_signed_post",
        "fapi_http_signature_signed_extra_headers",
        "fapi_http_signature_tampered_extra_header",
        "fapi_http_signature_signed_dpop_bound_resource",
        "fapi_http_signature_response_verification_and_request_binding",
        "fapi_http_signature_response_tampered_content_type",
        "fapi_http_signature_response_tampered_interaction_id",
        "fapi_http_signature_tampered_method",
        "fapi_http_signature_tampered_uri",
        "fapi_http_signature_tampered_authorization",
        "fapi_http_signature_tampered_dpop",
        "fapi_http_signature_tampered_body",
        "fapi_http_signature_stale_created",
        "fapi_http_signature_future_created",
        "fapi_http_signature_replay",
        "fapi_http_signature_wrong_key",
        "fapi_http_signature_wrong_client",
        "fapi_http_signature_unsigned_fallback",
    }
)

HTTP_SIGNATURE_CASE_REGISTRY = (
    ("fapi_http_signature_signed_get", "signed_request", {"query": "signed-get", "expected_status": 200}),
    ("fapi_http_signature_signed_post", "signed_post", {"query": "signed-post", "expected_status": 200}),
    ("fapi_http_signature_signed_extra_headers", "signed_request", {"query": "signed-extra-headers", "signed_extra_headers": {"Content-Type": "application/json", "Idempotency-Key": "operation-123"}, "expected_status": 200}),
    ("fapi_http_signature_tampered_extra_header", "signed_request", {"query": "tampered-extra-header", "signed_extra_headers": {"Content-Type": "application/json", "Idempotency-Key": "operation-123"}, "sent_extra_headers": {"Content-Type": "application/json", "Idempotency-Key": "operation-999"}, "expected_status": 401}),
    ("fapi_http_signature_signed_dpop_bound_resource", "signed_dpop", {"query": "signed-dpop-bound", "expected_status": 200}),
    ("fapi_http_signature_response_verification_and_request_binding", "response_binding", {"query": "response-binding", "expected_status": 200}),
    ("fapi_http_signature_response_tampered_content_type", "response_header_tamper", {"query": "response-tampered-content-type", "header": "Content-Type", "value": "text/plain", "expected_status": 200}),
    ("fapi_http_signature_response_tampered_interaction_id", "response_header_tamper", {"query": "response-tampered-interaction-id", "header": "X-Fapi-Interaction-Id", "value": "tampered-interaction-id", "expected_status": 200}),
    ("fapi_http_signature_tampered_method", "signed_request", {"method": "POST", "signed_method": "GET", "query": "tampered-method", "expected_status": 401}),
    ("fapi_http_signature_tampered_uri", "tampered_uri", {"query": "tampered-uri", "expected_status": 401}),
    ("fapi_http_signature_tampered_authorization", "tampered_authorization", {"query": "tampered-authorization", "expected_status": 401}),
    ("fapi_http_signature_tampered_dpop", "signed_request", {"query": "tampered-dpop", "signed_dpop": "signed-dpop-value", "sent_dpop": "altered-dpop-value", "expected_status": 401}),
    ("fapi_http_signature_tampered_body", "tampered_body", {"query": "tampered-body", "expected_status": 401}),
    ("fapi_http_signature_stale_created", "relative_created", {"query": "stale-created", "created_offset": -61, "expected_status": 401}),
    ("fapi_http_signature_future_created", "relative_created", {"query": "future-created", "created_offset": 6, "expected_status": 401}),
    ("fapi_http_signature_replay", "replay", {"query": "replay", "expected_status": 200}),
    ("fapi_http_signature_wrong_key", "wrong_key", {"query": "wrong-key", "expected_status": 401}),
    ("fapi_http_signature_wrong_client", "wrong_client", {"query": "wrong-client", "expected_status": 401}),
    ("fapi_http_signature_unsigned_fallback", "unsigned_fallback", {"expected_status": 200}),
)

HTTP_SIGNATURE_HANDLER_NAMES = frozenset(
    {
        "relative_created",
        "replay",
        "response_binding",
        "response_header_tamper",
        "signed_dpop",
        "signed_post",
        "signed_request",
        "tampered_authorization",
        "tampered_body",
        "tampered_uri",
        "unsigned_fallback",
        "wrong_client",
        "wrong_key",
    }
)
HTTP_SIGNATURE_RUNTIME_EVIDENCE = RuntimeCaseEvidence(HTTP_SIGNATURE_REQUIRED_E2E_CASES)


def validate_http_signature_case_registry(registry: tuple[tuple[str, str, dict[str, object]], ...]) -> None:
    validate_case_registry(
        registry,
        required=HTTP_SIGNATURE_REQUIRED_E2E_CASES,
        allowed_handlers=HTTP_SIGNATURE_HANDLER_NAMES,
    )


def execute_http_signature_case_registry(
    registry: tuple[tuple[str, str, dict[str, object]], ...],
    handlers: dict[str, object],
) -> tuple[str, ...]:
    return execute_case_registry(
        registry,
        handlers,
        required=HTTP_SIGNATURE_REQUIRED_E2E_CASES,
        allowed_handlers=HTTP_SIGNATURE_HANDLER_NAMES,
        evidence=HTTP_SIGNATURE_RUNTIME_EVIDENCE,
    )


def run_source_policy_check() -> None:
    validate_http_signature_case_registry(HTTP_SIGNATURE_CASE_REGISTRY)
    fake_handlers = {
        name: (lambda case, _params: HTTP_SIGNATURE_RUNTIME_EVIDENCE.observe(case, True))
        for name in HTTP_SIGNATURE_HANDLER_NAMES
    }
    executed = execute_http_signature_case_registry(HTTP_SIGNATURE_CASE_REGISTRY, fake_handlers)
    if tuple(name for name, _, _ in HTTP_SIGNATURE_CASE_REGISTRY) != executed:
        raise AssertionError("source-policy runner did not traverse the declared registry")


def run_source_policy_self_tests() -> None:
    run_source_policy_check()
    required = frozenset({"required_case"})
    allowed = frozenset({"handler"})
    registry = (("required_case", "handler", {}),)

    def must_fail(
        candidate: tuple[tuple[str, str, dict[str, object]], ...],
        handlers: dict[str, object],
        expected: str,
        evidence: RuntimeCaseEvidence | None = None,
    ) -> None:
        try:
            execute_case_registry(
                candidate,
                handlers,
                required=required,
                allowed_handlers=allowed,
                evidence=evidence or RuntimeCaseEvidence(required),
            )
        except AssertionError as error:
            if expected not in str(error):
                raise AssertionError(f"unexpected contract failure: {error}") from error
            return
        raise AssertionError(f"contract case did not fail: {expected}")

    noop = lambda _case, _params: None
    must_fail((), {"handler": noop}, "missing")
    must_fail(registry + (("extra", "handler", {}),), {"handler": noop}, "extra")
    must_fail(registry + registry, {"handler": noop}, "duplicates")
    must_fail((("required_case", "unknown", {}),), {}, "unknown_handlers")
    must_fail(registry, {"handler": object()}, "not callable")
    must_fail(registry, {}, "handler map is not exact")
    must_fail(
        registry,
        {"handler": noop, "extra_handler": noop},
        "handler map is not exact",
    )
    must_fail(registry, {"handler": noop}, "did not assert")
    must_fail(registry, {"handler": lambda _case, _params: None if False else None}, "did not assert")

    wrong_evidence = RuntimeCaseEvidence(required | {"other_case"})
    must_fail(
        registry,
        {"handler": lambda _case, _params: wrong_evidence.observe("other_case", True)},
        "wrong active case",
        wrong_evidence,
    )

    duplicate_evidence = RuntimeCaseEvidence(required)
    def duplicate(case: str, _params: dict[str, object]) -> None:
        duplicate_evidence.observe(case, True)
        duplicate_evidence.observe(case, True)
    must_fail(registry, {"handler": duplicate}, "duplicate runtime case assertion", duplicate_evidence)

    clean_evidence = RuntimeCaseEvidence(required)
    try:
        execute_case_registry(
            registry,
            {"handler": lambda _case, _params: (_ for _ in ()).throw(RuntimeError("boom"))},
            required=required,
            allowed_handlers=allowed,
            evidence=clean_evidence,
        )
    except RuntimeError:
        pass
    if clean_evidence.active_case is not None:
        raise AssertionError("runtime evidence state leaked after handler exception")
    execute_case_registry(
        registry,
        {"handler": lambda case, _params: clean_evidence.observe(case, True)},
        required=required,
        allowed_handlers=allowed,
        evidence=clean_evidence,
    )

    nested_evidence = RuntimeCaseEvidence(required)
    def nested(_case: str, _params: dict[str, object]) -> None:
        execute_case_registry(
            registry,
            {"handler": lambda case, _params: nested_evidence.observe(case, True)},
            required=required,
            allowed_handlers=allowed,
            evidence=nested_evidence,
        )
    must_fail(registry, {"handler": nested}, "nested runtime case execution", nested_evidence)
    if nested_evidence.active_case is not None:
        raise AssertionError("runtime evidence state leaked after nested execution")
    execute_case_registry(
        registry,
        {"handler": lambda case, _params: nested_evidence.observe(case, True)},
        required=required,
        allowed_handlers=allowed,
        evidence=nested_evidence,
    )


if sys.argv[1:] == ["--source-policy-check"]:
    run_source_policy_check()
    raise SystemExit(0)
if sys.argv[1:] == ["--source-policy-self-test"]:
    run_source_policy_self_tests()
    raise SystemExit(0)

import jwt
import psycopg
import redis
import requests
from aiosmtpd.controller import Controller
from argon2 import PasswordHasher
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


BASE_URL = os.environ.get("E2E_BASE_URL", "http://nazo-oauth-e2e-server:8000")
ISSUER_URL = os.environ.get("E2E_ISSUER_URL", BASE_URL)


def configured_oidc_provider() -> dict[str, Any]:
    # E2E 与服务端使用同一个 provider registry 事实源，避免脚本硬编码单 provider 路径。
    raw = os.environ.get("FEDERATION_PROVIDER_CONFIGS", "")
    if raw.strip():
        providers = json.loads(raw)
        for provider in providers:
            if provider.get("enabled") and provider.get("adapter_type") == "oidc":
                return provider
    return {
        "provider_id": os.environ.get("E2E_OIDC_PROVIDER_ID", "codecov-oidc"),
        "client_id": os.environ.get("E2E_OIDC_CLIENT_ID", "codecov-oidc-client"),
        "redirect_uri": f"{ISSUER_URL}/auth/federation/codecov-oidc/callback",
        "scopes": "openid email profile",
    }


OIDC_PROVIDER = configured_oidc_provider()
OIDC_PROVIDER_ID = str(OIDC_PROVIDER["provider_id"])
OIDC_CLIENT_ID = str(OIDC_PROVIDER["client_id"])
OIDC_SCOPE = str(OIDC_PROVIDER.get("scopes", "openid email profile"))
OIDC_CALLBACK_PATH = f"/auth/federation/{OIDC_PROVIDER_ID}/callback"
OIDC_START_PATH = f"/auth/federation/{OIDC_PROVIDER_ID}/start"
OIDC_REDIRECT_URI = os.environ.get(
    "E2E_OIDC_REDIRECT_URI",
    str(OIDC_PROVIDER.get("redirect_uri") or f"{ISSUER_URL}{OIDC_CALLBACK_PATH}"),
)
DATABASE_URL = os.environ.get(
    "E2E_DATABASE_URL",
    "postgresql://postgres:postgres@nazo-oauth-e2e-postgres:5432/oauth",
)
VALKEY_URL = os.environ.get("E2E_VALKEY_URL", "redis://nazo-oauth-e2e-valkey:6379/0")
E2E_CORS_ORIGIN = os.environ.get("E2E_CORS_ORIGIN", "http://127.0.0.1:3000")
E2E_SMTP_BIND_HOST = os.environ.get("E2E_SMTP_BIND_HOST", "0.0.0.0")

ADMIN_EMAIL = "admin-full-e2e@example.com"
ADMIN_PASSWORD = "AdminPassword-2026"
USER_EMAIL = "user-full-e2e@example.com"
USER_PASSWORD = "UserPassword-2026"
CLIENT_REDIRECT_URI = "https://client.example/callback"
DEFAULT_AUDIENCE = "resource://default"
SCIM_BEARER_TOKEN = os.environ.get("E2E_SCIM_BEARER_TOKEN", "codecov-scim-secret")
SAML_GATEWAY_ISSUER = os.environ.get("E2E_SAML_GATEWAY_ISSUER", "codecov-saml-gateway")
SAML_GATEWAY_AUDIENCE = os.environ.get("E2E_SAML_GATEWAY_AUDIENCE", "nazo-oauth-codecov")
SAML_GATEWAY_SECRET = os.environ.get(
    "E2E_SAML_GATEWAY_SECRET",
    "codecov-saml-gateway-secret-000000",
)
DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_REALM_ID = "00000000-0000-0000-0000-000000000002"
DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000003"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SESSION_COOKIE_NAME = "nazo_oauth_session"

checks: list[str] = []


def fail(message: str) -> None:
    raise AssertionError(message)


def check(name: str, condition: bool, detail: Any = None) -> None:
    HTTP_SIGNATURE_RUNTIME_EVIDENCE.observe(name, condition)
    if not condition:
        if detail is None:
            fail(name)
        fail(f"{name}: {detail}")
    checks.append(name)


def expect_status(name: str, response: requests.Response, expected: int) -> requests.Response:
    if response.status_code != expected:
        fail(f"{name}: expected {expected}, got {response.status_code}: {response.text}")
    checks.append(name)
    return response


def expect_json(response: requests.Response) -> dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:  # noqa: BLE001
        fail(f"response is not JSON: {response.status_code} {response.text} ({exc})")
    raise AssertionError("unreachable")


def comma_header_values(response: requests.Response, name: str) -> set[str]:
    raw = response.headers.get(name, "")
    return {value.strip().lower() for value in raw.split(",") if value.strip()}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def content_digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')}:"


def fapi_http_signature_fields(
    key: ed25519.Ed25519PrivateKey,
    kid: str,
    method: str,
    target_uri: str,
    authorization: str,
    *,
    body: bytes = b"",
    dpop: str | None = None,
    created: int | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    """Mirror the Rust core's fixed Ed25519 request vector for black-box transport tests.

    The Rust crate remains the canonical cryptographic/vector implementation; the source-policy
    gate pins every caller below and the crate tests independently pin canonicalization.
    """
    created = now() if created is None else created
    components = ["@method", "@target-uri", "authorization"]
    values = [
        f'"@method": {method}',
        f'"@target-uri": {target_uri}',
        f'"authorization": {authorization.strip()}',
    ]
    if dpop is not None:
        components.append("dpop")
        values.append(f'"dpop": {dpop.strip()}')
    headers = {"Authorization": authorization}
    if dpop is not None:
        headers["DPoP"] = dpop
    if body:
        digest = content_digest(body)
        components.append("content-digest")
        values.append(f'"content-digest": {digest}')
        headers["Content-Digest"] = digest
    for name, value in (extra_headers or {}).items():
        component = name.lower()
        components.append(component)
        values.append(f'"{component}": {value.strip()}')
        headers[name] = value
    component_list = " ".join(f'"{component}"' for component in components)
    params = (
        f'({component_list});created={created};keyid="{kid}";alg="ed25519";'
        'tag="fapi-2-request"'
    )
    signature_input = f"sig1={params}"
    signature_base = "\n".join(values) + f'\n"@signature-params": {params}'
    signature = key.sign(signature_base.encode("ascii"))
    headers["Signature-Input"] = signature_input
    headers["Signature"] = f"sig1=:{base64.b64encode(signature).decode('ascii')}:"
    return headers


def verify_fapi_http_signature_response(
    response: requests.Response,
    server_jwks: dict[str, Any],
    *,
    method: str,
    target_uri: str,
    request_body: bytes,
    request_headers: dict[str, str] | None,
) -> None:
    signature_input = response.headers.get("Signature-Input", "")
    signature_field = response.headers.get("Signature", "")
    match = re.fullmatch(
        r'nazo=\((?P<components>.+)\);created=(?P<created>-?\d+);keyid="(?P<kid>[^"]+)";alg="(?P<alg>ed25519|rsa-v1_5-sha256|ecdsa-p256-sha256)";tag="fapi-2-response"',
        signature_input,
    )
    check("fapi_http_signature_response_input_shape", match is not None, signature_input)
    assert match is not None
    valid_request_digest = (
        request_headers is not None
        and bool(request_body)
        and request_headers.get("Content-Digest") == content_digest(request_body)
    )
    expected_components = ['"@status"', '"content-digest"']
    for header_name in ("Content-Type", "X-Fapi-Interaction-Id"):
        if response.headers.get(header_name) is not None:
            expected_components.append(f'"{header_name.lower()}"')
    expected_components.extend(['"@method";req', '"@target-uri";req'])
    if valid_request_digest:
        expected_components.append('"content-digest";req')
    if request_headers is not None:
        expected_components.extend(['"signature-input";req', '"signature";req'])
    check(
        "fapi_http_signature_response_components",
        match.group("components").split(" ") == expected_components,
        match.group("components"),
    )
    digest = response.headers.get("Content-Digest", "")
    check("fapi_http_signature_response_digest", digest == content_digest(response.content))
    lines = [f'"@status": {response.status_code}', f'"content-digest": {digest}']
    for header_name in ("Content-Type", "X-Fapi-Interaction-Id"):
        header_value = response.headers.get(header_name)
        if header_value is not None:
            lines.append(f'"{header_name.lower()}": {header_value}')
    lines.extend([f'"@method";req: {method}', f'"@target-uri";req: {target_uri}'])
    if valid_request_digest:
        assert request_headers is not None
        lines.append(f'"content-digest";req: {request_headers["Content-Digest"]}')
    if request_headers is not None:
        lines.extend(
            [
                f'"signature-input";req: {request_headers["Signature-Input"]}',
                f'"signature";req: {request_headers["Signature"]}',
            ]
        )
    params = signature_input.removeprefix("nazo=")
    signature_base = "\n".join(lines) + f'\n"@signature-params": {params}'
    signature_match = re.fullmatch(r"nazo=:(?P<value>[A-Za-z0-9+/]+={0,2}):", signature_field)
    check("fapi_http_signature_response_value_shape", signature_match is not None)
    assert signature_match is not None
    jwk = next(
        (item for item in server_jwks.get("keys", []) if item.get("kid") == match.group("kid")),
        None,
    )
    check("fapi_http_signature_response_kid_resolves", jwk is not None)
    assert jwk is not None
    signature_bytes = base64.b64decode(signature_match.group("value"))
    signature_base_bytes = signature_base.encode("ascii")
    if match.group("alg") == "ed25519":
        check("fapi_http_signature_response_key_is_ed25519", jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519")
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        )
        public_key.verify(signature_bytes, signature_base_bytes)
    elif match.group("alg") == "rsa-v1_5-sha256":
        check("fapi_http_signature_response_key_is_rsa", jwk.get("kty") == "RSA")
        modulus = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)))
        exponent = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4)))
        rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
            signature_bytes,
            signature_base_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    else:
        check("fapi_http_signature_response_key_is_p256", jwk.get("kty") == "EC" and jwk.get("crv") == "P-256")
        x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)))
        y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=" * (-len(jwk["y"]) % 4)))
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().verify(
            signature_bytes,
            signature_base_bytes,
            ec.ECDSA(hashes.SHA256()),
        )


def now() -> int:
    return int(time.time())


def totp_code(secret_base32: str, timestamp: int | None = None) -> str:
    normalized = "".join(secret_base32.split()).upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    secret = base64.b32decode(normalized + padding)
    step = (timestamp or now()) // 30
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def saml_gateway_signature(
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    iat: int,
    exp: int,
) -> str:
    message = f"{issuer}\n{audience}\n{subject}\n{email}\n{iat}\n{exp}".encode("utf-8")
    digest = hmac.new(SAML_GATEWAY_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
    return b64url(digest)


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def ed25519_private_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_pem(key: Any) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_public_jwk(key: ed25519.Ed25519PrivateKey, kid: str | None = None) -> dict[str, Any]:
    raw_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk: dict[str, Any] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(raw_public),
        "alg": "EdDSA",
        "use": "sig",
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def rsa_public_jwk(key: rsa.RSAPrivateKey, kid: str, algorithm: str) -> dict[str, Any]:
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
        "alg": algorithm,
        "use": "sig",
        "kid": kid,
    }


def ec_public_jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, Any]:
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(public_numbers.x.to_bytes(32, "big")),
        "y": b64url(public_numbers.y.to_bytes(32, "big")),
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
    }


def dpop_proof(
    method: str,
    url: str,
    key: Any,
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
    nonce: str | None = None,
    access_token: str | None = None,
    jti: str | None = None,
) -> str:
    claims: dict[str, Any] = {
        "htm": method.upper(),
        "htu": url,
        "iat": now(),
        "jti": jti or str(uuid.uuid4()),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if access_token is not None:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode("utf-8")).digest())
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "dpop+jwt", "jwk": public_jwk or ed25519_public_jwk(key)},
    )


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    kty = jwk["kty"]
    if kty == "OKP":
        canonical = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "EC":
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        fail(f"unsupported dpop jwk kty: {kty}")
    raw = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url(hashlib.sha256(raw).digest())


def client_assertion(
    client_id: str,
    key: Any,
    *,
    jti: str | None = None,
    audience_path: str = "/token",
    algorithm: str = "EdDSA",
    kid: str = "private-key-jwt-e2e",
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": f"{ISSUER_URL}{audience_path}",
        "iat": now(),
        "exp": now() + 120,
        "jti": jti or str(uuid.uuid4()),
    }
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "JWT", "kid": kid},
    )


def authorization_request_object(
    client_id: str,
    key: Any,
    *,
    code_challenge: str,
    scope: str = "openid profile email",
    state: str = "jar-flow",
    nonce: str | None = None,
    audience: str | None = None,
    jti: str | None = None,
    algorithm: str = "EdDSA",
    kid: str = "private-key-jwt-e2e",
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "client_id": client_id,
        "aud": audience or ISSUER_URL,
        "exp": now() + 120,
        "nbf": now() - 5,
        "iat": now(),
        "jti": jti or str(uuid.uuid4()),
        "response_type": "code",
        "redirect_uri": CLIENT_REDIRECT_URI,
        "scope": scope,
        "state": state,
        "nonce": nonce or f"nonce-{state}",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if algorithm == "none":
        return jwt.encode(claims, key="", algorithm="none", headers={"typ": "oauth-authz-req+jwt"})
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=algorithm,
        headers={"typ": "oauth-authz-req+jwt", "kid": kid},
    )


def authorization_request_object_without_redirect_uri(
    client_id: str,
    key: Any,
    *,
    code_challenge: str,
    state: str,
) -> str:
    token = authorization_request_object(
        client_id,
        key,
        code_challenge=code_challenge,
        state=state,
    )
    headers = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    claims.pop("redirect_uri", None)
    return jwt.encode(
        claims,
        private_key_pem(key),
        algorithm=headers["alg"],
        headers={"typ": "oauth-authz-req+jwt", "kid": headers["kid"]},
    )


def csrf_header(session: requests.Session) -> dict[str, str]:
    token = session.cookies.get("nazo_oauth_csrf")
    if not token:
        fail("missing csrf cookie")
    return {"x-csrf-token": token}


def location_query(response: requests.Response) -> dict[str, list[str]]:
    location = response.headers.get("Location")
    if not location:
        fail("redirect response missing Location")
    return parse_qs(urlparse(location).query)


def scim_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {SCIM_BEARER_TOKEN}",
        "User-Agent": "nazo-oauth-codecov-e2e",
    }


def scim_user_payload(email: str, *, active: bool = True, family_name: str = "User") -> dict[str, Any]:
    return {
        "userName": email,
        "active": active,
        "name": {
            "formatted": f"SCIM {family_name}",
            "givenName": "SCIM",
            "familyName": family_name,
        },
        "emails": [{"value": email, "primary": True}],
    }


def exercise_scim_routes() -> None:
    missing = requests.get(f"{BASE_URL}/scim/v2/ServiceProviderConfig", timeout=10)
    expect_status("GET /scim/v2/ServiceProviderConfig missing bearer", missing, 401)
    check("scim_missing_bearer_error", expect_json(missing).get("scimType") == "unauthorized")

    config = expect_json(
        expect_status(
            "GET /scim/v2/ServiceProviderConfig",
            requests.get(f"{BASE_URL}/scim/v2/ServiceProviderConfig", headers=scim_headers(), timeout=10),
            200,
        )
    )
    check(
        "scim_service_provider_config_shape",
        config["authenticationSchemes"][0]["type"] == "oauthbearertoken"
        and config["filter"]["supported"] is True,
        config,
    )
    schemas = expect_json(
        expect_status(
            "GET /scim/v2/Schemas",
            requests.get(f"{BASE_URL}/scim/v2/Schemas", headers=scim_headers(), timeout=10),
            200,
        )
    )
    check("scim_schemas_shape", schemas["Resources"][0]["id"].endswith(":User"), schemas)
    resource_types = expect_json(
        expect_status(
            "GET /scim/v2/ResourceTypes",
            requests.get(f"{BASE_URL}/scim/v2/ResourceTypes", headers=scim_headers(), timeout=10),
            200,
        )
    )
    check("scim_resource_types_shape", resource_types["Resources"][0]["endpoint"] == "/Users")

    invalid_filter = requests.get(
        f"{BASE_URL}/scim/v2/Users",
        params={"filter": 'email eq "scim-user@example.com"'},
        headers=scim_headers(),
        timeout=10,
    )
    expect_status("GET /scim/v2/Users invalid filter", invalid_filter, 400)
    check("scim_invalid_filter_type", expect_json(invalid_filter).get("scimType") == "invalidFilter")

    created = expect_json(
        expect_status(
            "POST /scim/v2/Users",
            requests.post(
                f"{BASE_URL}/scim/v2/Users",
                json=scim_user_payload("scim-user@example.com", family_name="Created"),
                headers=scim_headers(),
                timeout=10,
            ),
            201,
        )
    )
    scim_user_id = created["id"]
    check(
        "scim_create_user_projection",
        created["userName"] == "scim-user@example.com"
        and created["active"] is True
        and "password_hash" not in created,
        created,
    )

    duplicate = requests.post(
        f"{BASE_URL}/scim/v2/Users",
        json=scim_user_payload("scim-user@example.com", family_name="Duplicate"),
        headers=scim_headers(),
        timeout=10,
    )
    expect_status("POST /scim/v2/Users duplicate", duplicate, 409)
    check("scim_duplicate_conflict", expect_json(duplicate).get("scimType") == "uniqueness")

    user_list = expect_json(
        expect_status(
            "GET /scim/v2/Users",
            requests.get(
                f"{BASE_URL}/scim/v2/Users",
                params={"startIndex": 1, "count": 10},
                headers=scim_headers(),
                timeout=10,
            ),
            200,
        )
    )
    check(
        "scim_list_contains_created_user",
        any(resource["id"] == scim_user_id for resource in user_list["Resources"]),
        user_list,
    )

    filtered = expect_json(
        expect_status(
            "GET /scim/v2/Users filtered",
            requests.get(
                f"{BASE_URL}/scim/v2/Users",
                params={"filter": 'userName eq "SCIM-USER@example.com"'},
                headers=scim_headers(),
                timeout=10,
            ),
            200,
        )
    )
    check(
        "scim_filter_normalizes_email",
        filtered["totalResults"] == 1 and filtered["Resources"][0]["id"] == scim_user_id,
        filtered,
    )

    loaded = expect_json(
        expect_status(
            "GET /scim/v2/Users/{id}",
            requests.get(
                f"{BASE_URL}/scim/v2/Users/{scim_user_id}",
                headers=scim_headers(),
                timeout=10,
            ),
            200,
        )
    )
    check("scim_get_user_projection", loaded["id"] == scim_user_id and "role" not in loaded, loaded)

    replacement = expect_json(
        expect_status(
            "PUT /scim/v2/Users/{id}",
            requests.put(
                f"{BASE_URL}/scim/v2/Users/{scim_user_id}",
                json=scim_user_payload("scim-replaced@example.com", family_name="Replaced"),
                headers=scim_headers(),
                timeout=10,
            ),
            200,
        )
    )
    check(
        "scim_replace_user_updates_identity",
        replacement["userName"] == "scim-replaced@example.com"
        and replacement["name"]["familyName"] == "Replaced",
        replacement,
    )

    patched = expect_json(
        expect_status(
            "PATCH /scim/v2/Users/{id}",
            requests.patch(
                f"{BASE_URL}/scim/v2/Users/{scim_user_id}",
                json={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [
                        {"op": "replace", "path": "active", "value": False},
                        {"op": "replace", "path": "name.familyName", "value": "Patched"},
                    ],
                },
                headers=scim_headers(),
                timeout=10,
            ),
            200,
        )
    )
    check(
        "scim_patch_user_updates_allowed_fields",
        patched["active"] is False and patched["name"]["familyName"] == "Patched",
        patched,
    )

    missing_patch = requests.patch(
        f"{BASE_URL}/scim/v2/Users/{uuid.uuid4()}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": True}],
        },
        headers=scim_headers(),
        timeout=10,
    )
    expect_status("PATCH /scim/v2/Users missing", missing_patch, 404)

    expect_status(
        "DELETE /scim/v2/Users/{id}",
        requests.delete(
            f"{BASE_URL}/scim/v2/Users/{scim_user_id}",
            headers=scim_headers(),
            timeout=10,
        ),
        204,
    )
    missing_delete = requests.delete(
        f"{BASE_URL}/scim/v2/Users/{uuid.uuid4()}",
        headers=scim_headers(),
        timeout=10,
    )
    expect_status("DELETE /scim/v2/Users missing", missing_delete, 404)


def seed_malformed_passkey(user_id: str, credential_id: str = "malformed-e2e-credential") -> str:
    passkey_id = str(uuid.uuid4())
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_passkey_credentials
                    (id, tenant_id, user_id, credential_id, credential, label, sign_count)
                VALUES
                    (%s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (
                    passkey_id,
                    DEFAULT_TENANT_ID,
                    user_id,
                    credential_id,
                    json.dumps(
                        {
                            "id": [1, 2, 3, 4],
                            "public_key_cose": [5, 6, 7],
                            "counter": 9,
                            "transports": ["internal"],
                            "aaguid": [0] * 16,
                        }
                    ),
                    "Seeded malformed passkey",
                    9,
                ),
            )
    return passkey_id


def exercise_passkey_profile_edges(user: requests.Session, user_id: str) -> None:
    passkey_id = seed_malformed_passkey(user_id)
    listed = expect_json(
        expect_status(
            "GET /auth/me/passkeys seeded malformed",
            user.get(f"{BASE_URL}/auth/me/passkeys", timeout=10),
            200,
        )
    )
    check(
        "passkey_list_projects_public_fields",
        any(
            item["id"] == passkey_id
            and item["label"] == "Seeded malformed passkey"
            and item["sign_count"] == 9
            and "credential" not in item
            for item in listed["passkeys"]
        ),
        listed,
    )

    registration_begin = expect_json(
        expect_status(
            "POST /auth/me/passkeys/registration/begin with existing credential",
            user.post(
                f"{BASE_URL}/auth/me/passkeys/registration/begin",
                json={"label": "New passkey"},
                headers=csrf_header(user),
                timeout=10,
            ),
            200,
        )
    )
    check(
        "passkey_registration_begin_excludes_existing_credential",
        registration_begin["publicKey"]["excludeCredentials"][0]["id"] == "AQIDBA",
        registration_begin,
    )
    expect_status(
        "POST /auth/me/passkeys/registration/finish malformed response",
        user.post(
            f"{BASE_URL}/auth/me/passkeys/registration/finish",
            json={
                "ceremony_id": "B" * 32,
                "response": {
                    "id": "AQIDBA",
                    "rawId": "AQIDBA",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30",
                        "attestationObject": "e30",
                    },
                },
            },
            headers=csrf_header(user),
            timeout=10,
        ),
        400,
    )

    passkey_login_begin = expect_json(
        expect_status(
            "POST /auth/passkey/begin with existing credential",
            requests.post(
                f"{BASE_URL}/auth/passkey/begin",
                json={"email": USER_EMAIL},
                timeout=10,
            ),
            200,
        )
    )
    check(
        "passkey_login_begin_returns_allowed_credential",
        passkey_login_begin["publicKey"]["allowCredentials"][0]["id"] == "AQIDBA",
        passkey_login_begin,
    )
    expect_status(
        "POST /auth/passkey/finish malformed response",
        requests.post(
            f"{BASE_URL}/auth/passkey/finish",
            json={
                "ceremony_id": "C" * 32,
                "response": {
                    "id": "AQIDBA",
                    "rawId": "AQIDBA",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30",
                        "authenticatorData": "e30",
                        "signature": "e30",
                        "userHandle": "e30",
                    },
                },
            },
            timeout=10,
        ),
        400,
    )

    missing_passkey = user.delete(
        f"{BASE_URL}/auth/me/passkeys/{uuid.uuid4()}",
        headers=csrf_header(user),
        timeout=10,
    )
    expect_status("DELETE /auth/me/passkeys missing", missing_passkey, 404)

    expect_status(
        "DELETE /auth/me/passkeys seeded malformed",
        user.delete(
            f"{BASE_URL}/auth/me/passkeys/{passkey_id}",
            headers=csrf_header(user),
            timeout=10,
        ),
        204,
    )
    empty_list = expect_json(
        expect_status(
            "GET /auth/me/passkeys after delete",
            user.get(f"{BASE_URL}/auth/me/passkeys", timeout=10),
            200,
        )
    )
    check(
        "passkey_delete_removes_current_user_credential",
        all(item["id"] != passkey_id for item in empty_list["passkeys"]),
        empty_list,
    )


def exercise_oidc_logout(public_client_id: str) -> None:
    redirect_without_client = requests.get(
        f"{BASE_URL}/logout",
        params={"post_logout_redirect_uri": "https://client.example/logout/callback?flow=rp"},
        timeout=10,
    )
    expect_status("GET /logout redirect without client", redirect_without_client, 400)
    check(
        "oidc_logout_redirect_requires_client",
        expect_json(redirect_without_client).get("error") == "invalid_request",
    )

    duplicate_parameter = requests.get(
        f"{BASE_URL}/logout?client_id=a&client_id=b",
        timeout=10,
    )
    expect_status("GET /logout duplicate client_id", duplicate_parameter, 400)

    logout_user = requests.Session()
    login(logout_user, USER_EMAIL, USER_PASSWORD, "POST /auth/login OIDC logout no redirect")
    unauthorized_logout = expect_json(
        expect_status(
            "GET /logout without CSRF or id_token_hint rejects session clear",
            logout_user.get(f"{BASE_URL}/logout", timeout=10),
            400,
        )
    )
    check(
        "oidc_logout_rejects_unauthorized_session_clear",
        unauthorized_logout.get("error") == "invalid_request",
        unauthorized_logout,
    )
    expect_status(
        "GET /auth/me after unauthorized OIDC logout",
        logout_user.get(f"{BASE_URL}/auth/me", timeout=10),
        200,
    )
    logout_response = expect_json(
        expect_status(
            "GET /logout with CSRF clears OP session",
            logout_user.get(f"{BASE_URL}/logout", headers=csrf_header(logout_user), timeout=10),
            200,
        )
    )
    check("oidc_logout_success_body", logout_response.get("success") is True, logout_response)
    expect_status(
        "GET /auth/me after OIDC logout",
        logout_user.get(f"{BASE_URL}/auth/me", timeout=10),
        401,
    )

    redirect_user = requests.Session()
    login(redirect_user, USER_EMAIL, USER_PASSWORD, "POST /auth/login OIDC logout redirect")
    redirect = expect_status(
        "GET /logout registered post_logout_redirect_uri",
        redirect_user.get(
            f"{BASE_URL}/logout",
            params={
                "client_id": public_client_id,
                "post_logout_redirect_uri": "https://client.example/logout/callback?flow=rp",
                "state": "logout-state",
            },
            headers=csrf_header(redirect_user),
            allow_redirects=False,
            timeout=10,
        ),
        302,
    )
    check(
        "oidc_logout_redirect_preserves_registered_query_and_state",
        redirect.headers.get("Location")
        == "https://client.example/logout/callback?flow=rp&state=logout-state",
        redirect.headers,
    )
    expect_status(
        "GET /auth/me after OIDC logout redirect",
        redirect_user.get(f"{BASE_URL}/auth/me", timeout=10),
        401,
    )

    invalid_redirect = requests.get(
        f"{BASE_URL}/logout",
        params={
            "client_id": public_client_id,
            "post_logout_redirect_uri": "https://client.example/logout/unregistered",
        },
        timeout=10,
    )
    expect_status("GET /logout unregistered post_logout_redirect_uri", invalid_redirect, 400)
    check(
        "oidc_logout_unregistered_redirect_error",
        expect_json(invalid_redirect).get("error") == "invalid_request",
    )

    unknown_client = requests.get(
        f"{BASE_URL}/logout",
        params={"client_id": "missing-client"},
        timeout=10,
    )
    expect_status("GET /logout unknown client", unknown_client, 400)
    check("oidc_logout_unknown_client_error", expect_json(unknown_client).get("error") == "invalid_request")


def exercise_saml_federation() -> None:
    federated = requests.Session()
    federated.headers.update({"User-Agent": "nazo-oauth-full-e2e-federation/1"})
    email = "federated-saml-full-e2e@example.com"
    subject = "saml-subject-full-e2e"
    issued_at = now()
    expires_at = issued_at + 120
    payload = {
        "issuer": SAML_GATEWAY_ISSUER,
        "audience": SAML_GATEWAY_AUDIENCE,
        "subject": subject,
        "email": email,
        "name": "Federated SAML User",
        "iat": issued_at,
        "exp": expires_at,
    }
    payload["signature"] = saml_gateway_signature(
        payload["issuer"],
        payload["audience"],
        payload["subject"],
        email,
        issued_at,
        expires_at,
    )

    response = expect_json(
        expect_status(
            "POST /auth/federation/saml/acs",
            federated.post(
                f"{BASE_URL}/auth/federation/saml/acs",
                json=payload,
                timeout=10,
            ),
            200,
        )
    )
    check(
        "saml_federation_sets_session",
        response.get("mfa_required") is False
        and bool(response.get("csrf_token"))
        and bool(federated.cookies.get(SESSION_COOKIE_NAME)),
        response,
    )
    me = expect_json(
        expect_status(
            "GET /auth/me after SAML federation",
            federated.get(f"{BASE_URL}/auth/me", timeout=10),
            200,
        )
    )
    check(
        "saml_federation_user_profile",
        me.get("email") == email
        and me.get("display_name") == "Federated SAML User",
        me,
    )
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT provider_type, provider_id, subject, email, claims->>'sub'
                FROM external_identity_links
                WHERE user_id = %s
                """,
                (me["id"],),
            )
            row = cur.fetchone()
    check(
        "saml_federation_external_identity_link",
        row == ("saml", SAML_GATEWAY_ISSUER, subject, email, subject),
        row,
    )

    replay = expect_json(
        expect_status(
            "POST /auth/federation/saml/acs replay",
            federated.post(
                f"{BASE_URL}/auth/federation/saml/acs",
                json=payload,
                timeout=10,
            ),
            401,
        )
    )
    check(
        "saml_federation_replay_is_rejected",
        replay.get("error") == "access_denied",
        replay,
    )

    fresh_issued_at = max(now(), issued_at + 1)
    fresh_expires_at = fresh_issued_at + 120
    fresh_payload = dict(payload)
    fresh_payload.update(
        {
            "iat": fresh_issued_at,
            "exp": fresh_expires_at,
            "signature": saml_gateway_signature(
                payload["issuer"],
                payload["audience"],
                payload["subject"],
                email,
                fresh_issued_at,
                fresh_expires_at,
            ),
        }
    )
    existing_link = expect_json(
        expect_status(
            "POST /auth/federation/saml/acs existing link",
            federated.post(
                f"{BASE_URL}/auth/federation/saml/acs",
                json=fresh_payload,
                timeout=10,
            ),
            200,
        )
    )
    check(
        "saml_federation_existing_link_reauthenticates",
        existing_link.get("mfa_required") is False
        and bool(federated.cookies.get(SESSION_COOKIE_NAME)),
        existing_link,
    )


def exercise_oidc_federation_start() -> None:
    start = expect_status(
        f"GET {OIDC_START_PATH}",
        requests.get(f"{BASE_URL}{OIDC_START_PATH}", allow_redirects=False, timeout=10),
        302,
    )
    location = start.headers.get("Location", "")
    parsed = urlparse(location)
    query = parse_qs(parsed.query)
    state_token = query.get("state", [""])[0]
    nonce = query.get("nonce", [""])[0]
    check(
        "oidc_federation_start_redirect_binds_pkce_state_nonce",
        parsed.scheme == "https"
        and parsed.netloc == "issuer.example"
        and parsed.path == "/authorize"
        and query.get("response_type") == ["code"]
        and query.get("client_id") == [OIDC_CLIENT_ID]
        and query.get("redirect_uri") == [OIDC_REDIRECT_URI]
        and query.get("scope") == [OIDC_SCOPE]
        and query.get("code_challenge_method") == ["S256"]
        and bool(query.get("code_challenge", [""])[0])
        and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", state_token) is not None
        and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce) is not None,
        location,
    )
    missing_state = expect_json(
        expect_status(
            f"GET {OIDC_CALLBACK_PATH} missing state",
            requests.get(
                f"{BASE_URL}{OIDC_CALLBACK_PATH}",
                params={"state": "A" * 32, "code": "authorization-code"},
                timeout=10,
            ),
            400,
        )
    )
    check("oidc_federation_callback_missing_state", missing_state.get("error") == "invalid_request")


def pkce_pair() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class SmtpSink:
    def __init__(self) -> None:
        self.messages: list[bytes] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        self.messages.append(envelope.content)
        return "250 OK"

    def wait_for_code(self) -> str:
        deadline = time.time() + 10
        while time.time() < deadline:
            for raw in self.messages:
                msg = message_from_bytes(raw)
                bodies: list[str] = []
                if msg.is_multipart():
                    for part in msg.walk():
                        payload = part.get_payload(decode=True)
                        if payload:
                            bodies.append(payload.decode("utf-8", errors="replace"))
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        bodies.append(payload.decode("utf-8", errors="replace"))
                text = "\n".join(bodies)
                for pattern in (
                    r"验证码是\s*(\d{6})",
                    r"验证码[^\d]{0,40}(\d{6})",
                    r">\s*(\d{6})\s*</div>",
                ):
                    match = re.search(pattern, text)
                    if match:
                        return match.group(1)
            time.sleep(0.1)
        fail("verification code email was not received")
        raise AssertionError("unreachable")


def assert_destructive_targets_are_e2e() -> None:
    database = urlparse(DATABASE_URL)
    valkey = urlparse(VALKEY_URL)
    base = urlparse(BASE_URL)

    actual = {
        "database_host": database.hostname,
        "database_port": database.port,
        "database_name": database.path.lstrip("/"),
        "valkey_host": valkey.hostname,
        "valkey_port": valkey.port,
        "valkey_db": valkey.path or "/0",
        "base_host": base.hostname,
        "base_port": base.port,
    }
    allowed_targets = [
        {
            "database_host": "nazo-oauth-e2e-postgres",
            "database_port": 5432,
            "database_name": "oauth",
            "valkey_host": "nazo-oauth-e2e-valkey",
            "valkey_port": 6379,
            "valkey_db": "/0",
            "base_host": "nazo-oauth-e2e-server",
            "base_port": 8000,
        }
    ]
    if os.environ.get("E2E_ALLOW_SAME_CONTAINER_LOOPBACK") == "1":
        allowed_targets.append(
            {
                "database_host": "postgres",
                "database_port": None,
                "database_name": "oauth",
                "valkey_host": "valkey",
                "valkey_port": None,
                "valkey_db": "/0",
                "base_host": "127.0.0.1",
                "base_port": None,
            }
        )
    if os.environ.get("E2E_ALLOW_CODEX_COVERAGE_LOOPBACK") == "1":
        allowed_targets.append(
            {
                "database_host": "127.0.0.1",
                "database_port": 15432,
                "database_name": "oauth",
                "valkey_host": "127.0.0.1",
                "valkey_port": 16383,
                "valkey_db": "/0",
                "base_host": "127.0.0.1",
                "base_port": 18000,
            }
        )
        allowed_targets.append(
            {
                "database_host": "nazo-oauth-codecov-postgres",
                "database_port": 5432,
                "database_name": "oauth",
                "valkey_host": "nazo-oauth-codecov-valkey",
                "valkey_port": 6379,
                "valkey_db": "/0",
                "base_host": "127.0.0.1",
                "base_port": 18000,
            }
        )
    if actual not in allowed_targets:
        fail(f"refusing destructive seed outside Docker E2E targets: {actual}")


def seed_prerequisites() -> None:
    assert_destructive_targets_are_e2e()
    password_hash = PasswordHasher().hash(ADMIN_PASSWORD)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT module_id, desired_mode, revision
                FROM runtime_module_desired_states
                ORDER BY module_id
                """
            )
            desired_states_before_reset = cur.fetchall()
            if not desired_states_before_reset:
                fail("runtime module desired states were not seeded before E2E reset")
            cur.execute(
                """
                TRUNCATE TABLE
                    access_token_revocations,
                    oauth_tokens,
                    user_client_grants,
                    client_access_requests,
                    external_identity_links,
                    oauth_clients
                RESTART IDENTITY CASCADE
                """
            )
            # DELETE preserves control-plane rows whose audit actor references use
            # ON DELETE SET NULL. TRUNCATE ... CASCADE would silently erase the
            # durable runtime-module desired state while the servers are running.
            cur.execute("DELETE FROM users")
            cur.execute(
                """
                SELECT module_id, desired_mode, revision
                FROM runtime_module_desired_states
                ORDER BY module_id
                """
            )
            desired_states_after_reset = cur.fetchall()
            if desired_states_after_reset != desired_states_before_reset:
                fail("E2E reset changed durable runtime module desired states")
            cur.execute(
                """
                INSERT INTO users (
                    tenant_id, realm_id, organization_id, username, email,
                    password_hash, email_verified, display_name, role, admin_level,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, 'admin', 10, TRUE)
                """,
                (
                    DEFAULT_TENANT_ID,
                    DEFAULT_REALM_ID,
                    DEFAULT_ORGANIZATION_ID,
                    "admin_full_e2e",
                    ADMIN_EMAIL,
                    password_hash,
                    "Admin E2E",
                ),
            )
        conn.commit()

    redis.Redis.from_url(VALKEY_URL, decode_responses=True).flushdb()


def wait_for_service() -> None:
    deadline = time.time() + 30
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.5)
    fail(f"service did not become healthy: {last_error}")


def login(session: requests.Session, email: str, password: str, check_name: str) -> dict[str, Any]:
    response = session.post(
        f"{BASE_URL}/auth/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    expect_status(check_name, response, 200)
    body = expect_json(response)
    check(f"{check_name}_sets_csrf", bool(body.get("csrf_token")))
    return body


def create_client(
    admin: requests.Session,
    payload: dict[str, Any],
    check_name: str,
) -> dict[str, Any]:
    response = admin.post(
        f"{BASE_URL}/admin/clients",
        json=payload,
        headers=csrf_header(admin),
        timeout=10,
    )
    expect_status(check_name, response, 201)
    return expect_json(response)


def authorize_request(
    user: requests.Session,
    client_id: str,
    *,
    state: str,
    nonce: str | None = "nonce-e2e",
    extra_params: dict[str, Any] | None = None,
    method: str = "GET",
) -> tuple[str, str]:
    verifier, challenge = pkce_pair()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT_URI,
        "scope": "openid profile email address phone offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if nonce is not None:
        params["nonce"] = nonce
    if extra_params:
        params.update(extra_params)
    if method == "POST":
        response = user.post(f"{BASE_URL}/authorize", data=params, allow_redirects=False, timeout=10)
    else:
        response = user.get(f"{BASE_URL}/authorize", params=params, allow_redirects=False, timeout=10)
    expect_status(f"authorize_{state}", response, 302)
    request_id = location_query(response).get("request_id", [None])[0]
    if not request_id:
        fail("authorize did not redirect to consent request")

    response = user.get(
        f"{BASE_URL}/authorize/consent",
        params={"request_id": request_id},
        timeout=10,
    )
    expect_status(f"authorize_consent_{state}", response, 200)
    consent = expect_json(response)
    check(f"authorize_consent_payload_{state}", consent["request_id"] == request_id)

    return request_id, verifier


def approve_authorization(
    user: requests.Session,
    request_id: str,
    verifier: str,
    *,
    state: str,
) -> tuple[str, str]:
    response = user.post(
        f"{BASE_URL}/authorize/decision",
        data={
            "request_id": request_id,
            "decision": "approve",
            "csrf_token": user.cookies.get("nazo_oauth_csrf"),
        },
        allow_redirects=False,
        timeout=10,
    )
    expect_status(f"authorize_decision_approve_{state}", response, 302)
    query = location_query(response)
    code = query.get("code", [None])[0]
    check(
        f"authorize_code_issued_{state}",
        bool(code),
        response.headers.get("Location", ""),
    )
    check(f"authorize_state_roundtrip_{state}", query.get("state", [None])[0] == state)
    return code, verifier


def consent_request_from_redirect(response: requests.Response, check_name: str) -> str:
    request_id = location_query(response).get("request_id", [None])[0]
    check(f"{check_name}_request_id", bool(request_id))
    return request_id or ""


def expect_authorization_error_redirect(
    check_name: str,
    response: requests.Response,
    error: str,
    *,
    state: str | None = None,
) -> None:
    expect_status(check_name, response, 302)
    query = location_query(response)
    check(f"{check_name}_error", query.get("error") == [error])
    check(f"{check_name}_issuer", query.get("iss") == [ISSUER_URL])
    if state is not None:
        check(f"{check_name}_state", query.get("state") == [state])


def token_plain(form: dict[str, str], check_name: str) -> dict[str, Any]:
    response = requests.post(f"{BASE_URL}/token", data=form, timeout=10)
    expect_status(check_name, response, 200)
    return expect_json(response)


def token_basic(
    client_id: str,
    client_secret: str,
    form: dict[str, str],
    check_name: str,
) -> dict[str, Any]:
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    response = requests.post(
        f"{BASE_URL}/token",
        data=form,
        headers={"Authorization": f"Basic {credentials}"},
        timeout=10,
    )
    expect_status(check_name, response, 200)
    return expect_json(response)


def request_dpop_nonce(
    form: dict[str, str],
    key: Any,
    path: str = "/token",
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
) -> str:
    url = f"{BASE_URL}{path}"
    proof_url = f"{ISSUER_URL}{path}"
    response = requests.post(
        url,
        data=form,
        headers={
            "DPoP": dpop_proof(
                "POST",
                proof_url,
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
        },
        timeout=10,
    )
    expect_status(f"dpop_nonce_challenge_{path}_{len(checks)}", response, 400)
    body = expect_json(response)
    check(f"dpop_nonce_error_{path}_{len(checks)}", body.get("error") == "use_dpop_nonce")
    nonce = response.headers.get("DPoP-Nonce")
    check(f"dpop_nonce_header_{path}_{len(checks)}", bool(nonce))
    return nonce or ""


def token_with_dpop(
    form: dict[str, str],
    key: Any,
    nonce: str,
    check_name: str,
    *,
    algorithm: str = "EdDSA",
    public_jwk: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = requests.post(
        f"{BASE_URL}/token",
        data=form,
        headers={
            "DPoP": dpop_proof(
                "POST",
                f"{ISSUER_URL}/token",
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
                nonce=nonce,
            )
        },
        timeout=10,
    )
    expect_status(check_name, response, 200)
    return expect_json(response)


def exercise_fapi_http_signature_profile(admin: requests.Session) -> None:
    signed_base = os.environ.get("E2E_SIGNED_BASE_URL")
    check("fapi_http_signature_signed_base_configured", bool(signed_base))
    target = f"{ISSUER_URL.rstrip('/')}/fapi/resource"
    kid = "fapi-http-signature-e2e"
    other_kid = "fapi-http-signature-other-e2e"
    key = ed25519.Ed25519PrivateKey.generate()
    other_key = ed25519.Ed25519PrivateKey.generate()

    def signature_client(
        name: str,
        public_key: ed25519.Ed25519PrivateKey,
        key_id: str,
        *,
        require_dpop: bool = False,
    ) -> dict[str, Any]:
        return create_client(
            admin,
            {
                "client_name": name,
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [target],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
                "require_dpop_bound_tokens": require_dpop,
                "jwks": {"keys": [ed25519_public_jwk(public_key, key_id)]},
            },
            f"POST /admin/clients {name}",
        )

    client = signature_client("FAPI HTTP Signature E2E", key, kid)
    other_client = signature_client("FAPI HTTP Signature Other E2E", other_key, other_kid)
    dpop_client = signature_client("FAPI HTTP Signature DPoP E2E", key, kid, require_dpop=True)

    def access_token(client_record: dict[str, Any]) -> str:
        token = expect_json(
            expect_status(
                "POST /token FAPI HTTP signature client_credentials",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_record["client_id"],
                        "client_secret": client_record["client_secret"],
                        "scope": "profile",
                        "resource": target,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        return str(token["access_token"])

    token = access_token(client)
    other_token = access_token(other_client)
    dpop_key = ed25519.Ed25519PrivateKey.generate()
    dpop_token_form = {
        "grant_type": "client_credentials",
        "client_id": dpop_client["client_id"],
        "client_secret": dpop_client["client_secret"],
        "scope": "profile",
        "resource": target,
    }
    dpop_token_nonce = request_dpop_nonce(dpop_token_form, dpop_key)
    dpop_token = token_with_dpop(
        dpop_token_form,
        dpop_key,
        dpop_token_nonce,
        "POST /token FAPI HTTP signature DPoP client_credentials",
    )["access_token"]
    server_jwks = expect_json(requests.get(f"{BASE_URL}/jwks.json", timeout=10))

    def signed_request(
        case: str,
        *,
        method: str = "GET",
        query: str,
        body: bytes = b"",
        signing_key: ed25519.Ed25519PrivateKey = key,
        signing_kid: str = kid,
        signed_method: str | None = None,
        signed_target: str | None = None,
        signed_authorization: str | None = None,
        sent_authorization: str | None = None,
        signed_dpop: str | None = None,
        sent_dpop: str | None = None,
        signed_extra_headers: dict[str, str] | None = None,
        sent_extra_headers: dict[str, str] | None = None,
        signed_body: bytes | None = None,
        created: int | None = None,
        expected_status: int,
    ) -> tuple[requests.Response, dict[str, str], str]:
        target_uri = f"{target}?case={query}"
        authorization = sent_authorization or f"Bearer {token}"
        headers = fapi_http_signature_fields(
            signing_key,
            signing_kid,
            signed_method or method,
            signed_target or target_uri,
            signed_authorization or authorization,
            body=body if signed_body is None else signed_body,
            dpop=signed_dpop,
            created=created,
            extra_headers=signed_extra_headers,
        )
        headers["Authorization"] = authorization
        if sent_dpop is not None:
            headers["DPoP"] = sent_dpop
        for name, value in (sent_extra_headers or signed_extra_headers or {}).items():
            headers[name] = value
        response = requests.request(
            method,
            f"{signed_base}/fapi/resource?case={query}",
            headers=headers,
            data=body,
            timeout=10,
        )
        check(case, response.status_code == expected_status, response.status_code)
        verify_fapi_http_signature_response(
            response,
            server_jwks,
            method=method,
            target_uri=target_uri,
            request_body=body,
            request_headers=headers,
        )
        return response, headers, target_uri

    def handle_signed_request(case: str, parameters: dict[str, object]) -> None:
        signed_request(case, **parameters)

    def handle_signed_post(case: str, parameters: dict[str, object]) -> None:
        signed_request(case, method="POST", body=b'{"operation":"read"}', **parameters)

    def handle_response_binding(case: str, parameters: dict[str, object]) -> None:
        response, _, _ = signed_request(case, **parameters)
        check("fapi_http_signature_response_binding_body", expect_json(response).get("client_id") == client["client_id"])

    def handle_response_header_tamper(case: str, parameters: dict[str, object]) -> None:
        header = str(parameters.pop("header"))
        value = str(parameters.pop("value"))
        response, request_headers, target_uri = signed_request(f"{case}_baseline", **parameters)
        response.headers[header] = value
        rejected = False
        try:
            verify_fapi_http_signature_response(
                response,
                server_jwks,
                method="GET",
                target_uri=target_uri,
                request_body=b"",
                request_headers=request_headers,
            )
        except InvalidSignature:
            rejected = True
        check(case, rejected)

    def handle_tampered_uri(case: str, parameters: dict[str, object]) -> None:
        signed_request(case, signed_target=f"{target}?case=different-uri", **parameters)

    def handle_tampered_authorization(case: str, parameters: dict[str, object]) -> None:
        signed_request(
            case,
            signed_authorization=f"Bearer {token}",
            sent_authorization=f"Bearer {other_token}",
            **parameters,
        )

    def handle_tampered_body(case: str, parameters: dict[str, object]) -> None:
        signed_request(
            case,
            method="POST",
            body=b'{"operation":"altered"}',
            signed_body=b'{"operation":"signed"}',
            **parameters,
        )

    def handle_relative_created(case: str, parameters: dict[str, object]) -> None:
        created_offset = int(parameters.pop("created_offset"))
        signed_request(case, created=now() + created_offset, **parameters)

    def handle_replay(case: str, parameters: dict[str, object]) -> None:
        response, headers, target_uri = signed_request(case, **parameters)
        replay = requests.get(
            f"{signed_base}/fapi/resource?case={parameters['query']}",
            headers=headers,
            timeout=10,
        )
        check("fapi_http_signature_replay_second_request_rejected", replay.status_code == 401)
        verify_fapi_http_signature_response(
            replay,
            server_jwks,
            method="GET",
            target_uri=target_uri,
            request_body=b"",
            request_headers=headers,
        )
        check("fapi_http_signature_replay_first_request_succeeded", response.status_code == 200)

    def handle_wrong_key(case: str, parameters: dict[str, object]) -> None:
        signed_request(case, signing_key=ed25519.Ed25519PrivateKey.generate(), **parameters)

    def handle_wrong_client(case: str, parameters: dict[str, object]) -> None:
        signed_request(case, signing_key=other_key, signing_kid=other_kid, **parameters)

    def handle_unsigned_fallback(case: str, parameters: dict[str, object]) -> None:
        expected_status = int(parameters["expected_status"])
        response = requests.get(
            f"{BASE_URL}/fapi/resource",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        check(
            case,
            response.status_code == expected_status
            and "Signature" not in response.headers
            and "Signature-Input" not in response.headers,
            response.status_code,
        )

    def handle_signed_dpop(case: str, parameters: dict[str, object]) -> None:
        query = str(parameters["query"])
        expected_status = int(parameters["expected_status"])
        target_uri = f"{target}?case={query}"
        authorization = f"DPoP {dpop_token}"
        initial_proof = dpop_proof("GET", target_uri, dpop_key, access_token=dpop_token)
        challenge_headers = fapi_http_signature_fields(
            key,
            kid,
            "GET",
            target_uri,
            authorization,
            dpop=initial_proof,
        )
        challenge = requests.get(
            f"{signed_base}/fapi/resource?case={query}",
            headers=challenge_headers,
            timeout=10,
        )
        check("fapi_http_signature_dpop_nonce_challenge", challenge.status_code == 401)
        nonce = challenge.headers.get("DPoP-Nonce")
        check("fapi_http_signature_dpop_nonce_present", bool(nonce))
        verify_fapi_http_signature_response(
            challenge,
            server_jwks,
            method="GET",
            target_uri=target_uri,
            request_body=b"",
            request_headers=challenge_headers,
        )
        proof = dpop_proof(
            "GET",
            target_uri,
            dpop_key,
            nonce=nonce,
            access_token=dpop_token,
        )
        response, headers, _ = signed_request(
            case,
            query=query,
            sent_authorization=authorization,
            signed_dpop=proof,
            sent_dpop=proof,
            expected_status=expected_status,
        )
        check("fapi_http_signature_dpop_is_covered", '"dpop"' in headers["Signature-Input"])
        check("fapi_http_signature_dpop_client_binding", expect_json(response).get("client_id") == dpop_client["client_id"])

    handlers = {
        "relative_created": handle_relative_created,
        "replay": handle_replay,
        "response_binding": handle_response_binding,
        "response_header_tamper": handle_response_header_tamper,
        "signed_dpop": handle_signed_dpop,
        "signed_post": handle_signed_post,
        "signed_request": handle_signed_request,
        "tampered_authorization": handle_tampered_authorization,
        "tampered_body": handle_tampered_body,
        "tampered_uri": handle_tampered_uri,
        "unsigned_fallback": handle_unsigned_fallback,
        "wrong_client": handle_wrong_client,
        "wrong_key": handle_wrong_key,
    }
    executed = execute_http_signature_case_registry(HTTP_SIGNATURE_CASE_REGISTRY, handlers)
    check(
        "fapi_http_signature_runtime_registry_exact",
        set(executed) == HTTP_SIGNATURE_REQUIRED_E2E_CASES
        and len(executed) == len(HTTP_SIGNATURE_REQUIRED_E2E_CASES),
        executed,
    )


def run() -> None:
    seed_prerequisites()
    wait_for_service()

    smtp_sink = SmtpSink()
    smtp = Controller(smtp_sink, hostname=E2E_SMTP_BIND_HOST, port=1025)
    smtp.start()
    try:
        anonymous = requests.Session()
        user = requests.Session()
        admin = requests.Session()

        health = expect_status("GET /health", anonymous.get(f"{BASE_URL}/health", timeout=10), 200)
        check("health_body", expect_json(health).get("status") == "正常")

        discovery = expect_json(
            expect_status(
                "GET /.well-known/openid-configuration",
                anonymous.get(f"{BASE_URL}/.well-known/openid-configuration", timeout=10),
                200,
            )
        )
        check(
            "discovery_metadata",
            "private_key_jwt" in discovery["token_endpoint_auth_methods_supported"]
            and "private_key_jwt" in discovery["introspection_endpoint_auth_methods_supported"]
            and set(discovery["revocation_endpoint_auth_signing_alg_values_supported"])
            == {"EdDSA", "RS256", "ES256", "PS256"}
            and set(discovery["request_object_signing_alg_values_supported"])
            == {"none", "EdDSA", "RS256", "ES256", "PS256"}
            and set(discovery["dpop_signing_alg_values_supported"])
            == {"EdDSA", "ES256"}
            and {"address", "phone"}.issubset(set(discovery["scopes_supported"]))
            and "email_verified" in discovery["claims_supported"]
            and {"address", "phone_number", "phone_number_verified"}.issubset(
                set(discovery["claims_supported"])
            ),
        )
        oauth_metadata = expect_json(
            expect_status(
                "GET /.well-known/oauth-authorization-server",
                anonymous.get(f"{BASE_URL}/.well-known/oauth-authorization-server", timeout=10),
                200,
            )
        )
        check(
            "oauth_authorization_server_metadata",
            oauth_metadata["issuer"] == discovery["issuer"]
            and oauth_metadata["authorization_endpoint"] == discovery["authorization_endpoint"],
        )

        jwks = expect_json(
            expect_status("GET /jwks.json", anonymous.get(f"{BASE_URL}/jwks.json", timeout=10), 200)
        )
        check("jwks_has_keys", bool(jwks.get("keys")))

        captcha = expect_json(
            expect_status(
                "GET /auth/captcha-config",
                anonymous.get(f"{BASE_URL}/auth/captcha-config", timeout=10),
                200,
            )
        )
        check("captcha_config_shape", captcha.get("registration_enabled") is True)

        cors = anonymous.options(
            f"{BASE_URL}/token",
            headers={
                "Origin": E2E_CORS_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,dpop",
            },
            timeout=10,
        )
        check("OPTIONS /token CORS", cors.status_code < 400, cors.text)
        check(
            "CORS allow origin",
            cors.headers.get("access-control-allow-origin") == E2E_CORS_ORIGIN,
        )
        cors_csrf = anonymous.options(
            f"{BASE_URL}/token",
            headers={
                "Origin": E2E_CORS_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-csrf-token",
            },
            timeout=10,
        )
        check(
            "OPTIONS /token rejects CSRF header",
            cors_csrf.status_code >= 400
            and "access-control-allow-origin" not in cors_csrf.headers,
            {"status": cors_csrf.status_code, "headers": dict(cors_csrf.headers)},
        )
        cors_actual = anonymous.get(
            f"{BASE_URL}/health",
            headers={"Origin": E2E_CORS_ORIGIN},
            timeout=10,
        )
        expect_status("GET /health CORS actual", cors_actual, 200)
        exposed_headers = comma_header_values(cors_actual, "access-control-expose-headers")
        check(
            "CORS exposes retry-after",
            "retry-after" in exposed_headers,
            cors_actual.headers,
        )

        token_json = requests.post(
            f"{BASE_URL}/token",
            json={"grant_type": "authorization_code"},
            timeout=10,
        )
        expect_status("POST /token rejects JSON content type", token_json, 400)
        check("token_json_invalid_request", expect_json(token_json).get("error") == "invalid_request")

        token_missing_grant = requests.post(f"{BASE_URL}/token", data={}, timeout=10)
        expect_status("POST /token rejects missing grant_type", token_missing_grant, 400)
        check(
            "token_missing_grant_invalid_request",
            expect_json(token_missing_grant).get("error") == "invalid_request",
        )

        token_duplicate_grant = requests.post(
            f"{BASE_URL}/token",
            data="grant_type=authorization_code&grant_type=refresh_token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        expect_status("POST /token rejects duplicate grant_type", token_duplicate_grant, 400)
        check(
            "token_duplicate_grant_invalid_request",
            expect_json(token_duplicate_grant).get("error") == "invalid_request",
        )

        token_invalid_resource = requests.post(
            f"{BASE_URL}/token",
            data={"grant_type": "client_credentials", "resource": "https://api.example/#fragment"},
            timeout=10,
        )
        expect_status("POST /token rejects resource fragment", token_invalid_resource, 400)
        check(
            "token_invalid_resource_invalid_target",
            expect_json(token_invalid_resource).get("error") == "invalid_target",
        )

        token_mixed_auth = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "body-client",
                "client_secret": "body-secret",
            },
            headers={"Authorization": "Basic " + base64.b64encode(b"basic-client:secret").decode()},
            timeout=10,
        )
        expect_status("POST /token rejects mixed basic and body auth", token_mixed_auth, 400)
        check(
            "token_mixed_auth_invalid_request",
            expect_json(token_mixed_auth).get("error") == "invalid_request",
        )

        token_assertion_secret_mix = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "client-a",
                "client_secret": "secret",
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": "assertion",
            },
            timeout=10,
        )
        expect_status(
            "POST /token rejects client_secret plus private_key_jwt",
            token_assertion_secret_mix,
            400,
        )
        check(
            "token_assertion_secret_mix_invalid_request",
            expect_json(token_assertion_secret_mix).get("error") == "invalid_request",
        )

        anonymous_redirect = anonymous.get(
            f"{BASE_URL}/authorize",
            params={"client_id": "missing-client"},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize missing client rejected before login", anonymous_redirect, 401)
        check(
            "authorize_missing_client_unauthorized_client",
            expect_json(anonymous_redirect).get("error") == "unauthorized_client",
        )

        duplicate = anonymous.get(
            f"{BASE_URL}/authorize?client_id=a&client_id=b",
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize duplicate parameter", duplicate, 400)

        send_code = user.post(
            f"{BASE_URL}/auth/send-code",
            json={"email": USER_EMAIL},
            timeout=10,
        )
        expect_status("POST /auth/send-code", send_code, 200)
        verification_code = smtp_sink.wait_for_code()

        registered = expect_json(
            expect_status(
                "POST /auth/register",
                user.post(
                    f"{BASE_URL}/auth/register",
                    json={
                        "email": USER_EMAIL,
                        "verification_code": verification_code,
                        "password": USER_PASSWORD,
                    },
                    timeout=10,
                ),
                201,
            )
        )
        user_id = registered["id"]

        login(user, USER_EMAIL, USER_PASSWORD, "POST /auth/login user")
        me = expect_json(
            expect_status("GET /auth/me", user.get(f"{BASE_URL}/auth/me", timeout=10), 200)
        )
        check("auth_me_user", me["id"] == user_id and me["email"] == USER_EMAIL)

        valkey_client = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
        malformed_session = requests.Session()
        malformed_sid = secrets.token_urlsafe(32)
        valkey_client.set(f"oauth:session:{malformed_sid}", "not-json", ex=300)
        malformed_session.cookies.set(SESSION_COOKIE_NAME, malformed_sid)
        expect_status(
            "GET /auth/me malformed session is unauthenticated",
            malformed_session.get(f"{BASE_URL}/auth/me", timeout=10),
            401,
        )
        check(
            "malformed_session_deleted",
            valkey_client.get(f"oauth:session:{malformed_sid}") is None,
        )

        csrf = expect_json(
            expect_status("GET /auth/csrf", user.get(f"{BASE_URL}/auth/csrf", timeout=10), 200)
        )
        check("csrf_refresh_body", bool(csrf.get("csrf_token")))

        exercise_passkey_profile_edges(user, user_id)

        updated_me = expect_json(
            expect_status(
                "PATCH /auth/me",
                user.patch(
                    f"{BASE_URL}/auth/me",
                    json={
                        "display_name": "Full E2E User",
                        "address_formatted": "100 Universal City Plaza\nUniversal City, CA 91608\nUS",
                        "address_street_address": "100 Universal City Plaza",
                        "address_locality": "Universal City",
                        "address_region": "CA",
                        "address_postal_code": "91608",
                        "address_country": "US",
                        "phone_number": "+15555550000",
                    },
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "profile_updated",
            updated_me["display_name"] == "Full E2E User"
            and updated_me["address_country"] == "US"
            and updated_me["phone_number"] == "+15555550000"
            and updated_me["phone_number_verified"] is False,
        )

        missing_avatar = user.post(
            f"{BASE_URL}/auth/me/avatar",
            files={"not_avatar": ("ignored.txt", b"ignored", "text/plain")},
            headers=csrf_header(user),
            timeout=10,
        )
        expect_status("POST /auth/me/avatar missing avatar field", missing_avatar, 400)

        oversized_avatar = user.post(
            f"{BASE_URL}/auth/me/avatar",
            files={"avatar": ("avatar.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 2_100_000, "image/png")},
            headers=csrf_header(user),
            timeout=10,
        )
        expect_status("POST /auth/me/avatar oversized", oversized_avatar, 413)

        unsupported_avatar = user.post(
            f"{BASE_URL}/auth/me/avatar",
            files={"avatar": ("avatar.txt", b"not an image", "text/plain")},
            headers=csrf_header(user),
            timeout=10,
        )
        expect_status("POST /auth/me/avatar unsupported content", unsupported_avatar, 400)

        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        avatar_upload = expect_json(
            expect_status(
                "POST /auth/me/avatar",
                user.post(
                    f"{BASE_URL}/auth/me/avatar",
                    files={"avatar": ("avatar.png", png_bytes, "image/png")},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check("avatar_url_set", bool(avatar_upload.get("avatar_url")))

        webp_bytes = b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"\x00" * 24
        avatar_reupload = expect_json(
            expect_status(
                "POST /auth/me/avatar replace existing",
                user.post(
                    f"{BASE_URL}/auth/me/avatar",
                    files={"avatar": ("avatar.webp", webp_bytes, "image/webp")},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "avatar_reupload_rotates_version",
            avatar_reupload.get("avatar_url") != avatar_upload.get("avatar_url"),
            avatar_reupload,
        )

        avatar_get = expect_status(
            "GET /auth/me/avatar",
            user.get(f"{BASE_URL}/auth/me/avatar", timeout=10),
            200,
        )
        check("avatar_content_type", avatar_get.headers.get("content-type") == "image/webp")

        avatar_cross_site = user.get(
            f"{BASE_URL}/auth/me/avatar",
            headers={"sec-fetch-site": "cross-site"},
            timeout=10,
        )
        expect_status("GET /auth/me/avatar cross-site rejected", avatar_cross_site, 403)

        expect_status(
            "DELETE /auth/me/avatar",
            user.delete(
                f"{BASE_URL}/auth/me/avatar",
                headers=csrf_header(user),
                timeout=10,
            ),
            200,
        )
        expect_status(
            "GET /auth/me/avatar after delete",
            user.get(f"{BASE_URL}/auth/me/avatar", timeout=10),
            404,
        )
        expect_status(
            "DELETE /auth/me/avatar already absent",
            user.delete(
                f"{BASE_URL}/auth/me/avatar",
                headers=csrf_header(user),
                timeout=10,
            ),
            200,
        )

        expect_status(
            "GET /auth/me/applications initial",
            user.get(f"{BASE_URL}/auth/me/applications", timeout=10),
            200,
        )
        expect_status(
            "GET /auth/me/access-requests initial",
            user.get(f"{BASE_URL}/auth/me/access-requests", timeout=10),
            200,
        )

        exercise_scim_routes()

        exercise_oidc_federation_start()
        exercise_saml_federation()

        login(admin, ADMIN_EMAIL, ADMIN_PASSWORD, "POST /auth/login admin")
        admin_users = expect_json(
            expect_status(
                "GET /admin/users",
                admin.get(f"{BASE_URL}/admin/users", params={"page": 1, "page_size": 50}, timeout=10),
                200,
            )
        )
        check("admin_users_contains_user", any(item["id"] == user_id for item in admin_users["items"]))

        patched_user = expect_json(
            expect_status(
                "PATCH /admin/users/{user_id}",
                admin.patch(
                    f"{BASE_URL}/admin/users/{user_id}",
                    json={"role": "user", "admin_level": 0, "is_active": True},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_patch_user_shape", patched_user["id"] == user_id)

        public_client = create_client(
            admin,
            {
                "client_name": "Public Full E2E",
                "client_type": "public",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "post_logout_redirect_uris": ["https://client.example/logout/callback?flow=rp"],
                "scopes": ["openid", "profile", "email", "address", "phone", "offline_access"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
                "jwks": None,
            },
            "POST /admin/clients public",
        )
        public_client_id = public_client["client_id"]

        exercise_oidc_logout(public_client_id)

        secret_client = create_client(
            admin,
            {
                "client_name": "Secret Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
                "jwks": None,
            },
            "POST /admin/clients client_secret_post",
        )
        secret_client_id = secret_client["client_id"]
        secret_client_secret = secret_client["client_secret"]

        private_key = ed25519.Ed25519PrivateKey.generate()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ps_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        jwks_without_kid = admin.post(
            f"{BASE_URL}/admin/clients",
            json={
                "client_name": "Invalid JWKS Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [ed25519_public_jwk(private_key)]},
            },
            headers=csrf_header(admin),
            timeout=10,
        )
        expect_status("POST /admin/clients private_key_jwt jwks kid required", jwks_without_kid, 400)

        jwk_with_private_material = ed25519_public_jwk(private_key, "private-key-material-e2e")
        jwk_with_private_material["d"] = b64url(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        private_jwk_response = admin.post(
            f"{BASE_URL}/admin/clients",
            json={
                "client_name": "Private Material JWKS Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [jwk_with_private_material]},
            },
            headers=csrf_header(admin),
            timeout=10,
        )
        expect_status(
            "POST /admin/clients private_key_jwt private jwk rejected",
            private_jwk_response,
            400,
        )

        private_client = create_client(
            admin,
            {
                "client_name": "Private JWT Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "allow_client_assertion_endpoint_audience": True,
                "jwks": {"keys": [ed25519_public_jwk(private_key, "private-key-jwt-e2e")]},
            },
            "POST /admin/clients private_key_jwt",
        )
        private_client_id = private_client["client_id"]

        multi_alg_private_client = create_client(
            admin,
            {
                "client_name": "Private JWT Multi Alg Full E2E",
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["profile"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "allow_client_assertion_endpoint_audience": True,
                "jwks": {
                    "keys": [
                        rsa_public_jwk(rsa_key, "private-key-jwt-rs256-e2e", "RS256"),
                        ec_public_jwk(ec_key, "private-key-jwt-es256-e2e"),
                        rsa_public_jwk(ps_key, "private-key-jwt-ps256-e2e", "PS256"),
                    ]
                },
            },
            "POST /admin/clients private_key_jwt RS256 ES256 PS256",
        )
        multi_alg_private_client_id = multi_alg_private_client["client_id"]

        private_auth_client = create_client(
            admin,
            {
                "client_name": "Private JWT Auth Code Full E2E",
                "client_type": "confidential",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "scopes": ["openid", "profile", "email"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "allow_client_assertion_endpoint_audience": True,
                "jwks": {
                    "keys": [
                        ed25519_public_jwk(private_key, "private-key-jwt-e2e"),
                        rsa_public_jwk(rsa_key, "private-key-jwt-rs256-e2e", "RS256"),
                    ]
                },
            },
            "POST /admin/clients private_key_jwt authorization_code",
        )
        private_auth_client_id = private_auth_client["client_id"]

        dpop_required_private_auth_client = create_client(
            admin,
            {
                "client_name": "Private JWT DPoP Required Full E2E",
                "client_type": "confidential",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "scopes": ["openid", "profile", "email", "offline_access"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "private_key_jwt",
                "allow_client_assertion_endpoint_audience": True,
                "require_dpop_bound_tokens": True,
                "jwks": {"keys": [ed25519_public_jwk(private_key, "private-key-jwt-e2e")]},
            },
            "POST /admin/clients private_key_jwt DPoP required authorization_code",
        )
        dpop_required_private_auth_client_id = dpop_required_private_auth_client["client_id"]

        secret_auth_client = create_client(
            admin,
            {
                "client_name": "Secret Auth Code Full E2E",
                "client_type": "confidential",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "scopes": ["openid", "profile", "email"],
                "allowed_audiences": [DEFAULT_AUDIENCE],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
                "allow_authorization_code_without_pkce": True,
                "jwks": None,
            },
            "POST /admin/clients client_secret_basic authorization_code",
        )
        secret_auth_client_id = secret_auth_client["client_id"]
        secret_auth_client_secret = secret_auth_client["client_secret"]

        invalid_redirect = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": "https://attacker.example/callback",
                "scope": "openid",
                "state": "invalid-redirect-uri",
                "nonce": "invalid-redirect-uri-nonce",
                "code_challenge": pkce_pair()[1],
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize invalid redirect_uri error response", invalid_redirect, 400)
        check("authorize_invalid_redirect_no_location", "Location" not in invalid_redirect.headers)
        check(
            "authorize_invalid_redirect_json",
            "application/json" in invalid_redirect.headers.get("Content-Type", ""),
        )
        invalid_redirect_body = expect_json(invalid_redirect)
        check(
            "authorize_invalid_redirect_error_body",
            invalid_redirect_body.get("error") == "invalid_request",
        )

        public_without_pkce = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "public-missing-pkce",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize public missing PKCE", public_without_pkce, 302)
        check(
            "public_missing_pkce_invalid_request",
            location_query(public_without_pkce).get("error") == ["invalid_request"],
        )

        dpop_required_plain_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": dpop_required_private_auth_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid profile email",
                "state": "dpop-required-plain",
                "nonce": "nonce-dpop-required-plain",
                "code_challenge": pkce_pair()[1],
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize DPoP-bound client without PAR or JAR",
            dpop_required_plain_authorize,
            "invalid_request",
            state="dpop-required-plain",
        )

        dpop_required_long_state = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": dpop_required_private_auth_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid profile email",
                "state": "s" * 1000,
                "nonce": "nonce-dpop-required-long-state",
                "code_challenge": pkce_pair()[1],
                "code_challenge_method": "S256",
                "request": authorization_request_object(
                    dpop_required_private_auth_client_id,
                    private_key,
                    code_challenge=pkce_pair()[1],
                    state="dpop-required-long-state-jar",
                ),
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize DPoP-bound long outer state",
            dpop_required_long_state,
            "invalid_request_object",
        )

        dpop_required_long_jar_state_value = "j" * 1000
        dpop_required_long_jar_state_verifier, dpop_required_long_jar_state_challenge = pkce_pair()
        dpop_required_long_jar_state = user.get(
            f"{BASE_URL}/authorize",
            params={
                "request": authorization_request_object(
                    dpop_required_private_auth_client_id,
                    private_key,
                    code_challenge=dpop_required_long_jar_state_challenge,
                    state=dpop_required_long_jar_state_value,
                    nonce="nonce-dpop-required-long-jar-state",
                ),
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status(
            "GET /authorize DPoP-bound long JAR state",
            dpop_required_long_jar_state,
            302,
        )
        dpop_required_long_jar_state_request_id = consent_request_from_redirect(
            dpop_required_long_jar_state,
            "GET /authorize DPoP-bound long JAR state",
        )
        approve_authorization(
            user,
            dpop_required_long_jar_state_request_id,
            dpop_required_long_jar_state_verifier,
            state=dpop_required_long_jar_state_value,
        )

        dpop_required_jar_missing_redirect = user.get(
            f"{BASE_URL}/authorize",
            params={
                "request": authorization_request_object_without_redirect_uri(
                    dpop_required_private_auth_client_id,
                    private_key,
                    code_challenge=pkce_pair()[1],
                    state="dpop-required-missing-redirect",
                ),
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize DPoP-bound JAR missing redirect_uri",
            dpop_required_jar_missing_redirect,
            "invalid_request_object",
        )

        confidential_without_pkce = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": secret_auth_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid profile email",
                "state": "confidential-no-pkce",
                "nonce": "confidential-no-pkce-nonce",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize confidential without PKCE", confidential_without_pkce, 302)
        confidential_no_pkce_request_id = consent_request_from_redirect(
            confidential_without_pkce,
            "confidential_without_pkce",
        )
        confidential_no_pkce_code, _ = approve_authorization(
            user,
            confidential_no_pkce_request_id,
            "",
            state="confidential-no-pkce",
        )
        confidential_no_pkce_tokens = token_basic(
            secret_auth_client_id,
            secret_auth_client_secret,
            {
                "grant_type": "authorization_code",
                "code": confidential_no_pkce_code,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token confidential authorization_code without PKCE",
        )
        check("confidential_without_pkce_access_token", bool(confidential_no_pkce_tokens.get("access_token")))
        check("confidential_without_pkce_id_token", bool(confidential_no_pkce_tokens.get("id_token")))

        post_authorize_request_id, post_authorize_verifier = authorize_request(
            user,
            public_client_id,
            state="post-authorize-acr",
            nonce="post-authorize-acr-nonce",
            extra_params={"acr_values": "urn:nazo:acr:password urn:nazo:acr:mfa"},
            method="POST",
        )
        post_authorize_code, post_authorize_verifier = approve_authorization(
            user,
            post_authorize_request_id,
            post_authorize_verifier,
            state="post-authorize-acr",
        )
        post_authorize_token = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": post_authorize_code,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "code_verifier": post_authorize_verifier,
            },
            "POST /token authorization_code after POST /authorize",
        )
        post_authorize_id_token = decode_jwt_unverified(post_authorize_token["id_token"])
        check("post_authorize_id_token_acr_absent", "acr" not in post_authorize_id_token)
        check("post_authorize_id_token_nonce", post_authorize_id_token.get("nonce") == "post-authorize-acr-nonce")

        par_confidential_unauthenticated = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": secret_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "profile",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par confidential unauthenticated rejected", par_confidential_unauthenticated, 401)

        par_with_request_uri = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "par-request-uri",
                "request_uri": "urn:ietf:params:oauth:request_uri:external",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par request_uri rejected", par_with_request_uri, 400)

        par_unknown = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "par-unknown",
                "unexpected": "value",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par unsupported parameter rejected", par_unknown, 400)

        par_bad_redirect = requests.post(
            f"{BASE_URL}/par",
            data={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": f"{CLIENT_REDIRECT_URI}/not-registered",
                "scope": "openid",
                "state": "par-bad-redirect",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            timeout=10,
        )
        expect_status("POST /par invalid redirect_uri rejected", par_bad_redirect, 400)
        check("par_invalid_redirect_uri_error", expect_json(par_bad_redirect).get("error") == "invalid_request")

        par_verifier, par_challenge = pkce_pair()
        par = expect_json(
            expect_status(
                "POST /par public",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": public_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email address phone offline_access",
                        "state": "par-flow",
                        "nonce": "nonce-par-flow",
                        "code_challenge": par_challenge,
                        "code_challenge_method": "S256",
                    },
                    timeout=10,
                ),
                201,
            )
        )
        check("par_request_uri_shape", par["request_uri"].startswith("urn:ietf:params:oauth:request_uri:"))
        par_login_verifier, par_login_challenge = pkce_pair()
        par_login = expect_json(
            expect_status(
                "POST /par public login roundtrip",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": public_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email offline_access",
                        "state": "par-login-roundtrip",
                        "nonce": "nonce-par-login-roundtrip",
                        "code_challenge": par_login_challenge,
                        "code_challenge_method": "S256",
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_login_user = requests.Session()
        par_login_start = par_login_user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par_login["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR unauthenticated", par_login_start, 302)
        login_next = parse_qs(urlparse(par_login_start.headers.get("Location", "")).query).get(
            "next",
            [""],
        )[0]
        check(
            "par_login_next_preserves_request_uri",
            "request_uri=" in unquote(login_next) and "code_challenge" not in unquote(login_next),
            login_next,
        )
        par_login_reuse_before_auth = par_login_user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par_login["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status(
            "GET /authorize PAR request_uri reusable before auth completion",
            par_login_reuse_before_auth,
            302,
        )
        par_login_reuse_next = parse_qs(
            urlparse(par_login_reuse_before_auth.headers.get("Location", "")).query
        ).get("next", [""])[0]
        check(
            "par_request_uri_reuse_before_auth_preserves_request_uri",
            "request_uri=" in unquote(par_login_reuse_next)
            and "code_challenge" not in unquote(par_login_reuse_next),
            par_login_reuse_next,
        )
        login(par_login_user, USER_EMAIL, USER_PASSWORD, "POST /auth/login PAR roundtrip")
        par_login_resume = par_login_user.get(
            f"{BASE_URL}{login_next}",
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR after login", par_login_resume, 302)
        par_login_request_id = consent_request_from_redirect(
            par_login_resume,
            "GET /authorize PAR after login",
        )
        par_login_code, par_login_verifier = approve_authorization(
            par_login_user,
            par_login_request_id,
            par_login_verifier,
            state="par-login-roundtrip",
        )
        par_login_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": par_login_code,
                "code_verifier": par_login_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token PAR after login",
        )
        check("par_login_token_issued", bool(par_login_tokens.get("access_token")))
        unknown_par = user.get(
            f"{BASE_URL}/authorize",
            params={
                "client_id": public_client_id,
                "request_uri": "urn:ietf:params:oauth:request_uri:missing",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize unknown request_uri",
            unknown_par,
            "invalid_request_uri",
        )
        par_conflict = user.get(
            f"{BASE_URL}/authorize",
            params={
                "client_id": public_client_id,
                "request_uri": par["request_uri"],
                "scope": "openid",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize PAR parameter override rejected",
            par_conflict,
            "invalid_request",
            state="par-flow",
        )
        par = expect_json(
            expect_status(
                "POST /par public second",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": public_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email offline_access",
                        "state": "par-flow",
                        "nonce": "nonce-par-flow",
                        "code_challenge": par_challenge,
                        "code_challenge_method": "S256",
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR", par_authorize, 302)
        par_request_id = consent_request_from_redirect(par_authorize, "GET /authorize PAR")
        par_code, par_verifier = approve_authorization(user, par_request_id, par_verifier, state="par-flow")
        par_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": par_code,
                "code_verifier": par_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token PAR authorization_code",
        )
        check("par_token_issued", bool(par_tokens.get("access_token")) and bool(par_tokens.get("id_token")))

        par_dpop_key = ed25519.Ed25519PrivateKey.generate()
        par_dpop_jkt = jwk_thumbprint(ed25519_public_jwk(par_dpop_key))
        par_dpop_verifier, par_dpop_challenge = pkce_pair()
        par_dpop_unbound_verifier, par_dpop_unbound_challenge = pkce_pair()
        par_dpop_missing_redirect = requests.post(
            f"{BASE_URL}/par",
            data={
                "request": authorization_request_object_without_redirect_uri(
                    dpop_required_private_auth_client_id,
                    private_key,
                    code_challenge=par_dpop_unbound_challenge,
                    state="par-dpop-missing-redirect",
                ),
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    dpop_required_private_auth_client_id,
                    private_key,
                    jti="par-dpop-client-assertion-missing-redirect",
                    audience_path="",
                ),
            },
            timeout=10,
        )
        expect_status("POST /par DPoP-required JAR missing redirect_uri rejected", par_dpop_missing_redirect, 400)
        check(
            "par_dpop_missing_redirect_error",
            expect_json(par_dpop_missing_redirect).get("error") == "invalid_request_object",
        )
        par_dpop_unbound = expect_json(
            expect_status(
                "POST /par DPoP-required client without early binding",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "response_type": "code",
                        "client_id": dpop_required_private_auth_client_id,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                        "scope": "openid profile email",
                        "state": "par-dpop-unbound",
                        "nonce": "nonce-par-dpop-unbound",
                        "code_challenge": par_dpop_unbound_challenge,
                        "code_challenge_method": "S256",
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": client_assertion(
                            dpop_required_private_auth_client_id,
                            private_key,
                            jti="par-dpop-client-assertion-unbound-par",
                            audience_path="",
                        ),
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_dpop_unbound_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={
                "client_id": dpop_required_private_auth_client_id,
                "request_uri": par_dpop_unbound["request_uri"],
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status(
            "GET /authorize PAR DPoP-required without early binding",
            par_dpop_unbound_authorize,
            302,
        )
        par_dpop_unbound_request_id = consent_request_from_redirect(
            par_dpop_unbound_authorize,
            "GET /authorize PAR DPoP-required without early binding",
        )
        par_dpop_unbound_code, par_dpop_unbound_verifier = approve_authorization(
            user,
            par_dpop_unbound_request_id,
            par_dpop_unbound_verifier,
            state="par-dpop-unbound",
        )
        par_dpop_unbound_token = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": par_dpop_unbound_code,
                "code_verifier": par_dpop_unbound_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    dpop_required_private_auth_client_id,
                    private_key,
                    jti="par-dpop-client-assertion-unbound-token",
                ),
            },
            timeout=10,
        )
        expect_status(
            "POST /token DPoP-required client without proof rejected",
            par_dpop_unbound_token,
            400,
        )
        check(
            "par_dpop_required_token_missing_proof_invalid_grant",
            expect_json(par_dpop_unbound_token).get("error") == "invalid_grant",
        )
        par_dpop_form = {
            "response_type": "code",
            "client_id": dpop_required_private_auth_client_id,
            "redirect_uri": CLIENT_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "state": "par-dpop-binding",
            "nonce": "nonce-par-dpop-binding",
            "code_challenge": par_dpop_challenge,
            "code_challenge_method": "S256",
            "dpop_jkt": par_dpop_jkt,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion(
                dpop_required_private_auth_client_id,
                private_key,
                jti="par-dpop-client-assertion-retry",
                audience_path="",
            ),
        }
        par_dpop_nonce = request_dpop_nonce(par_dpop_form, par_dpop_key, path="/par")
        par_mismatch_key = ed25519.Ed25519PrivateKey.generate()
        par_mismatch_form = dict(par_dpop_form)
        par_mismatch_form["state"] = "par-dpop-mismatch"
        par_mismatch_form["nonce"] = "nonce-par-dpop-mismatch"
        par_mismatch_form["client_assertion"] = client_assertion(
            dpop_required_private_auth_client_id,
            private_key,
            jti="par-dpop-client-assertion-mismatch",
            audience_path="",
        )
        par_mismatch_nonce = request_dpop_nonce(par_mismatch_form, par_mismatch_key, path="/par")
        par_mismatch = requests.post(
            f"{BASE_URL}/par",
            data=par_mismatch_form,
            headers={
                "DPoP": dpop_proof(
                    "POST",
                    f"{ISSUER_URL}/par",
                    par_mismatch_key,
                    nonce=par_mismatch_nonce,
                )
            },
            timeout=10,
        )
        expect_status("POST /par DPoP dpop_jkt mismatch rejected", par_mismatch, 400)
        check(
            "par_dpop_jkt_mismatch_error",
            expect_json(par_mismatch).get("error") == "invalid_dpop_proof",
        )
        par_dpop_response = expect_json(
            expect_status(
                "POST /par DPoP-bound private_key_jwt after nonce",
                requests.post(
                    f"{BASE_URL}/par",
                    data=par_dpop_form,
                    headers={
                        "DPoP": dpop_proof(
                            "POST",
                            f"{ISSUER_URL}/par",
                            par_dpop_key,
                            nonce=par_dpop_nonce,
                        )
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_dpop_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={
                "client_id": dpop_required_private_auth_client_id,
                "request_uri": par_dpop_response["request_uri"],
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR DPoP-bound", par_dpop_authorize, 302)
        par_dpop_request_id = consent_request_from_redirect(
            par_dpop_authorize,
            "GET /authorize PAR DPoP-bound",
        )
        par_dpop_code, par_dpop_verifier = approve_authorization(
            user,
            par_dpop_request_id,
            par_dpop_verifier,
            state="par-dpop-binding",
        )
        par_dpop_token_form = {
            "grant_type": "authorization_code",
            "code": par_dpop_code,
            "code_verifier": par_dpop_verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion(
                dpop_required_private_auth_client_id,
                private_key,
                jti="par-dpop-token-client-assertion-retry",
            ),
        }
        wrong_dpop_key = ed25519.Ed25519PrivateKey.generate()
        par_dpop_wrong_key = requests.post(
            f"{BASE_URL}/token",
            data=par_dpop_token_form,
            headers={"DPoP": dpop_proof("POST", f"{ISSUER_URL}/token", wrong_dpop_key)},
            timeout=10,
        )
        expect_status("POST /token PAR DPoP-bound wrong key rejected", par_dpop_wrong_key, 400)
        check(
            "par_dpop_wrong_key_error",
            expect_json(par_dpop_wrong_key).get("error") == "invalid_grant",
        )
        par_dpop_token_nonce = request_dpop_nonce(par_dpop_token_form, par_dpop_key)
        par_dpop_tokens = token_with_dpop(
            par_dpop_token_form,
            par_dpop_key,
            par_dpop_token_nonce,
            "POST /token PAR DPoP-bound correct key after nonce",
        )
        par_dpop_access_claims = decode_jwt_unverified(par_dpop_tokens["access_token"])
        check("par_dpop_token_type", par_dpop_tokens.get("token_type") == "DPoP")
        check(
            "par_dpop_access_token_cnf",
            par_dpop_access_claims.get("cnf", {}).get("jkt") == par_dpop_jkt,
        )
        par_dpop_missing_refresh_proof = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": par_dpop_tokens["refresh_token"],
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    dpop_required_private_auth_client_id,
                    private_key,
                    jti="par-dpop-refresh-client-assertion-missing-proof",
                ),
            },
            timeout=10,
        )
        expect_status(
            "POST /token PAR DPoP-required refresh missing proof rejected",
            par_dpop_missing_refresh_proof,
            400,
        )
        check(
            "par_dpop_refresh_missing_proof_invalid_grant",
            expect_json(par_dpop_missing_refresh_proof).get("error") == "invalid_grant",
        )
        par_dpop_refresh_nonce = request_dpop_nonce(
            {
                "grant_type": "refresh_token",
                "refresh_token": par_dpop_tokens["refresh_token"],
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    dpop_required_private_auth_client_id,
                    private_key,
                    jti="par-dpop-refresh-client-assertion",
                ),
            },
            par_dpop_key,
        )
        par_dpop_refreshed = token_with_dpop(
            {
                "grant_type": "refresh_token",
                "refresh_token": par_dpop_tokens["refresh_token"],
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    dpop_required_private_auth_client_id,
                    private_key,
                    jti="par-dpop-refresh-client-assertion-retry",
                ),
            },
            par_dpop_key,
            par_dpop_refresh_nonce,
            "POST /token PAR DPoP-required refresh correct key after nonce",
        )
        check("par_dpop_refresh_token_type", par_dpop_refreshed.get("token_type") == "DPoP")
        refresh_race_form = {
            "grant_type": "refresh_token",
            "client_id": public_client_id,
            "refresh_token": par_tokens["refresh_token"],
        }

        def redeem_refresh_race() -> tuple[int, dict[str, Any]]:
            response = requests.post(f"{BASE_URL}/token", data=refresh_race_form, timeout=10)
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, {"raw": response.text}

        with ThreadPoolExecutor(max_workers=2) as pool:
            refresh_race_results = list(pool.map(lambda _: redeem_refresh_race(), range(2)))
        refresh_successes = [body for status, body in refresh_race_results if status == 200]
        refresh_rejections = [body for status, body in refresh_race_results if status == 400]
        check(
            "refresh_token_reuse_race_single_success",
            len(refresh_successes) == 1 and len(refresh_rejections) == 1,
            refresh_race_results,
        )
        check(
            "refresh_token_reuse_race_invalid_grant",
            refresh_rejections[0].get("error") == "invalid_grant",
            refresh_rejections,
        )
        refresh_after_race = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_successes[0]["refresh_token"],
            },
            timeout=10,
        )
        expect_status("POST /token refresh family revoked after reuse race", refresh_after_race, 400)
        check(
            "refresh_token_reuse_race_revokes_family",
            expect_json(refresh_after_race).get("error") == "invalid_grant",
        )
        refresh_race_access_introspection = expect_json(
            expect_status(
                "POST /introspect refresh race winner access token",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": refresh_successes[0]["access_token"],
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "refresh_race_winner_access_token_remains_active",
            refresh_race_access_introspection.get("active") is True,
            refresh_race_access_introspection,
        )
        par_reuse = user.get(
            f"{BASE_URL}/authorize",
            params={"client_id": public_client_id, "request_uri": par["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize PAR request_uri read once",
            par_reuse,
            "invalid_request_uri",
        )

        jar_verifier, jar_challenge = pkce_pair()
        jar_token = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-flow",
        )
        jar_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR", jar_authorize, 302)
        jar_request_id = consent_request_from_redirect(jar_authorize, "GET /authorize JAR")
        jar_code, jar_verifier = approve_authorization(user, jar_request_id, jar_verifier, state="jar-flow")
        jar_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": jar_code,
                "code_verifier": jar_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(private_auth_client_id, private_key),
            },
            "POST /token JAR authorization_code private_key_jwt",
        )
        check("jar_token_issued", bool(jar_tokens.get("access_token")) and bool(jar_tokens.get("id_token")))
        jar_replay = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize JAR jti replay rejected",
            jar_replay,
            "invalid_request_object",
        )

        jar_rs_verifier, jar_rs_challenge = pkce_pair()
        jar_rs_token = authorization_request_object(
            private_auth_client_id,
            rsa_key,
            code_challenge=jar_rs_challenge,
            state="jar-rs256-flow",
            algorithm="RS256",
            kid="private-key-jwt-rs256-e2e",
        )
        jar_rs_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_rs_token},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR RS256", jar_rs_authorize, 302)
        jar_rs_request_id = consent_request_from_redirect(jar_rs_authorize, "GET /authorize JAR RS256")
        jar_rs_code, jar_rs_verifier = approve_authorization(
            user,
            jar_rs_request_id,
            jar_rs_verifier,
            state="jar-rs256-flow",
        )
        jar_rs_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": jar_rs_code,
                "code_verifier": jar_rs_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    private_auth_client_id,
                    rsa_key,
                    algorithm="RS256",
                    kid="private-key-jwt-rs256-e2e",
                ),
            },
            "POST /token JAR RS256 authorization_code private_key_jwt",
        )
        check("jar_rs256_token_issued", bool(jar_rs_tokens.get("access_token")))

        jar_none = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-none",
            algorithm="none",
        )
        jar_none_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_none},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR alg none rejected", jar_none_authorize, 400)
        check("jar_alg_none_rejected", expect_json(jar_none_authorize).get("error") == "invalid_request")
        jar_bad_aud = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-bad-aud",
            audience="https://wrong-audience.example",
        )
        expect_authorization_error_redirect(
            "GET /authorize JAR audience mismatch rejected",
            user.get(
                f"{BASE_URL}/authorize",
                params={"request": jar_bad_aud},
                allow_redirects=False,
                timeout=10,
            ),
            "invalid_request_object",
        )

        jar_client_conflict = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_challenge,
            state="jar-client-conflict",
            jti=str(uuid.uuid4()),
        )
        expect_authorization_error_redirect(
            "GET /authorize JAR outer client_id conflict rejected",
            user.get(
                f"{BASE_URL}/authorize",
                params={"request": jar_client_conflict, "client_id": public_client_id},
                allow_redirects=False,
                timeout=10,
            ),
            "invalid_request_object",
        )

        jar_override_verifier, jar_override_challenge = pkce_pair()
        jar_override = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=jar_override_challenge,
            state="jar-internal-state",
        )
        jar_override_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request": jar_override, "state": "conflicting-outer-state"},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize JAR request object overrides outer state", jar_override_authorize, 302)
        jar_override_request_id = consent_request_from_redirect(
            jar_override_authorize,
            "GET /authorize JAR request object overrides outer state",
        )
        _jar_override_code, _jar_override_verifier = approve_authorization(
            user,
            jar_override_request_id,
            jar_override_verifier,
            state="jar-internal-state",
        )

        par_jar_verifier, par_jar_challenge = pkce_pair()
        par_jar = authorization_request_object(
            private_auth_client_id,
            private_key,
            code_challenge=par_jar_challenge,
            state="par-jar-flow",
        )
        par_jar_response = expect_json(
            expect_status(
                "POST /par JAR private_key_jwt",
                requests.post(
                    f"{BASE_URL}/par",
                    data={
                        "request": par_jar,
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": client_assertion(
                            private_auth_client_id,
                            private_key,
                            audience_path="",
                        ),
                    },
                    timeout=10,
                ),
                201,
            )
        )
        par_jar_authorize = user.get(
            f"{BASE_URL}/authorize",
            params={"request_uri": par_jar_response["request_uri"]},
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize PAR JAR", par_jar_authorize, 302)
        par_jar_request_id = consent_request_from_redirect(par_jar_authorize, "GET /authorize PAR JAR")
        par_jar_code, par_jar_verifier = approve_authorization(
            user,
            par_jar_request_id,
            par_jar_verifier,
            state="par-jar-flow",
        )
        par_jar_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "code": par_jar_code,
                "code_verifier": par_jar_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion(private_auth_client_id, private_key),
            },
            "POST /token PAR JAR authorization_code private_key_jwt",
        )
        check("par_jar_token_issued", bool(par_jar_tokens.get("access_token")))

        expect_status(
            "POST /introspect public client rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": public_client_id},
                timeout=10,
            ),
            401,
        )

        lower_basic = "basic " + base64.b64encode(
            f"{secret_client_id}:{secret_client_secret}".encode("utf-8")
        ).decode("ascii")
        expect_status(
            "POST /token lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": secret_client_id,
                    "client_secret": secret_client_secret,
                    "scope": "profile",
                },
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /introspect lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /revoke lowercase basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": lower_basic},
                timeout=10,
            ),
            400,
        )
        malformed_basic = "Basic not-base64 with-space"
        expect_status(
            "POST /token malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": secret_client_id,
                    "client_secret": secret_client_secret,
                    "scope": "profile",
                },
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /introspect malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/introspect",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /revoke malformed basic plus body credential rejected",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": "dummy-token", "client_id": secret_client_id},
                headers={"Authorization": malformed_basic},
                timeout=10,
            ),
            400,
        )

        admin_clients = expect_json(
            expect_status(
                "GET /admin/clients",
                admin.get(f"{BASE_URL}/admin/clients", params={"page": 1, "page_size": 100}, timeout=10),
                200,
            )
        )
        check("admin_clients_contains_created", admin_clients["total"] >= 3)

        expect_status(
            "GET /admin/clients/{client_id}",
            admin.get(f"{BASE_URL}/admin/clients/{public_client_id}", timeout=10),
            200,
        )
        patched_client = expect_json(
            expect_status(
                "PATCH /admin/clients/{client_id}",
                admin.patch(
                    f"{BASE_URL}/admin/clients/{public_client_id}",
                    json={"client_name": "Public Full E2E Updated", "is_active": True},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_patch_client_shape", patched_client["client_name"] == "Public Full E2E Updated")

        _prompt_verifier, prompt_challenge = pkce_pair()
        prompt_none = requests.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "prompt-none",
                "prompt": "none",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize prompt=none unauthenticated", prompt_none, 302)
        check("prompt_none_login_required", location_query(prompt_none).get("error") == ["login_required"])

        prompt_login = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "prompt-login",
                "prompt": "login",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize prompt=login", prompt_login, 302)
        prompt_login_location = prompt_login.headers.get("Location", "")
        check(
            "prompt_login_redirects_to_frontend_auth",
            prompt_login_location.startswith("http://127.0.0.1:3000/auth?next=")
            and "prompt%3Dlogin" in prompt_login_location,
            prompt_login_location,
        )

        time.sleep(1)
        max_age = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "max-age",
                "max_age": "0",
                "code_challenge": prompt_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize max_age expired", max_age, 302)
        check(
            "max_age_redirects_to_frontend_auth",
            max_age.headers.get("Location", "").startswith("http://127.0.0.1:3000/auth?next="),
            max_age.headers.get("Location"),
        )

        bad_response_type = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "token",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid",
                "state": "bad-response-type",
                "code_challenge": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize unsupported response_type", bad_response_type, 302)
        check(
            "authorize_unsupported_response_type_error",
            location_query(bad_response_type).get("error") == ["unsupported_response_type"],
        )

        deny_request_id, _deny_verifier = authorize_request(
            user, public_client_id, state="deny-flow", nonce=None
        )
        deny_response = user.post(
            f"{BASE_URL}/authorize/decision",
            data={
                "request_id": deny_request_id,
                "decision": "deny",
                "csrf_token": user.cookies.get("nazo_oauth_csrf"),
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("POST /authorize/decision deny", deny_response, 302)
        check("authorize_deny_error", location_query(deny_response).get("error") == ["access_denied"])

        dpop_key = ed25519.Ed25519PrivateKey.generate()
        missing_request_id, missing_verifier = authorize_request(
            user,
            public_client_id,
            state="missing-redirect-flow",
        )
        missing_code, missing_verifier = approve_authorization(
            user,
            missing_request_id,
            missing_verifier,
            state="missing-redirect-flow",
        )
        missing_redirect_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": missing_code,
            "code_verifier": missing_verifier,
        }
        nonce = request_dpop_nonce(missing_redirect_form, dpop_key)
        missing_redirect_response = requests.post(
            f"{BASE_URL}/token",
            data=missing_redirect_form,
            headers={"DPoP": dpop_proof("POST", f"{ISSUER_URL}/token", dpop_key, nonce=nonce)},
            timeout=10,
        )
        expect_status("POST /token redirect_uri required", missing_redirect_response, 400)
        check(
            "token_redirect_uri_required_error",
            expect_json(missing_redirect_response).get("error") == "invalid_grant",
        )

        request_id, verifier = authorize_request(user, public_client_id, state="approve-flow")
        code, verifier = approve_authorization(user, request_id, verifier, state="approve-flow")
        token_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }
        nonce = request_dpop_nonce(
            token_form, dpop_key
        )
        token_response = token_with_dpop(
            token_form,
            dpop_key,
            nonce,
            "POST /token authorization_code DPoP",
        )
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]
        check("id_token_issued", bool(token_response.get("id_token")))

        prompt_none_verifier, prompt_none_challenge = pkce_pair()
        prompt_none_success = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid email",
                "state": "prompt-none-success",
                "nonce": "prompt-none-success-nonce",
                "prompt": "none",
                "code_challenge": prompt_none_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_status("GET /authorize prompt=none with existing grant", prompt_none_success, 302)
        prompt_none_query = location_query(prompt_none_success)
        prompt_none_code = prompt_none_query.get("code", [None])[0]
        check("prompt_none_existing_grant_issues_code", bool(prompt_none_code))
        check(
            "prompt_none_existing_grant_state_roundtrip",
            prompt_none_query.get("state") == ["prompt-none-success"],
        )
        prompt_none_tokens = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": prompt_none_code,
                "code_verifier": prompt_none_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token prompt=none authorization_code",
        )
        check("prompt_none_existing_grant_token_issued", bool(prompt_none_tokens.get("access_token")))

        prompt_none_details_verifier, prompt_none_details_challenge = pkce_pair()
        prompt_none_consent_required = user.get(
            f"{BASE_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": public_client_id,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid email",
                "state": "prompt-none-consent-required",
                "nonce": "prompt-none-consent-required-nonce",
                "prompt": "none",
                "authorization_details": json.dumps(
                    [{"type": "account_information", "actions": ["read"], "locations": ["acct-new"]}],
                    separators=(",", ":"),
                ),
                "code_challenge": prompt_none_details_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False,
            timeout=10,
        )
        expect_authorization_error_redirect(
            "GET /authorize prompt=none consent required for new authorization_details",
            prompt_none_consent_required,
            "consent_required",
            state="prompt-none-consent-required",
        )

        bearer_request_id, bearer_verifier = authorize_request(
            user,
            public_client_id,
            state="bearer-code-flow",
        )
        bearer_code, bearer_verifier = approve_authorization(
            user,
            bearer_request_id,
            bearer_verifier,
            state="bearer-code-flow",
        )
        bearer_response = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": bearer_code,
                "code_verifier": bearer_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            "POST /token authorization_code Bearer without DPoP",
        )
        check("bearer_token_type", bearer_response.get("token_type") == "Bearer")

        wrong_verifier_request_id, wrong_verifier = authorize_request(
            user,
            public_client_id,
            state="wrong-verifier-flow",
        )
        wrong_verifier_code, wrong_verifier = approve_authorization(
            user,
            wrong_verifier_request_id,
            wrong_verifier,
            state="wrong-verifier-flow",
        )
        wrong_verifier_response = expect_json(
            expect_status(
                "POST /token authorization_code wrong verifier",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": public_client_id,
                        "code": wrong_verifier_code,
                        "code_verifier": "wrong-" + wrong_verifier,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                    },
                    timeout=10,
                ),
                400,
            )
        )
        check(
            "authorization_code_wrong_verifier_invalid_grant",
            wrong_verifier_response.get("error") == "invalid_grant",
        )
        wrong_verifier_replay = expect_json(
            expect_status(
                "POST /token authorization_code wrong verifier replay",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": public_client_id,
                        "code": wrong_verifier_code,
                        "code_verifier": wrong_verifier,
                        "redirect_uri": CLIENT_REDIRECT_URI,
                    },
                    timeout=10,
                ),
                400,
            )
        )
        check(
            "authorization_code_failed_marker_blocks_later_correct_verifier",
            wrong_verifier_replay.get("error") == "invalid_grant",
        )
        fapi_bearer = expect_json(
            expect_status(
                "GET /fapi/resource Bearer",
                requests.get(
                    f"{BASE_URL}/fapi/resource",
                    headers={"Authorization": f"Bearer {bearer_response['access_token']}"},
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "fapi_resource_bearer_claims",
            fapi_bearer.get("client_id") == public_client_id
            and fapi_bearer.get("aud") == DEFAULT_AUDIENCE,
            fapi_bearer,
        )

        holder_request_id, holder_verifier = authorize_request(
            user,
            public_client_id,
            state="holder-of-key-required",
            extra_params={"dpop_jkt": jwk_thumbprint(ed25519_public_jwk(dpop_key))},
        )
        holder_code, holder_verifier = approve_authorization(
            user,
            holder_request_id,
            holder_verifier,
            state="holder-of-key-required",
        )
        holder_missing_proof = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": holder_code,
                "code_verifier": holder_verifier,
                "redirect_uri": CLIENT_REDIRECT_URI,
            },
            timeout=10,
        )
        expect_status("POST /token DPoP-bound code missing proof rejected", holder_missing_proof, 400)
        check(
            "holder_of_key_missing_proof_invalid_grant",
            expect_json(holder_missing_proof).get("error") == "invalid_grant",
        )

        fapi_dpop_challenge = requests.get(
            f"{BASE_URL}/fapi/resource",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof(
                    "GET",
                    f"{ISSUER_URL}/fapi/resource",
                    dpop_key,
                    access_token=access_token,
                ),
            },
            timeout=10,
        )
        expect_status("GET /fapi/resource DPoP nonce challenge", fapi_dpop_challenge, 401)
        fapi_dpop_nonce = fapi_dpop_challenge.headers.get("DPoP-Nonce")
        check("fapi_resource_dpop_nonce_header", bool(fapi_dpop_nonce))
        fapi_dpop = expect_json(
            expect_status(
                "GET /fapi/resource DPoP",
                requests.get(
                    f"{BASE_URL}/fapi/resource",
                    headers={
                        "Authorization": f"DPoP {access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{ISSUER_URL}/fapi/resource",
                            dpop_key,
                            nonce=fapi_dpop_nonce,
                            access_token=access_token,
                        ),
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "fapi_resource_dpop_claims",
            fapi_dpop.get("client_id") == public_client_id and bool(fapi_dpop.get("sub")),
            fapi_dpop,
        )

        userinfo_no_nonce = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof("GET", f"{ISSUER_URL}/userinfo", dpop_key, access_token=access_token),
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP nonce challenge", userinfo_no_nonce, 401)
        userinfo_nonce = userinfo_no_nonce.headers.get("DPoP-Nonce")
        check("userinfo_nonce_header", bool(userinfo_nonce))
        check(
            "userinfo_nonce_www_authenticate",
            'error="use_dpop_nonce"' in userinfo_no_nonce.headers.get("WWW-Authenticate", ""),
            userinfo_no_nonce.headers,
        )
        userinfo = expect_json(
            expect_status(
                "GET /userinfo",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{ISSUER_URL}/userinfo",
                            dpop_key,
                            nonce=userinfo_nonce,
                            access_token=access_token,
                        ),
                    },
                    timeout=10,
                ),
                200,
            )
        )
        replay_userinfo_challenge = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof(
                    "GET",
                    f"{ISSUER_URL}/userinfo",
                    dpop_key,
                    access_token=access_token,
                ),
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP replay nonce challenge", replay_userinfo_challenge, 401)
        replay_userinfo_nonce = replay_userinfo_challenge.headers.get("DPoP-Nonce")
        check("userinfo_dpop_replay_nonce_header", bool(replay_userinfo_nonce))
        replay_userinfo_jti = str(uuid.uuid4())
        replay_userinfo_proof = dpop_proof(
            "GET",
            f"{ISSUER_URL}/userinfo",
            dpop_key,
            nonce=replay_userinfo_nonce,
            access_token=access_token,
            jti=replay_userinfo_jti,
        )
        first_replay_probe = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": replay_userinfo_proof,
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP replay proof first use", first_replay_probe, 200)
        second_replay_challenge = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof(
                    "GET",
                    f"{ISSUER_URL}/userinfo",
                    dpop_key,
                    access_token=access_token,
                ),
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP replay second nonce challenge", second_replay_challenge, 401)
        second_replay_nonce = second_replay_challenge.headers.get("DPoP-Nonce")
        check("userinfo_dpop_replay_second_nonce_header", bool(second_replay_nonce))
        second_replay_proof = dpop_proof(
            "GET",
            f"{ISSUER_URL}/userinfo",
            dpop_key,
            nonce=second_replay_nonce,
            access_token=access_token,
            jti=replay_userinfo_jti,
        )
        second_replay_probe = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": second_replay_proof,
            },
            timeout=10,
        )
        expect_status("GET /userinfo DPoP replay proof rejected", second_replay_probe, 400)
        check(
            "userinfo_dpop_replay_invalid_proof",
            expect_json(second_replay_probe).get("error") == "invalid_dpop_proof",
        )
        check(
            "userinfo_claims",
            userinfo.get("sub") == user_id
            and userinfo.get("email") == USER_EMAIL
            and userinfo.get("email_verified") is True
            and userinfo.get("address", {}).get("country") == "US"
            and userinfo.get("address", {}).get("street_address") == "100 Universal City Plaza"
            and userinfo.get("phone_number") == "+15555550000"
            and userinfo.get("phone_number_verified") is False,
        )
        claims_request_id, claims_verifier = authorize_request(
            user,
            public_client_id,
            state="claims-essential",
            nonce="claims-essential-nonce",
            extra_params={
                "scope": "openid",
                "claims": json.dumps({"userinfo": {"name": {"essential": True}}}, separators=(",", ":")),
            },
        )
        claims_code, claims_verifier = approve_authorization(
            user,
            claims_request_id,
            claims_verifier,
            state="claims-essential",
        )
        claims_token_response = token_plain(
            {
                "grant_type": "authorization_code",
                "client_id": public_client_id,
                "code": claims_code,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "code_verifier": claims_verifier,
            },
            "POST /token claims essential",
        )
        claims_userinfo = expect_json(
            expect_status(
                "GET /userinfo claims essential",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={"Authorization": f"Bearer {claims_token_response['access_token']}"},
                    timeout=10,
                ),
                200,
            )
        )
        check("userinfo_claims_essential_name", claims_userinfo.get("name") == "Full E2E User")
        userinfo_post_no_nonce = requests.post(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof("POST", f"{ISSUER_URL}/userinfo", dpop_key, access_token=access_token),
            },
            timeout=10,
        )
        expect_status("POST /userinfo DPoP nonce challenge", userinfo_post_no_nonce, 401)
        userinfo_post_nonce = userinfo_post_no_nonce.headers.get("DPoP-Nonce")
        check("userinfo_post_nonce_header", bool(userinfo_post_nonce))
        userinfo_post = expect_json(
            expect_status(
                "POST /userinfo DPoP",
                requests.post(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {access_token}",
                        "DPoP": dpop_proof(
                            "POST",
                            f"{ISSUER_URL}/userinfo",
                            dpop_key,
                            nonce=userinfo_post_nonce,
                            access_token=access_token,
                        ),
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("userinfo_post_claims", userinfo_post.get("sub") == userinfo.get("sub"))

        nonce = request_dpop_nonce(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
        )
        refreshed = token_with_dpop(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
            nonce,
            "POST /token refresh_token DPoP",
        )
        rotated_refresh_token = refreshed["refresh_token"]
        refreshed_access_token = refreshed["access_token"]
        check("refresh_token_rotated", rotated_refresh_token != refresh_token)
        missing_refresh_proof = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": rotated_refresh_token,
            },
            timeout=10,
        )
        expect_status(
            "POST /token refresh_token DPoP missing proof rejected",
            missing_refresh_proof,
            400,
        )
        check(
            "refresh_token_dpop_missing_proof_invalid_grant",
            expect_json(missing_refresh_proof).get("error") == "invalid_grant",
        )
        wrong_refresh_key = ed25519.Ed25519PrivateKey.generate()
        wrong_refresh = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": rotated_refresh_token,
            },
            headers={
                "DPoP": dpop_proof(
                    "POST",
                    f"{ISSUER_URL}/token",
                    wrong_refresh_key,
                )
            },
            timeout=10,
        )
        expect_status("POST /token refresh_token DPoP wrong key rejected", wrong_refresh, 400)
        check(
            "refresh_token_dpop_wrong_key_error",
            expect_json(wrong_refresh).get("error") == "invalid_dpop_proof",
        )
        lost_response_nonce = request_dpop_nonce(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
        )
        lost_response_refresh = token_with_dpop(
            {
                "grant_type": "refresh_token",
                "client_id": public_client_id,
                "refresh_token": refresh_token,
            },
            dpop_key,
            lost_response_nonce,
            "POST /token previous refresh_token inside lost response window",
        )
        check(
            "refresh_token_lost_response_rotates_successor",
            lost_response_refresh["refresh_token"] not in {refresh_token, rotated_refresh_token},
        )

        introspected = expect_json(
            expect_status(
                "POST /introspect active",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": refreshed_access_token,
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("introspect_active", introspected.get("active") is True)

        expect_status(
            "POST /revoke refresh token",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": lost_response_refresh["refresh_token"], "client_id": public_client_id},
                timeout=10,
            ),
            200,
        )
        refresh_introspection_after_revoke = expect_json(
            expect_status(
                "POST /introspect refresh token inactive",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": lost_response_refresh["refresh_token"],
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "refresh_token_introspection_inactive_after_revoke",
            refresh_introspection_after_revoke.get("active") is False,
            refresh_introspection_after_revoke,
        )

        expect_status(
            "POST /revoke access token",
            requests.post(
                f"{BASE_URL}/revoke",
                data={"token": refreshed_access_token, "client_id": public_client_id},
                timeout=10,
            ),
            200,
        )
        introspected_after_revoke = expect_json(
            expect_status(
                "POST /introspect inactive",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": refreshed_access_token,
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("introspect_inactive_after_revoke", introspected_after_revoke.get("active") is False)

        replay_request_id, replay_verifier = authorize_request(
            user, public_client_id, state="code-replay-flow"
        )
        replay_code, replay_verifier = approve_authorization(
            user, replay_request_id, replay_verifier, state="code-replay-flow"
        )
        replay_key = ed25519.Ed25519PrivateKey.generate()
        replay_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": replay_code,
            "code_verifier": replay_verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }
        replay_nonce = request_dpop_nonce(replay_form, replay_key)
        replay_tokens = token_with_dpop(
            replay_form,
            replay_key,
            replay_nonce,
            "POST /token authorization_code replay baseline",
        )
        replay_access_token = replay_tokens["access_token"]
        replay_refresh_form = {
            "grant_type": "refresh_token",
            "client_id": public_client_id,
            "refresh_token": replay_tokens["refresh_token"],
        }
        replay_refresh_nonce = request_dpop_nonce(replay_refresh_form, replay_key)
        replay_userinfo_nonce_response = requests.get(
            f"{BASE_URL}/userinfo",
            headers={
                "Authorization": f"DPoP {replay_access_token}",
                "DPoP": dpop_proof(
                    "GET",
                    f"{ISSUER_URL}/userinfo",
                    replay_key,
                    access_token=replay_access_token,
                ),
            },
            timeout=10,
        )
        expect_status(
            "GET /userinfo replay token nonce challenge",
            replay_userinfo_nonce_response,
            401,
        )
        replay_userinfo_nonce = replay_userinfo_nonce_response.headers.get("DPoP-Nonce")
        check("userinfo_replay_token_nonce_header", bool(replay_userinfo_nonce))
        replay_nonce = request_dpop_nonce(replay_form, replay_key)
        replay_response = requests.post(
            f"{BASE_URL}/token",
            data=replay_form,
            headers={"DPoP": dpop_proof("POST", f"{ISSUER_URL}/token", replay_key, nonce=replay_nonce)},
            timeout=10,
        )
        expect_status("POST /token authorization_code replay rejected", replay_response, 400)
        check(
            "authorization_code_replay_error",
            expect_json(replay_response).get("error") == "invalid_grant",
        )
        replay_userinfo_after_revoke = expect_json(
            expect_status(
                "GET /userinfo access token revoked after code replay",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={
                        "Authorization": f"DPoP {replay_access_token}",
                        "DPoP": dpop_proof(
                            "GET",
                            f"{ISSUER_URL}/userinfo",
                            replay_key,
                            nonce=replay_userinfo_nonce,
                            access_token=replay_access_token,
                        ),
                    },
                    timeout=10,
                ),
                401,
            )
        )
        check(
            "userinfo_revoked_after_code_replay_error",
            replay_userinfo_after_revoke.get("error") == "invalid_token",
        )
        replay_access_introspection_after_revoke = expect_json(
            expect_status(
                "POST /introspect access token inactive after code replay",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": replay_access_token,
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "introspect_access_token_inactive_after_code_replay",
            replay_access_introspection_after_revoke.get("active") is False,
            replay_access_introspection_after_revoke,
        )
        replay_refresh_after_revoke = expect_json(
            expect_status(
                "POST /token refresh token revoked after code replay",
                requests.post(
                    f"{BASE_URL}/token",
                    data=replay_refresh_form,
                    headers={
                        "DPoP": dpop_proof(
                            "POST",
                            f"{ISSUER_URL}/token",
                            replay_key,
                            nonce=replay_refresh_nonce,
                        )
                    },
                    timeout=10,
                ),
                400,
            )
        )
        check(
            "refresh_token_revoked_after_code_replay_error",
            replay_refresh_after_revoke.get("error") == "invalid_grant",
        )
        replay_refresh_introspection_after_revoke = expect_json(
            expect_status(
                "POST /introspect refresh token inactive after code replay",
                requests.post(
                    f"{BASE_URL}/introspect",
                    data={
                        "token": replay_tokens["refresh_token"],
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "introspect_refresh_token_inactive_after_code_replay",
            replay_refresh_introspection_after_revoke.get("active") is False,
            replay_refresh_introspection_after_revoke,
        )

        concurrent_request_id, concurrent_verifier = authorize_request(
            user,
            public_client_id,
            state="concurrent-code-flow",
            nonce=None,
        )
        concurrent_code, concurrent_verifier = approve_authorization(
            user,
            concurrent_request_id,
            concurrent_verifier,
            state="concurrent-code-flow",
        )
        concurrent_form = {
            "grant_type": "authorization_code",
            "client_id": public_client_id,
            "code": concurrent_code,
            "code_verifier": concurrent_verifier,
            "redirect_uri": CLIENT_REDIRECT_URI,
        }

        def redeem_concurrent_code() -> tuple[int, dict[str, Any]]:
            response = requests.post(f"{BASE_URL}/token", data=concurrent_form, timeout=10)
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, {"raw": response.text}

        with ThreadPoolExecutor(max_workers=2) as pool:
            concurrent_results = list(pool.map(lambda _: redeem_concurrent_code(), range(2)))
        success_results = [body for status, body in concurrent_results if status == 200]
        rejected_results = [body for status, body in concurrent_results if status == 400]
        check(
            "near_concurrent_authorization_code_single_success",
            len(success_results) == 1 and len(rejected_results) == 1,
            concurrent_results,
        )
        check(
            "near_concurrent_authorization_code_busy_invalid_grant",
            rejected_results[0].get("error") == "invalid_grant",
            rejected_results,
        )
        concurrent_access_token = success_results[0]["access_token"]
        concurrent_userinfo_post_body = expect_json(
            expect_status(
                "POST /userinfo bearer token in body",
                requests.post(
                    f"{BASE_URL}/userinfo",
                    data={"access_token": concurrent_access_token},
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "userinfo_post_body_claims",
            concurrent_userinfo_post_body.get("sub") == user_id,
        )
        replay_after_concurrent = requests.post(
            f"{BASE_URL}/token",
            data=concurrent_form,
            timeout=10,
        )
        expect_status("POST /token authorization_code post-success replay rejected", replay_after_concurrent, 400)
        concurrent_userinfo_after_replay = expect_json(
            expect_status(
                "GET /userinfo revoked after post-success code replay",
                requests.get(
                    f"{BASE_URL}/userinfo",
                    headers={"Authorization": f"Bearer {concurrent_access_token}"},
                    timeout=10,
                ),
                401,
            )
        )
        check(
            "post_success_code_replay_revoked_access_token",
            concurrent_userinfo_after_replay.get("error") == "invalid_token",
        )

        secret_cc = expect_json(
            expect_status(
                "POST /token client_credentials client_secret_post",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": secret_client_id,
                        "client_secret": secret_client_secret,
                        "scope": "profile",
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("client_secret_post_access_token", bool(secret_cc.get("access_token")))

        exercise_fapi_http_signature_profile(admin)

        for algorithm, key, public_jwk in [
            ("ES256", ec_key, ec_public_jwk(ec_key, "dpop-es256-e2e")),
        ]:
            dpop_client_credentials_form = {
                "grant_type": "client_credentials",
                "client_id": secret_client_id,
                "client_secret": secret_client_secret,
                "scope": "profile",
            }
            nonce = request_dpop_nonce(
                dpop_client_credentials_form,
                key,
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
            alg_dpop_token = token_with_dpop(
                dpop_client_credentials_form,
                key,
                nonce,
                f"POST /token client_credentials DPoP {algorithm}",
                algorithm=algorithm,
                public_jwk=public_jwk,
            )
            check(f"dpop_{algorithm.lower()}_access_token", bool(alg_dpop_token.get("access_token")))

        assertion_jti = str(uuid.uuid4())
        assertion = client_assertion(private_client_id, private_key, jti=assertion_jti)
        private_cc = expect_json(
            expect_status(
                "POST /token private_key_jwt",
                requests.post(
                    f"{BASE_URL}/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": assertion,
                        "scope": "profile",
                    },
                    timeout=10,
                ),
                200,
            )
        )
        check("private_key_jwt_access_token", bool(private_cc.get("access_token")))
        replay = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
                "scope": "profile",
            },
            timeout=10,
        )
        expect_status("POST /token private_key_jwt replay rejected", replay, 401)
        check(
            "private_key_jwt_replay_invalid_client",
            expect_json(replay).get("error") == "invalid_client",
        )

        for algorithm, key, kid in [
            ("RS256", rsa_key, "private-key-jwt-rs256-e2e"),
            ("ES256", ec_key, "private-key-jwt-es256-e2e"),
            ("PS256", ps_key, "private-key-jwt-ps256-e2e"),
        ]:
            alg_response = expect_json(
                expect_status(
                    f"POST /token private_key_jwt {algorithm}",
                    requests.post(
                        f"{BASE_URL}/token",
                        data={
                            "grant_type": "client_credentials",
                            "client_assertion_type": CLIENT_ASSERTION_TYPE,
                            "client_assertion": client_assertion(
                                multi_alg_private_client_id,
                                key,
                                algorithm=algorithm,
                                kid=kid,
                            ),
                            "scope": "profile",
                        },
                        timeout=10,
                    ),
                    200,
                )
            )
            check(f"private_key_jwt_{algorithm.lower()}_access_token", bool(alg_response.get("access_token")))

        applications = expect_json(
            expect_status(
                "GET /auth/me/applications after authorization",
                user.get(f"{BASE_URL}/auth/me/applications", timeout=10),
                200,
            )
        )
        check("applications_has_public_client", applications["total"] >= 1)

        grants = expect_json(
            expect_status(
                "GET /admin/grants",
                admin.get(f"{BASE_URL}/admin/grants", params={"page": 1, "page_size": 100}, timeout=10),
                200,
            )
        )
        check("admin_grants_has_public_client", any(g["client_id"] == public_client_id for g in grants["items"]))

        revoked_grant = expect_json(
            expect_status(
                "POST /admin/grants/revoke",
                admin.post(
                    f"{BASE_URL}/admin/grants/revoke",
                    json={"user_id": user_id, "client_id": public_client_id},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("admin_revoke_grant_removed", revoked_grant["removed_grants"] >= 1)

        first_request = expect_json(
            expect_status(
                "POST /auth/me/access-requests reject target",
                user.post(
                    f"{BASE_URL}/auth/me/access-requests",
                    json={
                        "site_name": "Reject Target",
                        "site_url": "https://reject.example",
                        "request_description": "Reject target for full e2e",
                    },
                    headers=csrf_header(user),
                    timeout=10,
                ),
                201,
            )
        )
        first_request_id = first_request["id"]
        expect_status(
            "GET /admin/access-requests",
            admin.get(
                f"{BASE_URL}/admin/access-requests",
                params={"status": 0, "q": "Reject", "page": 1, "page_size": 20},
                timeout=10,
            ),
            200,
        )
        rejected = expect_json(
            expect_status(
                "POST /admin/access-requests/{request_id}/reject",
                admin.post(
                    f"{BASE_URL}/admin/access-requests/{first_request_id}/reject",
                    json={"admin_note": "Rejected by full e2e"},
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("access_request_rejected", rejected["status"] == 2)

        second_request = expect_json(
            expect_status(
                "POST /auth/me/access-requests approve target",
                user.post(
                    f"{BASE_URL}/auth/me/access-requests",
                    json={
                        "site_name": "Approve Target",
                        "site_url": "https://approve.example",
                        "request_description": "Approve target for full e2e",
                    },
                    headers=csrf_header(user),
                    timeout=10,
                ),
                201,
            )
        )
        second_request_id = second_request["id"]
        approved = expect_json(
            expect_status(
                "POST /admin/access-requests/{request_id}/approve",
                admin.post(
                    f"{BASE_URL}/admin/access-requests/{second_request_id}/approve",
                    json={
                        "client_name": "Approved Request Client",
                        "client_type": "confidential",
                        "redirect_uris": ["https://approve.example/callback"],
                        "scopes": ["openid", "profile", "email"],
                        "allowed_audiences": [DEFAULT_AUDIENCE],
                        "grant_types": ["authorization_code"],
                        "token_endpoint_auth_method": "client_secret_post",
                        "jwks": None,
                    },
                    headers=csrf_header(admin),
                    timeout=10,
                ),
                200,
            )
        )
        check("access_request_approved", approved["status"] == 1)

        access_requests = expect_json(
            expect_status(
                "GET /auth/me/access-requests after resolution",
                user.get(f"{BASE_URL}/auth/me/access-requests", timeout=10),
                200,
            )
        )
        check("user_access_requests_total", access_requests["total"] >= 2)

        valkey = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
        delivery_keys = valkey.keys(f"oauth:client_delivery:{user_id}:*")
        check("delivery_key_created", len(delivery_keys) == 1, delivery_keys)
        delivery_token = delivery_keys[0].split(":")[-1]
        delivery = expect_json(
            expect_status(
                "GET /auth/me/access-delivery",
                user.get(
                    f"{BASE_URL}/auth/me/access-delivery",
                    params={"token": delivery_token},
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "access_delivery_read_once_payload",
            delivery["request_id"] == second_request_id and delivery.get("client_secret"),
        )
        expect_status(
            "GET /auth/me/access-delivery read once",
            user.get(
                f"{BASE_URL}/auth/me/access-delivery",
                params={"token": delivery_token},
                timeout=10,
            ),
            404,
        )

        expect_status(
            "POST /auth/me/mfa/totp/confirm before begin",
            user.post(
                f"{BASE_URL}/auth/me/mfa/totp/confirm",
                json={"code": "000000"},
                headers=csrf_header(user),
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /auth/mfa/verify without pending challenge",
            user.post(
                f"{BASE_URL}/auth/mfa/verify",
                json={"code": "000000", "remember_device": False},
                headers=csrf_header(user),
                timeout=10,
            ),
            401,
        )

        totp_begin = expect_json(
            expect_status(
                "POST /auth/me/mfa/totp/begin",
                user.post(
                    f"{BASE_URL}/auth/me/mfa/totp/begin",
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "mfa_totp_begin_secret_shape",
            re.fullmatch(r"[A-Z2-7]+", totp_begin.get("secret_base32", "")) is not None,
            totp_begin,
        )
        check(
            "mfa_totp_begin_uri_binds_issuer_and_account",
            "otpauth://totp/" in totp_begin.get("otpauth_uri", "")
            and "issuer=" in totp_begin.get("otpauth_uri", ""),
            totp_begin,
        )
        totp_confirm = expect_json(
            expect_status(
                "POST /auth/me/mfa/totp/confirm",
                user.post(
                    f"{BASE_URL}/auth/me/mfa/totp/confirm",
                    json={"code": totp_code(totp_begin["secret_base32"])},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        backup_codes = totp_confirm.get("backup_codes", [])
        check(
            "mfa_totp_confirm_enables_mfa_and_returns_backup_codes_once",
            totp_confirm.get("mfa_enabled") is True
            and len(backup_codes) == 10
            and all(re.fullmatch(r"\d{5}-\d{5}", code) for code in backup_codes),
            totp_confirm,
        )
        expect_status(
            "POST /auth/me/mfa/totp/begin when enabled",
            user.post(
                f"{BASE_URL}/auth/me/mfa/totp/begin",
                headers=csrf_header(user),
                timeout=10,
            ),
            409,
        )
        expect_status(
            "POST /auth/me/mfa/backup-codes/regenerate invalid code",
            user.post(
                f"{BASE_URL}/auth/me/mfa/backup-codes/regenerate",
                json={"code": "000000"},
                headers=csrf_header(user),
                timeout=10,
            ),
            400,
        )
        regenerated = expect_json(
            expect_status(
                "POST /auth/me/mfa/backup-codes/regenerate backup code",
                user.post(
                    f"{BASE_URL}/auth/me/mfa/backup-codes/regenerate",
                    json={"code": backup_codes[0]},
                    headers=csrf_header(user),
                    timeout=10,
                ),
                200,
            )
        )
        regenerated_backup_codes = regenerated.get("backup_codes", [])
        check(
            "mfa_backup_regenerate_replaces_codes",
            len(regenerated_backup_codes) == 10
            and regenerated_backup_codes != backup_codes
            and all(re.fullmatch(r"\d{5}-\d{5}", code) for code in regenerated_backup_codes),
            regenerated,
        )
        backup_codes = regenerated_backup_codes
        expect_status(
            "POST /auth/logout before MFA challenge login",
            user.post(f"{BASE_URL}/auth/logout", timeout=10),
            200,
        )

        mfa_login = requests.Session()
        mfa_login.headers.update({"User-Agent": "nazo-oauth-full-e2e-mfa/1"})
        mfa_login_body = login(
            mfa_login,
            USER_EMAIL,
            USER_PASSWORD,
            "POST /auth/login MFA challenge",
        )
        check("mfa_login_requires_second_factor", mfa_login_body.get("mfa_required") is True)
        pending_me = expect_json(
            expect_status(
                "GET /auth/me pending MFA",
                mfa_login.get(f"{BASE_URL}/auth/me", timeout=10),
                200,
            )
        )
        check("auth_me_reports_pending_mfa", pending_me.get("mfa_required") is True, pending_me)
        expect_status(
            "POST /auth/mfa/verify invalid backup code",
            mfa_login.post(
                f"{BASE_URL}/auth/mfa/verify",
                json={"code": "00000-00000", "remember_device": False},
                headers=csrf_header(mfa_login),
                timeout=10,
            ),
            400,
        )
        mfa_verified = expect_json(
            expect_status(
                "POST /auth/mfa/verify backup code remember device",
                mfa_login.post(
                    f"{BASE_URL}/auth/mfa/verify",
                    json={"code": backup_codes[0], "remember_device": True},
                    headers=csrf_header(mfa_login),
                    timeout=10,
                ),
                200,
            )
        )
        check(
            "mfa_backup_code_completes_pending_session",
            mfa_verified.get("success") is True and mfa_verified.get("method") == "recovery_code",
            mfa_verified,
        )
        check(
            "mfa_remember_device_cookie_set",
            bool(mfa_login.cookies.get("nazo_oauth_mfa_remembered")),
            mfa_login.cookies.get_dict(),
        )
        expect_status(
            "POST /auth/logout after remembered MFA",
            mfa_login.post(f"{BASE_URL}/auth/logout", timeout=10),
            200,
        )
        remembered_login_body = login(
            mfa_login,
            USER_EMAIL,
            USER_PASSWORD,
            "POST /auth/login remembered MFA device",
        )
        check(
            "remembered_mfa_device_skips_second_factor",
            remembered_login_body.get("mfa_required") is False,
            remembered_login_body,
        )
        expect_status(
            "POST /auth/me/mfa/disable invalid code",
            mfa_login.post(
                f"{BASE_URL}/auth/me/mfa/disable",
                json={"code": "000000"},
                headers=csrf_header(mfa_login),
                timeout=10,
            ),
            400,
        )
        mfa_disabled = expect_json(
            expect_status(
                "POST /auth/me/mfa/disable",
                mfa_login.post(
                    f"{BASE_URL}/auth/me/mfa/disable",
                    json={"code": backup_codes[1]},
                    headers=csrf_header(mfa_login),
                    timeout=10,
                ),
                200,
            )
        )
        check("mfa_disable_clears_mfa_state", mfa_disabled.get("mfa_enabled") is False)
        disabled_again = expect_json(
            expect_status(
                "POST /auth/me/mfa/disable already disabled",
                mfa_login.post(
                    f"{BASE_URL}/auth/me/mfa/disable",
                    json={"code": "000000"},
                    headers=csrf_header(mfa_login),
                    timeout=10,
                ),
                200,
            )
        )
        check("mfa_disable_is_idempotent_when_disabled", disabled_again.get("mfa_enabled") is False)
        expect_status(
            "POST /auth/me/mfa/backup-codes/regenerate when disabled",
            mfa_login.post(
                f"{BASE_URL}/auth/me/mfa/backup-codes/regenerate",
                json={"code": "000000"},
                headers=csrf_header(mfa_login),
                timeout=10,
            ),
            400,
        )
        expect_status(
            "POST /auth/logout after MFA disable",
            mfa_login.post(f"{BASE_URL}/auth/logout", timeout=10),
            200,
        )

        expect_status(
            "POST /auth/logout",
            user.post(f"{BASE_URL}/auth/logout", timeout=10),
            200,
        )
        expect_status(
            "GET /auth/me after logout",
            user.get(f"{BASE_URL}/auth/me", timeout=10),
            401,
        )

    finally:
        smtp.stop()


if __name__ == "__main__":
    run()
    print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=False, indent=2))
