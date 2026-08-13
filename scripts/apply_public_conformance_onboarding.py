#!/usr/bin/env python3
"""Provision public conformance clients through the production control plane.

The tool deliberately has no database, server-crate, or host-filesystem integration.
It performs the same authenticated application, approval, one-time credential delivery,
and mTLS trust review steps available to ordinary operators.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import http.cookiejar
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CREDENTIAL_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0
LOGIN_TRANSPORT_ATTEMPTS = 3
LOGIN_RETRY_BASE_SECONDS = 1.0
MFA_VERIFICATION_ATTEMPTS = 2
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6


class OnboardingError(RuntimeError):
    pass


class OnboardingHttpError(OnboardingError):
    def __init__(self, method: str, path: str, status: int) -> None:
        super().__init__(f"{method} {path} returned HTTP {status}")
        self.method = method
        self.path = path
        self.status = status


def closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise OnboardingError("operator credentials contain a duplicate field")
        value[key] = child
    return value


def read_operator_credentials(args: argparse.Namespace) -> dict[str, str]:
    use_stdin = bool(getattr(args, "credentials_stdin", False))
    descriptor = getattr(args, "credentials_fd", None)
    if use_stdin == (descriptor is not None):
        raise OnboardingError(
            "select exactly one of --credentials-stdin or --credentials-fd"
        )
    if use_stdin:
        if sys.stdin.isatty():
            raise OnboardingError("--credentials-stdin refuses an interactive terminal")
        payload = sys.stdin.buffer.read(MAX_CREDENTIAL_BYTES + 1)
    else:
        if not isinstance(descriptor, int) or descriptor < 3:
            raise OnboardingError("--credentials-fd must be an already-open descriptor >= 3")
        chunks = []
        total = 0
        while total <= MAX_CREDENTIAL_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_CREDENTIAL_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    if not payload or len(payload) > MAX_CREDENTIAL_BYTES:
        raise OnboardingError(
            f"operator credentials must contain 1 through {MAX_CREDENTIAL_BYTES} bytes"
        )
    try:
        value = json.loads(payload, object_pairs_hook=closed_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OnboardingError("operator credentials must be strict UTF-8 JSON") from error
    required = {
        "applicant_email",
        "applicant_password",
        "admin_email",
        "admin_password",
        "admin_mfa_totp_secret",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OnboardingError(
            "operator credentials must contain exactly applicant_email, applicant_password, admin_email, admin_password, and admin_mfa_totp_secret"
        )
    if any(
        not isinstance(value[field], str)
        or not value[field]
        or len(value[field].encode("utf-8")) > 1024
        for field in required
    ):
        raise OnboardingError("operator credential values must contain 1 through 1024 bytes")
    if value["applicant_email"] == value["admin_email"]:
        raise OnboardingError("applicant and administrator identities must differ")
    return value


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise OnboardingError(
            f"unexpected redirect from control-plane request: HTTP {code}"
        )


def totp_code(secret_base32: str, timestamp: float | None = None) -> str:
    normalized = "".join(secret_base32.split()).upper()
    if not normalized or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in normalized):
        raise OnboardingError("administrator TOTP secret is not canonical base32")
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    try:
        secret = base64.b32decode(padded, casefold=False)
    except binascii.Error as error:
        raise OnboardingError("administrator TOTP secret is not canonical base32") from error
    if len(secret) < 16:
        raise OnboardingError("administrator TOTP secret is too short")
    counter = int(time.time() if timestamp is None else timestamp) // TOTP_PERIOD_SECONDS
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFF_FFFF
    return f"{value % (10**TOTP_DIGITS):0{TOTP_DIGITS}d}"


def canonical_https_origin(value: str, *, label: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise OnboardingError(f"{label} must be an HTTPS origin without credentials, path, query, or fragment")
    host = parsed.hostname.lower()
    port = parsed.port
    authority = host if port in {None, 443} else f"{host}:{port}"
    return f"https://{authority}"


def access_request_site_name(logical_client_id: str) -> str:
    digest = hashlib.sha256(logical_client_id.encode("utf-8")).hexdigest()[:24]
    return f"OIDF conformance client {digest}"


def validate_trust_bundle(bundle: bytes, *, required: bool) -> str:
    bundle_text = bundle.decode("ascii")
    if required and "-----BEGIN CERTIFICATE-----" not in bundle_text:
        raise OnboardingError("approved mTLS trust bundle contains no certificate")
    return bundle_text


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OnboardingError(f"cannot read JSON document {path}: {error}") from error


def write_private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def write_private_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


class ControlPlaneSession:
    def __init__(
        self,
        origin: str,
        opener: urllib.request.OpenerDirector,
        csrf_token: str,
    ) -> None:
        self.origin = origin
        self.opener = opener
        self.csrf_token = csrf_token

    @classmethod
    def login(
        cls,
        origin: str,
        email: str,
        password: str,
        *,
        mfa_totp_secret: str | None = None,
    ) -> "ControlPlaneSession":
        for attempt in range(LOGIN_TRANSPORT_ATTEMPTS):
            cookie_jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                urllib.request.HTTPCookieProcessor(cookie_jar),
                NoRedirectHandler(),
            )
            session = cls(origin=origin, opener=opener, csrf_token="")
            try:
                body = session.request_json(
                    "POST",
                    "/auth/login",
                    {"email": email, "password": password},
                    expected_status=200,
                    csrf=False,
                )
            except OnboardingError as error:
                cause = error.__cause__
                retryable = isinstance(cause, (urllib.error.URLError, TimeoutError, OSError)) and not isinstance(
                    cause, urllib.error.HTTPError
                )
                if not retryable or attempt + 1 == LOGIN_TRANSPORT_ATTEMPTS:
                    raise
                time.sleep(LOGIN_RETRY_BASE_SECONDS * (2**attempt))
                continue

            csrf_token = body.get("csrf_token") if isinstance(body, dict) else None
            if not isinstance(csrf_token, str) or not csrf_token:
                raise OnboardingError("login did not establish a CSRF token")
            session.csrf_token = csrf_token
            if body.get("mfa_required") is True:
                if mfa_totp_secret is None:
                    raise OnboardingError(
                        "login requires interactive MFA and no TOTP secret was supplied"
                    )
                for mfa_attempt in range(MFA_VERIFICATION_ATTEMPTS):
                    try:
                        session.request_json(
                            "POST",
                            "/auth/mfa/verify",
                            {"code": totp_code(mfa_totp_secret), "remember_device": False},
                            expected_status=200,
                            csrf=True,
                        )
                        break
                    except OnboardingHttpError as error:
                        if error.status not in {400, 401} or mfa_attempt + 1 == MFA_VERIFICATION_ATTEMPTS:
                            raise
                        wait_seconds = TOTP_PERIOD_SECONDS - (time.time() % TOTP_PERIOD_SECONDS) + 1
                        time.sleep(wait_seconds)
                refreshed = session.request_json(
                    "GET",
                    "/auth/csrf",
                    expected_status=200,
                )
                refreshed_token = refreshed.get("csrf_token") if isinstance(refreshed, dict) else None
                if not isinstance(refreshed_token, str) or not refreshed_token:
                    raise OnboardingError("MFA verification did not refresh the CSRF token")
                session.csrf_token = refreshed_token
            return session

        raise AssertionError("login retry loop exhausted without returning or raising")

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        expected_status: int,
        csrf: bool = False,
        raw_body: bytes | None = None,
        content_type: str | None = None,
    ) -> tuple[bytes, str]:
        if not path.startswith("/") or path.startswith("//"):
            raise OnboardingError(f"control-plane path must be origin-relative: {path}")
        url = f"{self.origin}{path}"
        data = None
        headers = {"Accept": "application/json", "User-Agent": "nazo-conformance-onboarding/1"}
        if payload is not None and raw_body is not None:
            raise OnboardingError("control-plane request cannot combine JSON and raw bodies")
        if raw_body is not None:
            if not content_type:
                raise OnboardingError("control-plane raw request requires a content type")
            data = raw_body
            headers["Content-Type"] = content_type
        elif content_type is not None:
            raise OnboardingError("control-plane content type requires a raw body")
        elif payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf:
            if not self.csrf_token:
                raise OnboardingError("CSRF-protected request has no established token")
            headers["x-csrf-token"] = self.csrf_token
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=DEFAULT_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            with error:
                error.read(MAX_RESPONSE_BYTES + 1)
                raise OnboardingHttpError(method, path, error.code) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OnboardingError(
                f"{method} {path} failed: {type(error).__name__}"
            ) from error
        with response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise OnboardingError(f"{method} {path} response exceeds {MAX_RESPONSE_BYTES} bytes")
            if response.status != expected_status:
                raise OnboardingHttpError(method, path, response.status)
            final = urllib.parse.urlsplit(response.geturl())
            if f"{final.scheme}://{final.netloc}" != self.origin:
                raise OnboardingError(f"{method} {path} escaped the configured origin")
            return body, response.headers.get("Content-Type", "")

    def request_json(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        expected_status: int,
        csrf: bool = False,
        raw_body: bytes | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        body, content_type = self.request(
            method,
            path,
            payload,
            expected_status=expected_status,
            csrf=csrf,
            raw_body=raw_body,
            content_type=content_type,
        )
        if "application/json" not in content_type.lower():
            raise OnboardingError(f"{method} {path} did not return JSON")
        try:
            value = json.loads(body)
        except json.JSONDecodeError as error:
            raise OnboardingError(f"{method} {path} returned invalid JSON") from error
        if not isinstance(value, dict):
            raise OnboardingError(f"{method} {path} must return a JSON object")
        return value


def replace_client_material(value: Any, logical_id: str, actual_id: str, secret: str | None) -> int:
    replacements = 0
    if isinstance(value, dict):
        if value.get("client_id") == logical_id:
            value["client_id"] = actual_id
            if secret is not None:
                value["client_secret"] = secret
            else:
                value.pop("client_secret", None)
            replacements += 1
        for child in value.values():
            replacements += replace_client_material(child, logical_id, actual_id, secret)
    elif isinstance(value, list):
        for child in value:
            replacements += replace_client_material(child, logical_id, actual_id, secret)
    return replacements


def write_runner_env(
    path: Path,
    plan_config_path: Path,
    plan_set_path: Path,
    plan_manifest_path: Path,
) -> None:
    plan_set = read_json(plan_set_path)
    plan_manifest = read_json(plan_manifest_path)
    if not isinstance(plan_set, list) or not isinstance(plan_manifest, dict):
        raise OnboardingError("plan set and plan manifest have invalid JSON shapes")
    write_private_text(
        path,
        "\n".join(
            (
                "# Secret-free path hints; pass these files explicitly to the runner.",
                f"OIDF_PLAN_CONFIG_FILE={plan_config_path.name}",
                f"OIDF_PLAN_SET_FILE={plan_set_path.name}",
                f"OIDF_PLAN_MANIFEST_FILE={plan_manifest_path.name}",
                "",
            )
        ),
    )


def require_manifest(path: Path) -> dict[str, Any]:
    value = read_json(path)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise OnboardingError("onboarding manifest must be a schema-1 JSON object")
    clients = value.get("clients")
    if not isinstance(clients, list) or not clients:
        raise OnboardingError("onboarding manifest must contain a non-empty clients array")
    logical_ids: set[str] = set()
    for index, client in enumerate(clients):
        if not isinstance(client, dict):
            raise OnboardingError(f"clients[{index}] must be an object")
        logical_id = client.get("logical_client_id")
        request = client.get("request")
        if not isinstance(logical_id, str) or not logical_id or logical_id in logical_ids:
            raise OnboardingError(f"clients[{index}] has an invalid or duplicate logical_client_id")
        if not isinstance(request, dict) or request.get("client_type") != "confidential":
            raise OnboardingError(f"clients[{index}] must contain a confidential client request")
        logical_ids.add(logical_id)
    return value


def persist_onboarding_state(path: Path, state: dict[str, Any]) -> None:
    """Durably journal every externally visible onboarding mutation."""
    write_private_json(path, state)


def access_request_for_id(session: ControlPlaneSession, request_id: str) -> dict[str, Any] | None:
    listed = session.request_json("GET", "/auth/me/access-requests", expected_status=200)
    return next(
        (
            candidate
            for candidate in listed.get("items", [])
            if isinstance(candidate, dict) and candidate.get("id") == request_id
        ),
        None,
    )


def delivered_client_for_request(
    session: ControlPlaneSession,
    request_id: str,
) -> tuple[str, str | None] | None:
    request = access_request_for_id(session, request_id)
    if not isinstance(request, dict) or request.get("delivery_available") is not True:
        return None
    delivery = session.request_json(
        "POST",
        "/auth/me/access-delivery",
        {"request_id": request_id},
        expected_status=200,
        csrf=True,
    )
    client_id = delivery.get("client_id")
    secret = delivery.get("client_secret")
    if not isinstance(client_id, str) or not client_id:
        raise OnboardingError(f"credential delivery for request {request_id} returned no client_id")
    if secret is not None and (not isinstance(secret, str) or not secret):
        raise OnboardingError(f"credential delivery for request {request_id} returned an invalid client_secret")
    return client_id, secret


def apply_onboarding(args: argparse.Namespace) -> int:
    try:
        lease_id = str(uuid.UUID(args.lease_id))
    except (AttributeError, TypeError, ValueError) as error:
        raise OnboardingError("apply requires --lease-id UUID") from error
    manifest_sha256 = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    manifest = require_manifest(args.manifest)
    origin = canonical_https_origin(str(manifest.get("target_issuer", "")), label="target_issuer")
    configured = canonical_https_origin(args.target_issuer, label="--target-issuer")
    if origin != configured:
        raise OnboardingError("onboarding manifest target_issuer does not match --target-issuer")
    applicant_email = str(manifest.get("applicant_email", "")).strip()
    if not applicant_email:
        raise OnboardingError("onboarding manifest applicant_email is required")
    credentials = read_operator_credentials(args)
    if credentials["applicant_email"] != applicant_email:
        raise OnboardingError(
            "operator credential applicant_email does not match the manifest commitment"
        )
    applicant_password = credentials["applicant_password"]
    admin_email = credentials["admin_email"]
    admin_password = credentials["admin_password"]
    admin_mfa_totp_secret = credentials["admin_mfa_totp_secret"]
    if args.state_file.exists():
        raise OnboardingError(f"state file already exists; clean up the prior onboarding first: {args.state_file}")

    plan_document = read_json(args.plan_configs)
    if not isinstance(plan_document, dict) or not isinstance(plan_document.get("configs"), dict):
        raise OnboardingError("plan config document must contain a configs object")
    applicant = ControlPlaneSession.login(origin, applicant_email, applicant_password)
    admin = ControlPlaneSession.login(
        origin,
        admin_email,
        admin_password,
        mfa_totp_secret=admin_mfa_totp_secret,
    )
    applicant_me = applicant.request_json("GET", "/auth/me", expected_status=200)
    admin_me = admin.request_json("GET", "/auth/me", expected_status=200)
    if applicant_me.get("id") == admin_me.get("id"):
        raise OnboardingError("applicant and approver must be different users")
    if not isinstance(admin_me.get("admin_level"), int) or admin_me["admin_level"] < 1:
        raise OnboardingError("OIDF_ADMIN_EMAIL is not an active administrator")

    state: dict[str, Any] = {
        "schema": 1,
        "target_issuer": origin,
        "conformance_lease_id": lease_id,
        "manifest_sha256": manifest_sha256,
        "applicant_user_id": applicant_me.get("id"),
        "approver_user_id": admin_me.get("id"),
        "clients": [],
    }
    delivered_clients: list[dict[str, Any]] = []
    requested_trust_anchor = False
    persist_onboarding_state(args.state_file, state)
    for item in manifest["clients"]:
        logical_id = item["logical_client_id"]
        state_entry: dict[str, Any] = {"logical_client_id": logical_id}
        state["clients"].append(state_entry)
        persist_onboarding_state(args.state_file, state)
        access = applicant.request_json(
            "POST",
            "/auth/me/access-requests",
            {
                "site_name": access_request_site_name(logical_id),
                "site_url": manifest["suite_base_url"],
                "request_description": "Public black-box conformance onboarding through the production approval flow.",
            },
            expected_status=201,
            csrf=True,
        )
        request_id = access.get("id")
        if not isinstance(request_id, str):
            raise OnboardingError(f"access request for {logical_id} returned no id")
        state_entry["access_request_id"] = request_id
        persist_onboarding_state(args.state_file, state)
        client_request = dict(item["request"])
        client_request["conformance_lease_id"] = lease_id
        approval = admin.request_json(
            "POST",
            f"/admin/access-requests/{urllib.parse.quote(request_id, safe='')}/approve",
            client_request,
            expected_status=200,
            csrf=True,
        )
        approved_client_record_id = approval.get("approved_client_id")
        if isinstance(approved_client_record_id, str) and approved_client_record_id:
            state_entry["approved_client_record_id"] = approved_client_record_id
        state_entry["access_request_approved"] = True
        persist_onboarding_state(args.state_file, state)
        delivered = delivered_client_for_request(applicant, request_id)
        if delivered is None:
            raise OnboardingError(f"approved access request {request_id} has no one-time delivery token")
        actual_id, secret = delivered
        delivered_clients.append(
            {
                "logical_client_id": logical_id,
                "client_id": actual_id,
                "client_secret": secret,
            }
        )
        state_entry["client_id"] = actual_id
        persist_onboarding_state(args.state_file, state)
        replacements = replace_client_material(plan_document, logical_id, actual_id, secret)
        if replacements == 0:
            raise OnboardingError(f"logical client {logical_id} is absent from the plan configs")

        trust_request_id = None
        certificate_pem = item.get("mtls_trust_anchor_pem")
        if certificate_pem is not None:
            requested_trust_anchor = True
            if not isinstance(certificate_pem, str) or not certificate_pem.startswith("-----BEGIN CERTIFICATE-----"):
                raise OnboardingError(f"logical client {logical_id} has an invalid trust anchor")
            trust_request = applicant.request_json(
                "POST",
                "/auth/me/mtls-trust-requests",
                {"client_id": actual_id, "certificate_pem": certificate_pem},
                expected_status=201,
                csrf=True,
            )
            trust_request_id = trust_request.get("id")
            if not isinstance(trust_request_id, str):
                raise OnboardingError(f"mTLS trust application for {logical_id} returned no id")
            state_entry["mtls_trust_request_id"] = trust_request_id
            persist_onboarding_state(args.state_file, state)
            admin.request_json(
                "POST",
                f"/admin/mtls-trust-requests/{urllib.parse.quote(trust_request_id, safe='')}/approve",
                {"admin_note": "Approved for public conformance validation."},
                expected_status=200,
                csrf=True,
            )
            state_entry["mtls_trust_approved"] = True
            persist_onboarding_state(args.state_file, state)

    bundle, _ = admin.request("GET", "/admin/mtls-trust-anchors.pem", expected_status=200)
    bundle_text = validate_trust_bundle(bundle, required=requested_trust_anchor)
    state["trust_bundle_sha256"] = hashlib.sha256(bundle).hexdigest()
    write_private_json(args.plan_configs, plan_document)
    if not args.no_runner_env:
        write_runner_env(
            args.runner_env,
            args.plan_configs,
            args.plan_set,
            args.plan_manifest,
        )
    write_private_json(
        args.delivered_client_material,
        {
            "schema": 1,
            "target_issuer": origin,
            "suite_base_url": manifest["suite_base_url"],
            "conformance_lease_id": lease_id,
            "manifest_sha256": manifest_sha256,
            "clients": delivered_clients,
        },
    )
    write_private_text(args.trust_bundle, bundle_text)
    state["complete"] = True
    persist_onboarding_state(args.state_file, state)
    return 0


def cleanup_onboarding(args: argparse.Namespace) -> int:
    state = read_json(args.state_file)
    if not isinstance(state, dict) or state.get("schema") != 1:
        raise OnboardingError("cleanup state must be a schema-1 JSON object")
    origin = canonical_https_origin(str(state.get("target_issuer", "")), label="state target_issuer")
    configured = canonical_https_origin(args.target_issuer, label="--target-issuer")
    if origin != configured:
        raise OnboardingError("cleanup state target_issuer does not match --target-issuer")
    credentials = read_operator_credentials(args)
    applicant_email = credentials["applicant_email"]
    applicant_password = credentials["applicant_password"]
    admin_email = credentials["admin_email"]
    admin_password = credentials["admin_password"]
    admin_mfa_totp_secret = credentials["admin_mfa_totp_secret"]
    applicant = ControlPlaneSession.login(origin, applicant_email, applicant_password)
    admin = ControlPlaneSession.login(
        origin,
        admin_email,
        admin_password,
        mfa_totp_secret=admin_mfa_totp_secret,
    )
    for item in reversed(state.get("clients", [])):
        if not isinstance(item, dict):
            raise OnboardingError("cleanup state contains an invalid client record")
        trust_request_id = item.get("mtls_trust_request_id")
        client_id = item.get("client_id")
        request_id = item.get("access_request_id")
        if not any(isinstance(value, str) and value for value in (request_id, client_id, trust_request_id)):
            continue
        if not isinstance(request_id, str) or not request_id:
            raise OnboardingError("cleanup state contains a remote client without an access request")
        if isinstance(trust_request_id, str):
            trust_requests = applicant.request_json(
                "GET", "/auth/me/mtls-trust-requests", expected_status=200
            )
            trust_request = next(
                (
                    candidate
                    for candidate in trust_requests.get("items", [])
                    if isinstance(candidate, dict) and candidate.get("id") == trust_request_id
                ),
                None,
            )
            status = trust_request.get("status") if isinstance(trust_request, dict) else None
            if status == 0:
                admin.request_json(
                    "POST",
                    f"/admin/mtls-trust-requests/{urllib.parse.quote(trust_request_id, safe='')}/reject",
                    {"admin_note": "Public conformance onboarding did not complete."},
                    expected_status=200,
                    csrf=True,
                )
            elif status == 1:
                admin.request_json(
                    "POST",
                    f"/admin/mtls-trust-requests/{urllib.parse.quote(trust_request_id, safe='')}/revoke",
                    {"reason": "Public conformance run completed."},
                    expected_status=200,
                    csrf=True,
                )
        if not isinstance(client_id, str) or not client_id:
            request = access_request_for_id(applicant, request_id)
            status = request.get("status") if isinstance(request, dict) else None
            if status == 0:
                admin.request_json(
                    "POST",
                    f"/admin/access-requests/{urllib.parse.quote(request_id, safe='')}/reject",
                    {"admin_note": "Public conformance onboarding did not complete."},
                    expected_status=200,
                    csrf=True,
                )
                continue
            delivered = delivered_client_for_request(applicant, request_id)
            if delivered is not None:
                client_id = delivered[0]
            if not isinstance(client_id, str) or not client_id:
                raise OnboardingError(
                    f"cannot recover client_id for onboarding record {item.get('logical_client_id')}"
                )
        admin.request_json(
            "PATCH",
            f"/admin/clients/{urllib.parse.quote(client_id, safe='')}",
            {"is_active": False},
            expected_status=200,
            csrf=True,
        )
    args.state_file.unlink()
    args.delivered_client_material.unlink(missing_ok=True)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("apply", "cleanup"))
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--lease-id")
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--credentials-stdin", action="store_true")
    credentials.add_argument("--credentials-fd", type=int)
    parser.add_argument("--manifest", type=Path, default=Path("runtime/oidf/oidf-onboarding-manifest.json"))
    parser.add_argument("--plan-configs", type=Path, default=Path("runtime/oidf/oidf-plan-configs.json"))
    parser.add_argument("--plan-set", type=Path, default=Path("runtime/oidf/oidf-plan-set.json"))
    parser.add_argument(
        "--plan-manifest",
        type=Path,
        default=Path("runtime/oidf/oidf-plan-set-manifest.json"),
    )
    parser.add_argument("--runner-env", type=Path, default=Path("runtime/oidf/oidf-runner.env"))
    parser.add_argument(
        "--delivered-client-material",
        type=Path,
        default=Path("runtime/oidf/oidf-delivered-client-material.json"),
    )
    parser.add_argument("--no-runner-env", action="store_true")
    parser.add_argument("--state-file", type=Path, default=Path("runtime/oidf/oidf-onboarding-state.json"))
    parser.add_argument(
        "--trust-bundle",
        type=Path,
        default=Path("runtime/oidf/approved-mtls-trust-anchors.pem"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "apply":
            return apply_onboarding(args)
        return cleanup_onboarding(args)
    except OnboardingError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
