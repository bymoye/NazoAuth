#!/usr/bin/env python3
"""Translate a verified official OIDF artifact into production applications."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
from typing import Any

from oidf_onboarding_bundle import (
    MANIFEST_FILE_NAME,
    validate_artifact_directory,
)
from prepare_openid4vc_public_onboarding import (
    base_client_request as openid4vc_client_request,
    prepare_clients as prepare_openid4vc_clients,
    public_https_origin,
    public_jwks,
)


OPENID4VC_AGGREGATE = "openid4vc-onboarding-configs.json"


def fail(message: str) -> None:
    raise SystemExit(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def callback_url(suite_origin: str, alias: str, endpoint: str = "callback") -> str:
    if not alias or any(character in alias for character in "/?#"):
        fail("OIDF configuration contains an invalid alias")
    return f"{suite_origin}/test/a/{alias}/{endpoint}"


def oauth_client_request(
    *,
    target_origin: str,
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
        "allowed_audiences": [
            "resource://default",
            f"{target_origin}/userinfo",
            f"{target_origin}/fapi/resource",
        ],
        "grant_types": grant_types or ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": auth_method,
        "require_dpop_bound_tokens": False,
        "require_mtls_bound_tokens": False,
        "allow_client_assertion_audience_array": False,
        "allow_client_assertion_endpoint_audience": False,
        "require_par_request_object": False,
        "backchannel_token_delivery_mode": "poll",
        "backchannel_user_code_parameter": False,
        "backchannel_logout_session_required": False,
        "frontchannel_logout_session_required": False,
        "jwks": None,
    }


def require_object(configs: dict[str, object], file_name: str) -> dict[str, object]:
    value = configs.get(file_name)
    if not isinstance(value, dict):
        fail(f"official OIDF artifact is missing {file_name}")
    return value


def require_alias(config: dict[str, object], file_name: str) -> str:
    alias = config.get("alias")
    if not isinstance(alias, str) or not alias:
        fail(f"{file_name}.alias is required")
    return alias


def require_client(config: dict[str, object], field: str, source: str) -> dict[str, object]:
    client = config.get(field)
    if not isinstance(client, dict):
        fail(f"{source}.{field} is required")
    client_id = client.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        fail(f"{source}.{field}.client_id is required")
    return client


def certificate_subject_dn(certificate_pem: str) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
        input=certificate_pem,
        text=True,
        capture_output=True,
        check=True,
    )
    subject = result.stdout.strip()
    if subject.startswith("subject="):
        subject = subject[len("subject=") :].strip()
    if not subject or "\n" in subject or "\r" in subject:
        fail("OIDF mTLS certificate has no canonical RFC 4514 subject DN")
    return subject


def certificate_sha256(certificate_pem: str) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(certificate_pem)
    except ValueError as error:
        fail(f"OIDF mTLS client certificate is malformed: {error}")
    return hashlib.sha256(der).hexdigest()


def prepare_oidc_clients(
    configs: dict[str, object], *, target_origin: str, suite_origin: str
) -> list[dict[str, object]]:
    clients: dict[str, dict[str, object]] = {}

    def add(logical_id: str, request: dict[str, object], ca: str | None = None) -> None:
        candidate = {
            "logical_client_id": logical_id,
            "request": request,
            "mtls_trust_anchor_pem": ca,
        }
        previous = clients.get(logical_id)
        if previous is not None and previous != candidate:
            fail(f"conflicting official onboarding policy for {logical_id}")
        clients[logical_id] = candidate

    basic_name = "oidf-oidcc-basic-plan-config.json"
    formpost_name = "oidf-oidcc-formpost-plan-config.json"
    basic = require_object(configs, basic_name)
    formpost = require_object(configs, formpost_name)
    callbacks = [
        callback_url(suite_origin, require_alias(basic, basic_name)),
        callback_url(suite_origin, require_alias(formpost, formpost_name)),
    ]
    for field, auth_method, name in (
        ("client", "client_secret_basic", "OIDF Basic Client"),
        ("client2", "client_secret_basic", "OIDF Basic Client 2"),
        ("client_secret_post", "client_secret_post", "OIDF Form Post Client"),
    ):
        metadata = require_client(basic, field, basic_name)
        add(
            str(metadata["client_id"]),
            oauth_client_request(
                target_origin=target_origin,
                name=name,
                auth_method=auth_method,
                redirect_uris=callbacks,
                scopes=str(metadata.get("scope", "")).split(),
            ),
        )

    rp_name = "oidf-oidcc-rp-initiated-logout-plan-config.json"
    rp = require_object(configs, rp_name)
    rp_alias = require_alias(rp, rp_name)
    rp_client = require_client(rp, "client", rp_name)
    add(
        str(rp_client["client_id"]),
        oauth_client_request(
            target_origin=target_origin,
            name="OIDF RP-Initiated Logout Client",
            auth_method="client_secret_basic",
            redirect_uris=[callback_url(suite_origin, rp_alias)],
            post_logout_redirect_uris=[
                callback_url(suite_origin, rp_alias, "post_logout_redirect")
            ],
            scopes=str(rp_client.get("scope", "")).split(),
        ),
    )

    back_name = "oidf-oidcc-backchannel-logout-plan-config.json"
    back = require_object(configs, back_name)
    back_alias = require_alias(back, back_name)
    back_client = require_client(back, "client", back_name)
    back_request = oauth_client_request(
        target_origin=target_origin,
        name="OIDF Back-Channel Logout Client",
        auth_method="client_secret_basic",
        redirect_uris=[callback_url(suite_origin, back_alias)],
        post_logout_redirect_uris=[
            callback_url(suite_origin, back_alias, "post_logout_redirect")
        ],
        scopes=str(back_client.get("scope", "")).split(),
    )
    back_request["backchannel_logout_uri"] = callback_url(
        suite_origin, back_alias, "backchannel_logout"
    )
    back_request["backchannel_logout_session_required"] = True
    add(str(back_client["client_id"]), back_request)

    front_name = "oidf-oidcc-frontchannel-logout-plan-config.json"
    front = require_object(configs, front_name)
    front_alias = require_alias(front, front_name)
    front_client = require_client(front, "client", front_name)
    front_request = oauth_client_request(
        target_origin=target_origin,
        name="OIDF Front-Channel Logout Client",
        auth_method="client_secret_basic",
        redirect_uris=[callback_url(suite_origin, front_alias)],
        post_logout_redirect_uris=[
            callback_url(suite_origin, front_alias, "post_logout_redirect")
        ],
        scopes=str(front_client.get("scope", "")).split(),
    )
    front_request["frontchannel_logout_uri"] = callback_url(
        suite_origin, front_alias, "frontchannel_logout"
    )
    front_request["frontchannel_logout_session_required"] = True
    add(str(front_client["client_id"]), front_request)

    session_name = "oidf-oidcc-session-management-plan-config.json"
    session = require_object(configs, session_name)
    session_alias = require_alias(session, session_name)
    session_client = require_client(session, "client", session_name)
    add(
        str(session_client["client_id"]),
        oauth_client_request(
            target_origin=target_origin,
            name="OIDF Session Management Client",
            auth_method="client_secret_basic",
            redirect_uris=[callback_url(suite_origin, session_alias)],
            post_logout_redirect_uris=[
                callback_url(suite_origin, session_alias, "post_logout_redirect")
            ],
            scopes=str(session_client.get("scope", "")).split(),
        ),
    )

    for file_name, raw_config in sorted(configs.items()):
        if not file_name.startswith("oidf-fapi-"):
            continue
        if not isinstance(raw_config, dict):
            fail(f"{file_name} must be an object")
        alias = require_alias(raw_config, file_name)
        nazo = raw_config.get("nazo")
        if not isinstance(nazo, dict):
            fail(f"{file_name}.nazo is required")
        ciba = file_name.startswith("oidf-fapi-ciba-")
        auth_type = str(nazo.get("client_auth_type", "private_key_jwt"))
        if auth_type not in {"private_key_jwt", "mtls"}:
            fail(f"{file_name} uses unsupported client authentication {auth_type}")
        sender_constraint = str(
            nazo.get("sender_constrain", "mtls" if ciba else "dpop")
        )
        fapi_profile = str(nazo.get("fapi_profile", "plain_fapi"))
        response_mode = str(nazo.get("fapi_response_mode", "plain_response"))
        auth_method = "tls_client_auth" if auth_type == "mtls" else "private_key_jwt"
        for field, mtls_field in (("client", "mtls"), ("client2", "mtls2")):
            metadata = require_client(raw_config, field, file_name)
            mtls = raw_config.get(mtls_field)
            if not isinstance(mtls, dict):
                fail(f"{file_name}.{mtls_field} is required")
            cert = mtls.get("cert")
            ca = mtls.get("ca")
            if not isinstance(cert, str) or not isinstance(ca, str):
                fail(f"{file_name}.{mtls_field} requires cert and ca")
            callback = callback_url(suite_origin, alias)
            request = oauth_client_request(
                target_origin=target_origin,
                name=f"OIDF FAPI Client {metadata['client_id']}",
                auth_method=auth_method,
                redirect_uris=[callback, f"{callback}?dummy1=lorem&dummy2=ipsum"],
                scopes=str(metadata.get("scope", "")).split(),
                grant_types=(
                    ["client_credentials"]
                    if fapi_profile == "fapi_client_credentials_grant"
                    else ["urn:openid:params:grant-type:ciba", "refresh_token"]
                    if ciba
                    else ["authorization_code", "refresh_token"]
                ),
            )
            request["jwks"] = public_jwks(
                metadata.get("jwks"), source=f"{file_name}.{field}.jwks"
            )
            request["require_dpop_bound_tokens"] = sender_constraint == "dpop"
            request["require_mtls_bound_tokens"] = sender_constraint == "mtls"
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
                metadata.get("backchannel_token_delivery_mode", "poll")
            )
            request["backchannel_client_notification_endpoint"] = metadata.get(
                "backchannel_client_notification_endpoint"
            )
            request["backchannel_authentication_request_signing_alg"] = metadata.get(
                "backchannel_authentication_request_signing_alg"
            )
            if auth_method == "tls_client_auth":
                request["tls_client_auth_subject_dn"] = certificate_subject_dn(cert)
                request["tls_client_auth_cert_sha256"] = certificate_sha256(cert)
            add(
                str(metadata["client_id"]),
                request,
                ca
                if auth_method == "tls_client_auth" or sender_constraint == "mtls"
                else None,
            )
    return [clients[key] for key in sorted(clients)]


def load_configs(directory: Path) -> dict[str, object]:
    configs: dict[str, object] = {}
    for path in sorted(directory.glob("*.json")):
        if path.name in {
            MANIFEST_FILE_NAME,
            OPENID4VC_AGGREGATE,
            "standards-full-profile.json",
        }:
            continue
        if not (path.name.startswith("oidf-") or path.name.startswith("openid4vc-")):
            fail(f"unexpected configuration in official artifact: {path.name}")
        configs[path.name] = read_json(path)
    if not configs:
        fail("official OIDF artifact contains no plan configurations")
    return configs


def verify_email_commitment(
    directory: Path, configs: dict[str, object], applicant_email: str
) -> None:
    expected = hashlib.sha256(applicant_email.encode("utf-8")).hexdigest()
    commitments = {
        nazo["oidf_user_email_sha256"]
        for config in configs.values()
        if isinstance(config, dict)
        and isinstance((nazo := config.get("nazo")), dict)
        and isinstance(nazo.get("oidf_user_email_sha256"), str)
    }
    aggregate = read_json(directory / OPENID4VC_AGGREGATE)
    if isinstance(aggregate, dict) and isinstance(
        aggregate.get("credential_holder_email_sha256"), str
    ):
        commitments.add(aggregate["credential_holder_email_sha256"])
    if commitments != {expected}:
        fail("applicant email does not match the official artifact commitment")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-directory", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--suite-base-url", required=True)
    parser.add_argument("--applicant-email", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    target = public_https_origin(args.target_issuer, label="--target-issuer")
    suite = public_https_origin(args.suite_base_url, label="--suite-base-url")
    if target == suite:
        fail("target issuer and conformance suite must use different origins")
    applicant_email = args.applicant_email.strip()
    if "@" not in applicant_email or any(ch.isspace() for ch in applicant_email):
        fail("--applicant-email must be a non-empty email address")
    validate_artifact_directory(
        args.artifact_directory,
        expected_source_commit=args.expected_source_commit,
        expected_target_issuer=target,
        expected_suite_base_url=suite,
        expected_onboarding_profile="official",
    )
    configs = load_configs(args.artifact_directory)
    verify_email_commitment(args.artifact_directory, configs, applicant_email)
    oidc_clients = prepare_oidc_clients(
        configs, target_origin=target, suite_origin=suite
    )
    openid4vc_clients = prepare_openid4vc_clients(
        configs, target_origin=target, suite_origin=suite
    )
    clients = oidc_clients + openid4vc_clients
    logical_ids = [str(item["logical_client_id"]) for item in clients]
    if len(logical_ids) != 55 or len(set(logical_ids)) != 55:
        fail(
            f"official full-matrix onboarding requires 55 unique clients, found {len(set(logical_ids))}"
        )
    if args.output_dir.exists():
        fail(f"output directory already exists: {args.output_dir}")
    args.output_dir.mkdir(parents=True, mode=0o700)
    write_private_json(
        args.output_dir / "oidf-onboarding-manifest.json",
        {
            "schema": 1,
            "source_commit": args.expected_source_commit,
            "target_issuer": target,
            "suite_base_url": suite,
            "applicant_email": applicant_email,
            "clients": clients,
        },
    )
    write_private_json(
        args.output_dir / "oidf-plan-configs.json", {"configs": configs}
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
