#!/usr/bin/env python3
"""Export public-only OIDF plan configs for production control-plane onboarding."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from collections.abc import Sequence
from typing import Any

from oidf_onboarding_bundle import (
    BUNDLE_FILE_NAME,
    MANIFEST_FILE_NAME,
    build_artifact_manifest,
    build_ca_bundle,
)
from build_oidf_full_install_profile import (
    ProfileError,
    document_from_onboarding_artifact,
)


PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
OAUTH_ONBOARDING_NAZO_FIELDS = {
    "fapi_profile",
    "fapi_request_method",
    "fapi_response_mode",
    "client_auth_type",
    "sender_constrain",
}
OPENID4VC_ONBOARDING_NAZO_FIELDS = {
    "client_auth_type",
    "openid4vc_role",
    "credential_format",
    "credential_dataset",
}
ONBOARDING_NAZO_FIELDS = OAUTH_ONBOARDING_NAZO_FIELDS | OPENID4VC_ONBOARDING_NAZO_FIELDS
OPENID4VC_ONBOARDING_BUNDLE_FILE = "openid4vc-onboarding-configs.json"
STANDARDS_FULL_PROFILE_FILE = "standards-full-profile.json"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def public_jwk(value: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(child) for key, child in value.items() if key not in PRIVATE_JWK_FIELDS}


def strip_private_jwks(value: Any) -> Any:
    if isinstance(value, dict):
        if isinstance(value.get("keys"), list):
            stripped = copy.deepcopy(value)
            stripped["keys"] = [
                public_jwk(key) if isinstance(key, dict) else copy.deepcopy(key)
                for key in value["keys"]
            ]
            return stripped
        return {key: strip_private_jwks(child) for key, child in value.items()}
    if isinstance(value, list):
        return [strip_private_jwks(child) for child in value]
    return copy.deepcopy(value)


def public_onboarding_client(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key in (
        "client_id",
        "scope",
        "backchannel_token_delivery_mode",
        "backchannel_client_notification_endpoint",
        "backchannel_authentication_request_signing_alg",
        "backchannel_user_code_parameter",
        "request_object_trust_anchor_pem",
    ):
        if key in value:
            item = copy.deepcopy(value[key])
            if key == "request_object_trust_anchor_pem" and (
                not isinstance(item, str)
                or "-----BEGIN CERTIFICATE-----" not in item
                or "-----END CERTIFICATE-----" not in item
                or "PRIVATE KEY" in item
            ):
                raise SystemExit(
                    "request_object_trust_anchor_pem must contain certificates and no private key"
                )
            result[key] = item
    if "jwks" in value:
        result["jwks"] = strip_private_jwks(value["jwks"])
    if isinstance(value.get("client_secret"), str) and value["client_secret"]:
        result["client_secret_sha256"] = hashlib.sha256(
            value["client_secret"].encode("utf-8")
        ).hexdigest()
    return result or None


def public_client_attestation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    issuer = value.get("issuer")
    attester_jwks = value.get("attester_jwks")
    key_attestation_jwks = value.get("key_attestation_jwks")
    if not isinstance(issuer, str) or not issuer:
        return None
    if not isinstance(attester_jwks, dict) or not isinstance(
        key_attestation_jwks, dict
    ):
        raise SystemExit("client_attestation requires both public trust JWKS sets")
    return {
        "issuer": issuer,
        "attester_jwks": strip_private_jwks(attester_jwks),
        "key_attestation_jwks": strip_private_jwks(key_attestation_jwks),
    }


def public_onboarding_mtls(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or "ca" not in value or "cert" not in value:
        return None
    return {
        "ca": copy.deepcopy(value["ca"]),
        "cert": copy.deepcopy(value["cert"]),
    }


def public_onboarding_nazo(
    value: Any, credential_holder_email_sha256: str | None = None
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {key: copy.deepcopy(value[key]) for key in ONBOARDING_NAZO_FIELDS if key in value}
    if credential_holder_email_sha256 is not None:
        result["oidf_user_email_sha256"] = credential_holder_email_sha256
    elif isinstance(value.get("oidf_user_email"), str) and value["oidf_user_email"]:
        result["oidf_user_email_sha256"] = hashlib.sha256(
            value["oidf_user_email"].encode("utf-8")
        ).hexdigest()
    return result or None


def public_onboarding_config(
    config: Any, credential_holder_email_sha256: str | None = None
) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    result: dict[str, Any] = {}
    if "alias" in config:
        result["alias"] = copy.deepcopy(config["alias"])
    vci = config.get("vci")
    if isinstance(vci, dict) and isinstance(
        vci.get("credential_configuration_id"), str
    ):
        result["vci"] = {
            "credential_configuration_id": vci["credential_configuration_id"]
        }
    for key in ("client", "client2", "client_secret_post"):
        public_client = public_onboarding_client(config.get(key))
        if public_client is not None:
            result[key] = public_client
    client_attestation = public_client_attestation(config.get("client_attestation"))
    if client_attestation is not None:
        result["client_attestation"] = client_attestation
    for key in ("mtls", "mtls2"):
        public_mtls = public_onboarding_mtls(config.get(key))
        if public_mtls is not None:
            result[key] = public_mtls
    public_nazo = public_onboarding_nazo(
        config.get("nazo"), credential_holder_email_sha256
    )
    if public_nazo is not None:
        result["nazo"] = public_nazo
    return result


def main_with_args_for_test(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config-json-file", required=True, type=Path, action="append"
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--suite-base-url", required=True)
    parser.add_argument("--credential-holder-email-sha256")
    parser.add_argument(
        "--onboarding-profile",
        choices=("official", "operator-black-box"),
        required=True,
    )
    args = parser.parse_args(argv)
    credential_holder_email_sha256 = args.credential_holder_email_sha256
    if credential_holder_email_sha256 is not None and (
        len(credential_holder_email_sha256) != 64
        or any(character not in "0123456789abcdef" for character in credential_holder_email_sha256)
    ):
        raise SystemExit(
            "--credential-holder-email-sha256 must be a lowercase SHA-256 digest"
        )

    configs: dict[str, Any] = {}
    for config_path in args.config_json_file:
        rendered = read_json(config_path)
        source_configs = rendered.get("configs") if isinstance(rendered, dict) else None
        if not isinstance(source_configs, dict):
            raise SystemExit(f"{config_path} must contain a configs object")
        for file_name, config in source_configs.items():
            if file_name in configs:
                raise SystemExit(f"duplicate OIDF config file name: {file_name}")
            configs[file_name] = config

    try:
        ca_bundle, _ = build_ca_bundle(configs)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    outputs: dict[str, bytes] = {}
    openid4vc_configs: dict[str, Any] = {}
    user_email_commitments: set[str] = set()
    for file_name, config in configs.items():
        if Path(file_name).name != file_name or not file_name.endswith(".json"):
            raise SystemExit(f"invalid OIDF config file name: {file_name}")
        public_config = public_onboarding_config(
            config, credential_holder_email_sha256
        )
        public_nazo = public_config.get("nazo")
        if isinstance(public_nazo, dict) and isinstance(
            public_nazo.get("oidf_user_email_sha256"), str
        ):
            user_email_commitments.add(public_nazo["oidf_user_email_sha256"])
        if file_name.startswith("openid4vc-"):
            openid4vc_configs[file_name] = public_config
        outputs[file_name] = (
            json.dumps(public_config, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    if openid4vc_configs:
        if len(user_email_commitments) != 1:
            raise SystemExit(
                "combined OpenID4VC onboarding artifact requires exactly one credential-holder email commitment"
            )
        openid4vc_bundle = {
            "configs": openid4vc_configs,
            "credential_holder_email_sha256": next(iter(user_email_commitments)),
        }
        outputs[OPENID4VC_ONBOARDING_BUNDLE_FILE] = (
            json.dumps(openid4vc_bundle, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if args.onboarding_profile == "official":
            try:
                standards_full_profile = document_from_onboarding_artifact(
                    openid4vc_bundle, args.suite_base_url
                )
            except ProfileError as error:
                raise SystemExit(
                    f"cannot derive closed standards-full install profile: {error}"
                ) from error
            outputs[STANDARDS_FULL_PROFILE_FILE] = (
                json.dumps(standards_full_profile, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
    outputs[BUNDLE_FILE_NAME] = ca_bundle
    outputs[MANIFEST_FILE_NAME] = build_artifact_manifest(
        outputs,
        args.source_commit,
        args.target_issuer,
        args.suite_base_url,
        args.onboarding_profile,
    )

    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            dir=args.output_dir.parent,
            prefix=f".{args.output_dir.name}.",
        )
    )
    try:
        for file_name, content in outputs.items():
            staging.joinpath(file_name).write_bytes(content)
        staging.replace(args.output_dir)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return 0


def main() -> int:
    return main_with_args_for_test()


if __name__ == "__main__":
    raise SystemExit(main())
