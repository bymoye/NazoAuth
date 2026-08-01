#!/usr/bin/env python3
"""Build the public, non-secret material consumed by nazoauthctl's OIDF profile."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any


class ProfileError(RuntimeError):
    pass


PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def read_bounded(path: Path, limit: int = 256 * 1024) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ProfileError(f"input must be an absolute regular file: {path}")
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise ProfileError(f"input must contain 1 through {limit} bytes: {path}")
    return data


def json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_bounded(path))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfileError(f"{label} must be strict JSON: {error}") from error
    if not isinstance(value, dict) or not value:
        raise ProfileError(f"{label} must be a non-empty object")
    return value


def validate_public_jwks(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be a non-empty object")
    keys = value.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ProfileError(f"{label} must contain a non-empty keys array")
    for key in keys:
        if not isinstance(key, dict) or PRIVATE_JWK_MEMBERS.intersection(key):
            raise ProfileError(f"{label} must contain public asymmetric keys only")
    return value


def public_jwks(path: Path, label: str) -> dict[str, Any]:
    return validate_public_jwks(json_object(path, label), label)


def origin(value: str, label: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ProfileError(f"{label} must be an HTTPS origin without credentials or a path")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def one_canonical(values: list[Any], label: str) -> Any:
    unique = {
        json.dumps(value, sort_keys=True, separators=(",", ":")): value
        for value in values
    }
    if len(unique) != 1:
        raise ProfileError(f"onboarding artifact must contain exactly one {label}")
    return next(iter(unique.values()))


def credential_configuration(identifier: str, format_name: str) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "format": format_name,
        "scope": identifier,
        "cryptographic_binding_methods_supported": ["jwk"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]},
            "attestation": {
                "proof_signing_alg_values_supported": ["ES256", "EdDSA"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_moderate"],
                    "user_authentication": ["iso_18045_moderate"],
                },
            },
        },
    }
    if format_name == "dc+sd-jwt":
        configuration["vct"] = identifier
    elif format_name == "mso_mdoc":
        configuration["doctype"] = identifier
    else:
        raise ProfileError(f"unsupported credential format {format_name}")
    return configuration


def document_from_onboarding_artifact(
    artifact: Any, suite_origin: str
) -> dict[str, Any]:
    if not isinstance(artifact, dict) or not artifact:
        raise ProfileError("OpenID4VC onboarding artifact must be a non-empty object")
    configs = artifact.get("configs")
    if not isinstance(configs, dict) or not configs:
        raise ProfileError("OpenID4VC onboarding artifact must contain configs")
    attestation = [
        value["client_attestation"]
        for value in configs.values()
        if isinstance(value, dict) and isinstance(value.get("client_attestation"), dict)
    ]
    trust = one_canonical(attestation, "client attestation trust object")
    if set(trust) != {"issuer", "attester_jwks", "key_attestation_jwks"}:
        raise ProfileError("client attestation trust object has unknown or missing fields")
    issuer = origin(trust["issuer"], "client attestation issuer")
    identifiers: dict[str, set[str]] = {"dc+sd-jwt": set(), "mso_mdoc": set()}
    for filename, value in configs.items():
        if not isinstance(filename, str) or not isinstance(value, dict):
            raise ProfileError("OpenID4VC onboarding configs must be named objects")
        vci = value.get("vci")
        identifier = vci.get("credential_configuration_id") if isinstance(vci, dict) else None
        if isinstance(identifier, str) and identifier:
            nazo = value.get("nazo")
            source_format = nazo.get("credential_format") if isinstance(nazo, dict) else None
            format_name = {
                "sd_jwt_vc": "dc+sd-jwt",
                "mdoc": "mso_mdoc",
            }.get(source_format)
            if format_name is None:
                raise ProfileError(
                    f"{filename} must explicitly declare a supported nazo.credential_format"
                )
            identifiers[format_name].add(identifier)
    credential_configurations: dict[str, Any] = {}
    for format_name, candidates in identifiers.items():
        if len(candidates) != 1:
            raise ProfileError(
                f"onboarding artifact must contain exactly one {format_name} identifier"
            )
        identifier = next(iter(candidates))
        credential_configurations[identifier] = credential_configuration(
            identifier, format_name
        )
    suite = origin(suite_origin, "suite origin")
    return {
        "client_attestation_issuer": f"{issuer}/",
        "client_attestation_jwks": validate_public_jwks(
            trust["attester_jwks"], "client attestation JWKS"
        ),
        "key_attestation_jwks": validate_public_jwks(
            trust["key_attestation_jwks"], "key attestation JWKS"
        ),
        "credential_configurations": credential_configurations,
        "wallet_authorization_origins": [suite],
        "ciba_notification_private_origins": [suite],
        "backchannel_logout_private_origins": [suite],
    }


def document_from_onboarding(path: Path, suite_origin: str) -> dict[str, Any]:
    return document_from_onboarding_artifact(
        json_object(path, "OpenID4VC onboarding artifact"), suite_origin
    )


def write_atomic(path: Path, document: dict[str, Any]) -> None:
    if not path.is_absolute() or path == Path(path.anchor):
        raise ProfileError("--output must be an absolute non-root path")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--onboarding-configs", type=Path)
    parser.add_argument("--suite-origin")
    parser.add_argument("--client-attestation-issuer")
    parser.add_argument("--client-attestation-jwks", type=Path)
    parser.add_argument("--key-attestation-jwks", type=Path)
    parser.add_argument("--credential-configurations", type=Path)
    parser.add_argument("--wallet-origin", action="append")
    parser.add_argument("--ciba-origin", action="append")
    parser.add_argument("--backchannel-logout-origin", action="append")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    explicit = [
        args.client_attestation_issuer,
        args.client_attestation_jwks,
        args.key_attestation_jwks,
        args.credential_configurations,
        args.wallet_origin,
        args.ciba_origin,
        args.backchannel_logout_origin,
    ]
    if args.onboarding_configs is not None:
        if args.suite_origin is None or any(value is not None for value in explicit):
            raise ProfileError(
                "--onboarding-configs requires only --suite-origin and may not mix explicit inputs"
            )
        document = document_from_onboarding(args.onboarding_configs, args.suite_origin)
    else:
        if args.suite_origin is not None or any(value is None for value in explicit):
            raise ProfileError(
                "explicit mode requires issuer, both JWKS, credential configurations and all three origin inputs"
            )
        issuer = origin(args.client_attestation_issuer, "client attestation issuer")
        document = {
            "client_attestation_issuer": f"{issuer}/",
            "client_attestation_jwks": public_jwks(
                args.client_attestation_jwks, "client attestation JWKS"
            ),
            "key_attestation_jwks": public_jwks(
                args.key_attestation_jwks, "key attestation JWKS"
            ),
            "credential_configurations": json_object(
                args.credential_configurations, "credential configurations"
            ),
            "wallet_authorization_origins": [
                origin(value, "wallet authorization origin") for value in args.wallet_origin
            ],
            "ciba_notification_private_origins": [
                origin(value, "CIBA notification origin") for value in args.ciba_origin
            ],
            "backchannel_logout_private_origins": [
                origin(value, "back-channel logout origin")
                for value in args.backchannel_logout_origin
            ],
        }
    write_atomic(args.output, document)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProfileError as error:
        raise SystemExit(f"profile material error: {error}") from error
