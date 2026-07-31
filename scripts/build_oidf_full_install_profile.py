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


def public_jwks(path: Path, label: str) -> dict[str, Any]:
    value = json_object(path, label)
    keys = value.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ProfileError(f"{label} must contain a non-empty keys array")
    for key in keys:
        if not isinstance(key, dict) or PRIVATE_JWK_MEMBERS.intersection(key):
            raise ProfileError(f"{label} must contain public asymmetric keys only")
    return value


def certificate_bundle(path: Path) -> str:
    try:
        value = read_bounded(path).decode("ascii")
    except UnicodeDecodeError as error:
        raise ProfileError("trust anchors must be ASCII PEM") from error
    if (
        "-----BEGIN CERTIFICATE-----" not in value
        or "-----END CERTIFICATE-----" not in value
        or "PRIVATE KEY" in value
    ):
        raise ProfileError("trust anchors must contain certificates and no private key")
    return value


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
    parser.add_argument("--client-attestation-issuer", required=True)
    parser.add_argument("--client-attestation-jwks", required=True, type=Path)
    parser.add_argument("--key-attestation-jwks", required=True, type=Path)
    parser.add_argument("--credential-configurations", required=True, type=Path)
    parser.add_argument("--trust-anchors", required=True, type=Path)
    parser.add_argument("--wallet-origin", required=True, action="append")
    parser.add_argument("--ciba-origin", required=True, action="append")
    parser.add_argument("--backchannel-logout-origin", required=True, action="append")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

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
        "trust_anchors_pem": certificate_bundle(args.trust_anchors),
    }
    write_atomic(args.output, document)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProfileError as error:
        raise SystemExit(f"profile material error: {error}") from error
