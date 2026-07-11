#!/usr/bin/env python3
"""Materialize OIDF plan config templates with secret patches."""

from __future__ import annotations

import argparse
import base64
import copy
import gzip
import json
import os
from pathlib import Path
from typing import Any

OIDCC_BASIC_CONFIG_FILE = "oidf-oidcc-basic-plan-config.json"
OIDCC_DYNAMIC_CONFIG_FILE = "oidf-oidcc-dynamic-plan-config.json"
OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE = "oidf-oidcc-dynamic-crypto-plan-config.json"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def secret_patch_from_env(prefix: str) -> dict[str, Any]:
    parts: list[str] = []
    for index in range(1, 21):
        value = os.environ.get(f"{prefix}_{index:02d}", "").strip()
        if value:
            parts.append(value)
    if not parts:
        raise SystemExit(f"{prefix}_01 secret patch chunk is required")
    payload = gzip.decompress(base64.b64decode("".join(parts)))
    patch = json.loads(payload.decode("utf-8"))
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch must be a JSON object")
    return patch


def secret_patch_from_file(path: Path) -> dict[str, Any]:
    patch = read_json(path)
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch file must contain a JSON object")
    return patch


def materialize(value: Any, patch: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        secret = value.get("$secret")
        if isinstance(secret, str):
            if set(value) != {"$secret"}:
                raise SystemExit(f"secret placeholder has unexpected keys: {secret}")
            if secret not in patch:
                raise SystemExit(f"missing secret patch value for {secret}")
            return patch[secret]
        return {key: materialize(child, patch) for key, child in value.items()}
    if isinstance(value, list):
        return [materialize(child, patch) for child in value]
    return value


def derive_dynamic_oidcc_config(rendered: dict[str, Any], initial_access_token: str) -> None:
    configs = rendered.get("configs")
    if not isinstance(configs, dict):
        raise SystemExit("OIDF config root must contain a configs object")

    basic = configs.get(OIDCC_BASIC_CONFIG_FILE)
    if not isinstance(basic, dict):
        raise SystemExit(f"missing {OIDCC_BASIC_CONFIG_FILE} config to derive dynamic OIDC config")
    if OIDCC_DYNAMIC_CONFIG_FILE in configs:
        raise SystemExit(f"{OIDCC_DYNAMIC_CONFIG_FILE} already exists in rendered configs")
    if OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE in configs:
        raise SystemExit(f"{OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE} already exists in rendered configs")

    dynamic = copy.deepcopy(basic)
    dynamic["alias"] = f"{basic.get('alias', 'nazo-oauth-oidf-basic')}-dynamic"
    dynamic["description"] = "OIDC Basic OP: RFC 7591 dynamic client registration."

    for client_key in ("client", "client2", "client_secret_post"):
        source = basic.get(client_key)
        if not isinstance(source, dict):
            raise SystemExit(f"missing {client_key} object in {OIDCC_BASIC_CONFIG_FILE}")
        scope = source.get("scope")
        dynamic[client_key] = {"initial_access_token": initial_access_token}
        if isinstance(scope, str):
            dynamic[client_key]["scope"] = scope

    configs[OIDCC_DYNAMIC_CONFIG_FILE] = dynamic
    dynamic_crypto = copy.deepcopy(dynamic)
    dynamic_crypto["alias"] = f"{basic.get('alias', 'nazo-oauth-oidf-basic')}-dynamic-crypto"
    dynamic_crypto["description"] = (
        "OIDC dynamic-registration signed UserInfo interoperability coverage."
    )
    configs[OIDCC_DYNAMIC_CRYPTO_CONFIG_FILE] = dynamic_crypto


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--secret-patch-file",
        type=Path,
        default=None,
        help="read the secret patch JSON object from this file",
    )
    parser.add_argument(
        "--secret-prefix",
        default="OIDF_PLAN_CONFIG_SECRET_PATCH_GZ_B64",
        help="environment variable prefix for gzip+base64 secret patch chunks",
    )
    parser.add_argument(
        "--derive-dynamic-oidcc-config",
        action="store_true",
        help="derive RFC 7591 dynamic OIDC Basic config from the static OIDC Basic config",
    )
    parser.add_argument(
        "--dynamic-registration-token-env",
        default="OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
        help="environment variable containing the RFC 7591 initial access token",
    )
    args = parser.parse_args()

    template = read_json(args.template)
    patch = (
        secret_patch_from_file(args.secret_patch_file)
        if args.secret_patch_file is not None
        else secret_patch_from_env(args.secret_prefix)
    )
    rendered = materialize(template, patch)
    if args.derive_dynamic_oidcc_config:
        initial_access_token = os.environ.get(args.dynamic_registration_token_env, "")
        if not initial_access_token:
            raise SystemExit(f"{args.dynamic_registration_token_env} is required")
        if not isinstance(rendered, dict):
            raise SystemExit("OIDF rendered config must be a JSON object")
        derive_dynamic_oidcc_config(rendered, initial_access_token)
    args.output.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
