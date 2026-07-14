#!/usr/bin/env python3
"""Export public-only OIDF plan configs for server-side client seeding."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import tempfile
from pathlib import Path
from collections.abc import Sequence
from typing import Any

from oidf_mtls_ca_bundle import (
    BUNDLE_FILE_NAME,
    MANIFEST_FILE_NAME,
    build_artifact_manifest,
    build_ca_bundle,
)


PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
SEED_NAZO_FIELDS = {
    "fapi_profile",
    "fapi_request_method",
    "fapi_response_mode",
    "client_auth_type",
    "sender_constrain",
}


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


def public_seed_client(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key in ("client_id", "scope"):
        if key in value:
            result[key] = copy.deepcopy(value[key])
    if "jwks" in value:
        result["jwks"] = strip_private_jwks(value["jwks"])
    return result or None


def public_seed_mtls(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or "ca" not in value or "cert" not in value:
        return None
    return {
        "ca": copy.deepcopy(value["ca"]),
        "cert": copy.deepcopy(value["cert"]),
    }


def public_seed_nazo(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {key: copy.deepcopy(value[key]) for key in SEED_NAZO_FIELDS if key in value}
    return result or None


def public_seed_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    result: dict[str, Any] = {}
    if "alias" in config:
        result["alias"] = copy.deepcopy(config["alias"])
    for key in ("client", "client2"):
        public_client = public_seed_client(config.get(key))
        if public_client is not None:
            result[key] = public_client
    for key in ("mtls", "mtls2"):
        public_mtls = public_seed_mtls(config.get(key))
        if public_mtls is not None:
            result[key] = public_mtls
    public_nazo = public_seed_nazo(config.get("nazo"))
    if public_nazo is not None:
        result["nazo"] = public_nazo
    return result


def main_with_args_for_test(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-json-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)

    rendered = read_json(args.config_json_file)
    configs = rendered.get("configs") if isinstance(rendered, dict) else None
    if not isinstance(configs, dict):
        raise SystemExit("rendered OIDF config must contain a configs object")

    try:
        ca_bundle, _ = build_ca_bundle(configs)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    outputs: dict[str, bytes] = {}
    for file_name, config in configs.items():
        if Path(file_name).name != file_name or not file_name.endswith(".json"):
            raise SystemExit(f"invalid OIDF config file name: {file_name}")
        public_config = public_seed_config(config)
        outputs[file_name] = (
            json.dumps(public_config, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    outputs[BUNDLE_FILE_NAME] = ca_bundle
    outputs[MANIFEST_FILE_NAME] = build_artifact_manifest(outputs, args.source_commit)

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
