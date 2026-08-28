#!/usr/bin/env python3
"""Ensure a Nazo OAuth runtime keyset has the signing algorithms a test needs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUPPORTED_LOCAL_RSA_ALGS = {"RS256", "PS256"}
KEYSET_SCHEMA_VERSION = "nazo.keyset.v1"
REQUEST_OBJECT_ENCRYPTION_KEY_FILE = "request-object-encryption.pem"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-dir", required=True, type=Path)
    parser.add_argument(
        "--active-alg",
        choices=sorted(SUPPORTED_LOCAL_RSA_ALGS),
        default="RS256",
    )
    parser.add_argument(
        "--required-alg",
        action="append",
        choices=sorted(SUPPORTED_LOCAL_RSA_ALGS),
        default=[],
    )
    return parser.parse_args()


def load_keyset(keyset_path: Path) -> dict[str, Any]:
    if not keyset_path.is_file():
        return {
            "schema_version": KEYSET_SCHEMA_VERSION,
            "active_kid": "",
            "keys": [],
        }
    loaded = json.loads(keyset_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuntimeError(f"keyset must be a JSON object: {keyset_path}")
    if loaded.get("schema_version") != KEYSET_SCHEMA_VERSION:
        raise RuntimeError(
            f"keyset schema must be {KEYSET_SCHEMA_VERSION}: {keyset_path}"
        )
    if not isinstance(loaded.get("active_kid"), str):
        raise RuntimeError(f"keyset active_kid must be a string: {keyset_path}")
    keys = loaded.get("keys")
    if not isinstance(keys, list):
        raise RuntimeError(f"keyset keys must be an array: {keyset_path}")
    return loaded


def is_server_rsa_pem(path: Path) -> bool:
    if not path.is_file():
        return False
    first_line = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return bool(first_line and first_line[0].strip() == "-----BEGIN RSA PRIVATE KEY-----")
def live_local_key(keys: list[Any], key_dir: Path, alg: str) -> dict[str, Any] | None:
    for entry in keys:
        if (
            isinstance(entry, dict)
            and entry.get("alg") == alg
            and entry.get("backend") == "local-pem"
            and entry.get("retire_at") is None
            and isinstance(entry.get("file"), str)
            and is_server_rsa_pem(key_dir / entry["file"])
        ):
            return entry
    return None


def create_local_rsa_key(
    keys: list[Any],
    key_dir: Path,
    alg: str,
    now: str,
) -> dict[str, Any]:
    kid = f"{alg.lower()}-runtime-{uuid.uuid4().hex}"
    file_name = f"{kid}.pem"
    target = key_dir / file_name
    subprocess.run(
        ["openssl", "genrsa", "-traditional", "-out", str(target), "2048"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    target.chmod(0o600)
    entry = {
        "kid": kid,
        "alg": alg,
        "backend": "local-pem",
        "file": file_name,
        "created_at": now,
        "retire_at": None,
    }
    keys.append(entry)
    return entry


def ensure_request_object_encryption_key(key_dir: Path) -> None:
    target = key_dir / REQUEST_OBJECT_ENCRYPTION_KEY_FILE
    if target.is_file():
        return
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            str(target),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    target.chmod(0o600)


def ensure_keyset(key_dir: Path, active_alg: str, required_algs: list[str]) -> None:
    key_dir.mkdir(parents=True, exist_ok=True)
    keyset_path = key_dir / "keyset.json"
    keyset = load_keyset(keyset_path)
    keys = keyset["keys"]

    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    required = list(dict.fromkeys([active_alg, *required_algs]))
    live_by_alg: dict[str, dict[str, Any]] = {}
    for alg in required:
        existing = live_local_key(keys, key_dir, alg)
        live_by_alg[alg] = existing or create_local_rsa_key(keys, key_dir, alg, now)

    active = live_by_alg[active_alg]
    keyset["active_kid"] = active["kid"]
    ensure_request_object_encryption_key(key_dir)
    keyset_path.write_text(json.dumps(keyset, indent=2) + "\n", encoding="utf-8")
    os.chmod(keyset_path, 0o600)


def main() -> None:
    args = parse_args()
    ensure_keyset(args.key_dir, args.active_alg, args.required_alg)


if __name__ == "__main__":
    main()
