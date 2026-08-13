#!/usr/bin/env python3
"""Apply private applicant credentials to a materialized OIDF config bundle."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from oidf_secret_input import read_private_text, read_secret_document


FIELDS = ("applicant_email", "applicant_password")


def apply_credentials(config_path: Path, credentials: dict[str, str]) -> None:
    if set(credentials) != set(FIELDS) or any(not credentials[field] for field in FIELDS):
        raise RuntimeError("browser credentials must contain exactly non-empty applicant_email and applicant_password")
    try:
        document = json.loads(read_private_text(config_path))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("OIDF config bundle is not readable strict JSON") from error
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict) or not configs:
        raise RuntimeError("OIDF config bundle must contain a non-empty configs object")
    for name, config in configs.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            raise RuntimeError("OIDF config bundle contains an invalid configuration")
        nazo = config.setdefault("nazo", {})
        if not isinstance(nazo, dict):
            raise RuntimeError("OIDF configuration nazo field must be an object")
        nazo["oidf_user_email"] = credentials["applicant_email"]
        nazo["oidf_user_password"] = credentials["applicant_password"]
    descriptor, name = tempfile.mkstemp(dir=config_path.parent, prefix=f".{config_path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, separators=(",", ":"), sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, config_path)
    finally:
        temporary.unlink(missing_ok=True)


def apply(config_path: Path, credentials_path: Path) -> None:
    credentials = read_secret_document(
        argparse.Namespace(
            secrets_stdin=False,
            secret_fd=None,
            secret_file=credentials_path,
        ),
        required_fields=FIELDS,
    )
    apply_credentials(config_path, credentials)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-json-file", type=Path, required=True)
    parser.add_argument(
        "--credentials-file",
        type=Path,
        required=True,
        help="POSIX non-symlink mode-0600 applicant credential document",
    )
    args = parser.parse_args()
    apply(args.config_json_file.resolve(), args.credentials_file.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
