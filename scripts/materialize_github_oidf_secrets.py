#!/usr/bin/env python3
"""Materialize one GitHub Actions OIDF secret environment into private files.

This process is intentionally the only workflow process that receives the
GitHub secret environment.  Downstream tools receive file paths or inherited
descriptors only.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path


SECRET_FILES = {
    "OIDF_PLAN_CONFIG_AGE_IDENTITY": "plan-config.agekey",
    "OIDF_MTLS_MATERIAL_AGE_IDENTITY": "mtls-material.agekey",
    "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN": "dynamic-registration-token",
    "OIDF_CIBA_AUTOMATED_DECISION_TOKEN": "ciba-decision-token",
    "OIDF_CONFORMANCE_TOKEN": "suite-token",
}


def private_write(path: Path, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def materialize(output_dir: Path, *, mode: str = "full") -> None:
    if output_dir.exists():
        raise RuntimeError("OIDF secret output directory must not already exist")
    required_names = (
        (
            *SECRET_FILES,
            "OIDF_DELIVERED_CLIENT_MATERIAL_JSON",
            "OIDF_USER_EMAIL",
            "OIDF_USER_PASSWORD",
        )
        if mode == "full"
        else (
            "OIDF_PLAN_CONFIG_AGE_IDENTITY",
            "OIDF_CIBA_AUTOMATED_DECISION_TOKEN",
            "OIDF_CONFORMANCE_TOKEN",
        )
        if mode == "minimal"
        else (
            "OIDF_CONFORMANCE_TOKEN",
            "OPENID4VC_OIDF_BASE_CONFIG_JSON",
            "OPENID4VC_OIDF_MTLS_CONFIG_JSON",
            "OPENID4VC_OIDF_DRIVER_CONFIG_JSON",
            "OIDF_DELIVERED_CLIENT_MATERIAL_JSON",
            "OIDF_USER_EMAIL",
            "OIDF_USER_PASSWORD",
            "OIDF_ADMIN_EMAIL",
            "OIDF_ADMIN_PASSWORD",
        )
    )
    values = {
        name: os.environ.get(name, "")
        for name in required_names
    }
    if any(not value for value in values.values()):
        raise RuntimeError("one or more required OIDF workflow secrets are empty")
    try:
        delivered = (
            json.loads(values["OIDF_DELIVERED_CLIENT_MATERIAL_JSON"])
            if mode in {"full", "openid4vc"}
            else None
        )
    except json.JSONDecodeError as error:
        raise RuntimeError("delivered client material secret is not valid JSON") from error
    output_dir.mkdir(parents=True, mode=0o700)
    output_dir.chmod(0o700)
    try:
        for environment_name, filename in SECRET_FILES.items():
            if environment_name not in values:
                continue
            value = values[environment_name]
            if environment_name.endswith("AGE_IDENTITY"):
                value = value.rstrip("\r\n") + "\n"
            private_write(output_dir / filename, value.encode("utf-8"))
        if mode == "full":
            private_write(
                output_dir / "delivered-client-material.json",
                (json.dumps(delivered, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            browser = {
                "applicant_email": values["OIDF_USER_EMAIL"],
                "applicant_password": values["OIDF_USER_PASSWORD"],
            }
            private_write(
                output_dir / "browser-credentials.json",
                json.dumps(browser, separators=(",", ":")).encode("utf-8"),
            )
        elif mode == "openid4vc":
            for environment_name, filename in (
                ("OPENID4VC_OIDF_BASE_CONFIG_JSON", "base.json"),
                ("OPENID4VC_OIDF_MTLS_CONFIG_JSON", "mtls.json"),
                ("OPENID4VC_OIDF_DRIVER_CONFIG_JSON", "driver-input.json"),
            ):
                parsed = json.loads(values[environment_name])
                private_write(
                    output_dir / filename,
                    (json.dumps(parsed, separators=(",", ":")) + "\n").encode("utf-8"),
                )
            private_write(
                output_dir / "delivered-client-material.json",
                (json.dumps(delivered, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            private_write(
                output_dir / "browser-credentials.json",
                json.dumps(
                    {
                        "applicant_email": values["OIDF_USER_EMAIL"],
                        "applicant_password": values["OIDF_USER_PASSWORD"],
                    },
                    separators=(",", ":"),
                ).encode("utf-8"),
            )
            private_write(
                output_dir / "operator-credentials.json",
                json.dumps(
                    {
                        "admin_email": values["OIDF_ADMIN_EMAIL"],
                        "admin_password": values["OIDF_ADMIN_PASSWORD"],
                    },
                    separators=(",", ":"),
                ).encode("utf-8"),
            )
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--minimal", action="store_true")
    mode.add_argument("--openid4vc", action="store_true")
    args = parser.parse_args()
    selected = "openid4vc" if args.openid4vc else "minimal" if args.minimal else "full"
    materialize(args.output_dir.resolve(), mode=selected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
