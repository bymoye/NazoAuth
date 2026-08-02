#!/usr/bin/env python3
"""Bootstrap a fresh Compose admin and materialize private OIDF runner inputs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class BootstrapError(RuntimeError):
    pass


def origin(value: str) -> str:
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
        raise BootstrapError("--target-origin must be an HTTPS origin")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def container_secret(container: str, path: str) -> str:
    completed = subprocess.run(
        ["docker", "exec", container, "sh", "-euc", f"cat {path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BootstrapError(f"container secret is unavailable: {path}")
    value = completed.stdout.strip()
    if len(value) < 32 or any(character.isspace() for character in value):
        raise BootstrapError(f"container secret has an invalid shape: {path}")
    return value


def post_bootstrap(target: str, document: dict[str, str]) -> dict[str, object]:
    request = urllib.request.Request(
        f"{target}/auth/bootstrap-admin",
        data=json.dumps(document, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 201:
                raise BootstrapError(f"bootstrap endpoint returned HTTP {response.status}")
            if not response.headers.get_content_type() == "application/json":
                raise BootstrapError("bootstrap endpoint returned a non-JSON response")
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            error.read(1024 * 1024 + 1)
        raise BootstrapError(f"bootstrap endpoint returned HTTP {error.code}") from error
    if not isinstance(payload, dict) or payload.get("request_id") != document["request_id"]:
        raise BootstrapError("bootstrap endpoint returned an invalid receipt")
    if payload.get("email") != document["email"] or payload.get("role") != "admin":
        raise BootstrapError("bootstrap receipt does not match the requested administrator")
    return payload


def protected_file(path: Path) -> str:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BootstrapError(f"secret input must be a regular non-symlink file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BootstrapError(f"secret input must have mode 0600: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(character.isspace() for character in value):
        raise BootstrapError(f"secret input has an invalid shape: {path}")
    return value


def write_json(path: Path, document: dict[str, str]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def remove_consumed_token(container: str) -> None:
    completed = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-euc",
            "rm -f /var/lib/nazo_oauth/bootstrap/initial-admin-token; "
            "test ! -e /var/lib/nazo_oauth/bootstrap/initial-admin-token",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BootstrapError("consumed bootstrap token cleanup failed")


def run(args: argparse.Namespace) -> None:
    target = origin(args.target_origin)
    output = args.output_dir.resolve()
    if output.exists():
        raise BootstrapError("--output-dir must not already exist")

    admin_email = f"oidf-admin-{secrets.token_hex(8)}@example.invalid"
    applicant_email = f"oidf-applicant-{secrets.token_hex(8)}@example.invalid"
    admin_password = secrets.token_urlsafe(36)
    applicant_password = secrets.token_urlsafe(36)
    bootstrap_token = container_secret(
        args.server_container,
        "/var/lib/nazo_oauth/bootstrap/initial-admin-token",
    )
    dynamic_token = container_secret(
        args.server_container, "/run/nazoauth-secrets/dynamic-registration-token"
    )
    ciba_token = container_secret(
        args.server_container, "/run/nazoauth-secrets/ciba-decision-token"
    )
    issuer_token = container_secret(
        args.server_container, "/run/nazoauth-secrets/openid4vci-management-token"
    )
    verifier_token = container_secret(
        args.server_container, "/run/nazoauth-secrets/openid4vp-management-token"
    )
    suite_token = protected_file(args.suite_token_file.resolve())
    request_id = f"bootstrap-admin-{secrets.token_hex(16)}"
    post_bootstrap(
        target,
        {
            "request_id": request_id,
            "token": bootstrap_token,
            "email": admin_email,
            "password": admin_password,
        },
    )
    remove_consumed_token(args.server_container)

    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)

    write_json(
        output / "oidc-secrets.json",
        {
            "oidf_admin_email": admin_email,
            "oidf_admin_password": admin_password,
            "oidf_applicant_email": applicant_email,
            "oidf_applicant_password": applicant_password,
            "oidf_dynamic_registration_initial_access_token": dynamic_token,
            "oidf_ciba_automated_decision_token": ciba_token,
            "oidf_conformance_token": suite_token,
        },
    )
    write_json(
        output / "openid4vc-secrets.json",
        {
            "admin_email": admin_email,
            "admin_password": admin_password,
            "applicant_email": applicant_email,
            "applicant_password": applicant_password,
            "issuer_management_token": issuer_token,
            "suite_token": suite_token,
            "verifier_management_token": verifier_token,
        },
    )
    write_json(
        output / "operator-credentials.json",
        {
            "admin_email": admin_email,
            "admin_password": admin_password,
            "applicant_email": applicant_email,
            "applicant_password": applicant_password,
        },
    )
    print(f"Compose conformance credentials created under {output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-origin", required=True)
    parser.add_argument("--server-container", required=True)
    parser.add_argument("--suite-token-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    run(parser.parse_args())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapError as error:
        raise SystemExit(f"compose conformance bootstrap error: {error}") from error
