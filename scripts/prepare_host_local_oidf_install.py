#!/usr/bin/env python3
"""Prepare one source-bound host-local OIDF install profile and private run material."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_host_local_openid4vc_conformance as host_local  # noqa: E402
from run_public_oidf_conformance import verify_source  # noqa: E402


PROFILE_FILE = "standards-full-profile.json"
TRUST_FILE = "openid4vc-conformance-trust.json"
MATERIAL_FILE = "openid4vc-run-material.json"
MANIFEST_FILE = "host-local-oidf-install-manifest.json"


class PreparationError(RuntimeError):
    pass


def encoded(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_private(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    path.chmod(0o600)
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())
    return hashlib.sha256(payload).hexdigest()


def prepare(
    *,
    source_dir: Path,
    source_commit: str,
    suite_origin: str,
    output_dir: Path,
) -> Path:
    if not output_dir.is_absolute() or output_dir == Path(output_dir.anchor):
        raise PreparationError("--output-dir must be an absolute non-root path")
    if output_dir.exists() or output_dir.is_symlink():
        raise PreparationError("--output-dir must not already exist")
    source_dir = source_dir.resolve()
    verify_source(source_dir, source_commit, "host-local preparation")
    suite_origin = host_local.canonical_suite_origin(suite_origin)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent)
    )
    temporary.chmod(0o700)
    try:
        generation_dir = temporary / "generation"
        generation_dir.mkdir(mode=0o700)
        material = host_local.generate_certificate_material(
            generation_dir, suite_origin=suite_origin
        )
        host_local.validate_generated_material(material)
        profile = host_local.build_prepared_install_profile(material, suite_origin)
        trust = host_local.build_prepared_conformance_trust(material, suite_origin)

        profile_digest = write_private(temporary / PROFILE_FILE, encoded(profile))
        trust_digest = write_private(temporary / TRUST_FILE, encoded(trust))
        material_digest = write_private(temporary / MATERIAL_FILE, encoded(material))
        shutil.rmtree(generation_dir)
        manifest = {
            "schema": 1,
            "source_commit": source_commit,
            "suite_origin": suite_origin,
            "files": {
                PROFILE_FILE: profile_digest,
                TRUST_FILE: trust_digest,
                MATERIAL_FILE: material_digest,
            },
        }
        write_private(temporary / MANIFEST_FILE, encoded(manifest))
        if {path.name for path in temporary.iterdir()} != {
            PROFILE_FILE,
            TRUST_FILE,
            MATERIAL_FILE,
            MANIFEST_FILE,
        }:
            raise PreparationError("prepared directory contains an unexpected file")
        if os.name == "posix":
            descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.replace(temporary, output_dir)
        if os.name == "posix":
            descriptor = os.open(output_dir.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output_dir


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=ROOT)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--suite-origin", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        prepare(
            source_dir=args.source_dir,
            source_commit=args.source_commit,
            suite_origin=args.suite_origin,
            output_dir=args.output_dir,
        )
    except (PreparationError, host_local.HostLocalOpenid4vcError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
