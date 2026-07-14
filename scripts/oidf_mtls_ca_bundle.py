#!/usr/bin/env python3
"""Build and verify the public CA bundle used by OIDF mTLS clients."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


BUNDLE_FILE_NAME = "oidf-mtls-ca-bundle.pem"
MANIFEST_FILE_NAME = "oidf-public-plan-configs.manifest.json"
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CERTIFICATE_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+"
    r"[A-Za-z0-9+/=\r\n]+?"
    r"-----END CERTIFICATE-----",
    re.MULTILINE,
)


class BundleError(ValueError):
    """The public mTLS CA material is missing or invalid."""


def _certificate_der_blocks(pem: str, label: str) -> list[bytes]:
    if not pem.strip():
        raise BundleError(f"{label} is empty")
    if "PRIVATE KEY" in pem.upper():
        raise BundleError(f"{label} must not contain private key material")
    blocks = _CERTIFICATE_BLOCK.findall(pem)
    if not blocks or _CERTIFICATE_BLOCK.sub("", pem).strip():
        raise BundleError(f"{label} must contain only PEM certificates")
    result: list[bytes] = []
    for block in blocks:
        try:
            result.append(ssl.PEM_cert_to_DER_cert(block))
        except ValueError as error:
            raise BundleError(f"{label} contains a malformed certificate") from error
    return result


def _require_ca_certificate(der: bytes, label: str) -> None:
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-ext", "basicConstraints"],
            input=der,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise BundleError("openssl is required to validate the OIDF mTLS CA bundle") from error
    if result.returncode != 0:
        raise BundleError(f"{label} is not a valid X.509 certificate")
    constraints = re.sub(rb"\s+", b"", result.stdout).upper()
    if b"CA:TRUE" not in constraints:
        raise BundleError(f"{label} is not a CA certificate")
    key_usage = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-ext", "keyUsage"],
        input=der,
        capture_output=True,
        check=False,
    )
    normalized_key_usage = re.sub(rb"\s+", b"", key_usage.stdout).upper()
    if key_usage.returncode != 0:
        raise BundleError(f"{label} key usage could not be inspected")
    # RFC 5280 section 4.2.1.3 restricts certificate signing when KeyUsage is
    # present.  Some OIDF-issued test CAs omit the extension; OpenSSL then
    # emits no extension text, and the verified BasicConstraints/signature
    # chain remains authoritative.  A present KeyUsage must allow signing.
    if normalized_key_usage and b"CERTIFICATESIGN" not in normalized_key_usage:
        raise BundleError(f"{label} key usage does not permit certificate signing")


def _require_end_entity_certificate(der: bytes, label: str) -> None:
    result = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-ext", "basicConstraints"],
        input=der,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise BundleError(f"{label} is not a valid X.509 certificate")
    constraints = re.sub(rb"\s+", b"", result.stdout).upper()
    if b"CA:TRUE" in constraints:
        raise BundleError(f"{label} must be an end-entity certificate")


def canonical_ca_bundle(pem_values: Sequence[tuple[str, str]]) -> bytes:
    certificates: dict[str, bytes] = {}
    for label, pem in pem_values:
        for der in _certificate_der_blocks(pem, label):
            _require_ca_certificate(der, label)
            certificates[hashlib.sha256(der).hexdigest()] = der
    if not certificates:
        raise BundleError("OIDF material contains no mTLS CA certificates")
    return "".join(
        ssl.DER_cert_to_PEM_cert(certificates[digest]).rstrip() + "\n"
        for digest in sorted(certificates)
    ).encode("ascii")


def validate_ca_bundle(bundle: bytes, label: str = BUNDLE_FILE_NAME) -> bytes:
    try:
        text = bundle.decode("ascii")
    except UnicodeDecodeError as error:
        raise BundleError(f"{label} must be ASCII PEM") from error
    canonical = canonical_ca_bundle([(label, text)])
    if canonical != bundle:
        raise BundleError(f"{label} is not in deterministic canonical PEM form")
    return canonical


def build_artifact_manifest(files: Mapping[str, bytes], source_commit: str) -> bytes:
    if not _COMMIT_SHA.fullmatch(source_commit):
        raise BundleError("OIDF public seed source commit must be a full lowercase Git SHA")
    if MANIFEST_FILE_NAME in files:
        raise BundleError(f"artifact files must not include {MANIFEST_FILE_NAME}")
    file_hashes = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in sorted(files.items())
    }
    tree_input = "".join(
        f"{name}\t{digest}\n" for name, digest in file_hashes.items()
    ).encode("utf-8")
    bundle = files.get(BUNDLE_FILE_NAME)
    if bundle is None:
        raise BundleError(f"artifact files must include {BUNDLE_FILE_NAME}")
    try:
        bundle_text = bundle.decode("ascii")
    except UnicodeDecodeError as error:
        raise BundleError(f"{BUNDLE_FILE_NAME} must be ASCII PEM") from error
    ca_fingerprints = sorted(
        hashlib.sha256(der).hexdigest()
        for der in _certificate_der_blocks(bundle_text, BUNDLE_FILE_NAME)
    )
    payload = {
        "schema": 1,
        "source_commit": source_commit,
        "tree_sha256": hashlib.sha256(tree_input).hexdigest(),
        "ca_der_sha256": ca_fingerprints,
        "files": file_hashes,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_artifact_directory(
    directory: Path,
    expected_source_commit: str | None = None,
) -> bytes:
    if not directory.is_dir():
        raise BundleError(f"OIDF public seed artifact directory does not exist: {directory}")
    entries = list(directory.iterdir())
    if len(entries) > 128:
        raise BundleError("OIDF public seed artifact contains too many files")
    total_size = 0
    configs: dict[str, Any] = {}
    for path in sorted(entries, key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise BundleError(f"OIDF public seed artifact contains a non-regular file: {path.name}")
        size = path.stat().st_size
        if size > 1024 * 1024:
            raise BundleError(f"OIDF public seed artifact file is too large: {path.name}")
        total_size += size
        if total_size > 16 * 1024 * 1024:
            raise BundleError("OIDF public seed artifact is too large")
        if path.name in {BUNDLE_FILE_NAME, MANIFEST_FILE_NAME}:
            continue
        if path.suffix != ".json":
            raise BundleError(f"OIDF public seed artifact contains an unexpected file: {path.name}")
        try:
            configs[path.name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise BundleError(f"OIDF public seed config is invalid: {path.name}") from error
    bundle_path = directory / BUNDLE_FILE_NAME
    if not bundle_path.is_file() or bundle_path.is_symlink():
        raise BundleError(f"OIDF public seed artifact is missing {BUNDLE_FILE_NAME}")
    expected, _ = build_ca_bundle(configs)
    actual = validate_ca_bundle(bundle_path.read_bytes(), str(bundle_path))
    if actual != expected:
        raise BundleError("OIDF mTLS CA bundle does not match the public seed configs")
    manifest_path = directory / MANIFEST_FILE_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise BundleError(f"OIDF public seed artifact is missing {MANIFEST_FILE_NAME}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError("OIDF public seed artifact manifest is invalid") from error
    source_commit = manifest.get("source_commit") if isinstance(manifest, dict) else None
    recorded_files = manifest.get("files") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != 1
        or not isinstance(source_commit, str)
        or not _COMMIT_SHA.fullmatch(source_commit)
        or not isinstance(recorded_files, dict)
    ):
        raise BundleError("OIDF public seed artifact manifest has an invalid schema")
    if expected_source_commit is not None and source_commit != expected_source_commit:
        raise BundleError(
            "OIDF public seed artifact source commit does not match the deployed backend commit"
        )
    actual_files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.iterdir()
        if path.name != MANIFEST_FILE_NAME
    }
    if recorded_files != dict(sorted(actual_files.items())):
        raise BundleError("OIDF public seed artifact manifest does not match its files")
    actual_contents = {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.name != MANIFEST_FILE_NAME
    }
    expected_manifest = json.loads(build_artifact_manifest(actual_contents, source_commit))
    if manifest != expected_manifest:
        raise BundleError("OIDF public seed artifact manifest metadata is not canonical")
    return actual


def build_ca_bundle(configs: Mapping[str, Any]) -> tuple[bytes, list[tuple[str, str]]]:
    ca_values: list[tuple[str, str]] = []
    leaf_values: list[tuple[str, str]] = []
    for file_name in sorted(configs):
        config = configs[file_name]
        if not isinstance(config, Mapping):
            continue
        for key in ("mtls", "mtls2"):
            material = config.get(key)
            if not isinstance(material, Mapping):
                continue
            ca = material.get("ca")
            cert = material.get("cert")
            if cert is None and ca is None:
                continue
            if not isinstance(ca, str) or not ca.strip():
                raise BundleError(f"{file_name}.{key}.ca is missing or empty")
            if not isinstance(cert, str) or not cert.strip():
                raise BundleError(f"{file_name}.{key}.cert is missing or empty")
            ca_label = f"{file_name}.{key}.ca"
            cert_label = f"{file_name}.{key}.cert"
            if len(_certificate_der_blocks(ca, ca_label)) != 1:
                raise BundleError(f"{ca_label} must contain exactly one CA certificate")
            per_material_bundle = canonical_ca_bundle([(ca_label, ca)])
            verify_leaf_certificates(per_material_bundle, [(cert_label, cert)])
            ca_values.append((ca_label, ca))
            leaf_values.append((cert_label, cert))
    bundle = canonical_ca_bundle(ca_values)
    verify_leaf_certificates(bundle, leaf_values)
    return bundle, leaf_values


def verify_leaf_certificates(bundle: bytes, leaves: Sequence[tuple[str, str]]) -> None:
    if not leaves:
        raise BundleError("OIDF material contains no mTLS client certificates")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ca_path = root / "ca.pem"
        ca_path.write_bytes(validate_ca_bundle(bundle))
        for index, (label, pem) in enumerate(leaves):
            der_blocks = _certificate_der_blocks(pem, label)
            if len(der_blocks) != 1:
                raise BundleError(f"{label} must contain exactly one client certificate")
            _require_end_entity_certificate(der_blocks[0], label)
            leaf_path = root / f"leaf-{index}.pem"
            leaf_path.write_text(
                ssl.DER_cert_to_PEM_cert(der_blocks[0]).rstrip() + "\n",
                encoding="ascii",
                newline="\n",
            )
            result = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-purpose",
                    "sslclient",
                    "-auth_level",
                    "2",
                    "-CAfile",
                    str(ca_path),
                    str(leaf_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise BundleError(f"{label} is not issued by the exported mTLS CA bundle")


def write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verify", nargs="?")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", type=Path)
    source.add_argument("--artifact-directory", type=Path)
    parser.add_argument("--expected-source-commit")
    args = parser.parse_args(argv)
    if args.verify not in (None, "verify"):
        parser.error("only the verify operation is supported")
    if args.artifact_directory is not None:
        validate_artifact_directory(
            args.artifact_directory,
            expected_source_commit=args.expected_source_commit,
        )
    elif args.expected_source_commit is not None:
        parser.error("--expected-source-commit requires --artifact-directory")
    else:
        validate_ca_bundle(args.bundle.read_bytes(), str(args.bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
