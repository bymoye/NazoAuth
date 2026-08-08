#!/usr/bin/env python3
"""Run the fixed 17-plan OpenID4VC matrix against a host-local OIDF suite.

This is a public-control-plane black-box operation.  It provisions one fresh,
non-administrator applicant and exactly four namespaced wallet clients through
the ordinary applicant/approval/one-time-delivery flow.  Its secret document
is accepted only from non-interactive stdin or an inherited descriptor; no
secret is accepted in argv or the environment.

The OpenID4VC matrix uses private_key_jwt/client_attestation plus DPoP.  It
does not exercise RFC 8705 mTLS, so this runner deliberately refuses to create
an mTLS trust request or install a proxy client-CA.  The OIDC/FAPI 27-plan
runner owns that independent ingress trust boundary.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets as secure_random
import shutil
import signal
import ssl
import stat
import subprocess
import sys
from typing import Iterator
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import apply_oidf_browser_credentials as browser_credentials  # noqa: E402
import apply_public_conformance_onboarding as onboarding  # noqa: E402
import build_oidf_full_install_profile as install_profile  # noqa: E402
from conformance_lease_control import (  # noqa: E402
    ConformanceLeaseControlError,
    add_candidate_target_arguments,
    candidate_target_from_args,
    create as create_lease,
    revoke_and_cleanup,
)
import materialize_openid4vc_oidf_config as materializer  # noqa: E402
import prepare_openid4vc_public_onboarding as public_onboarding  # noqa: E402
import provision_public_oidf_applicant as applicant_provisioning  # noqa: E402
import run_oidf_conformance as oidf  # noqa: E402
import run_openid4vc_conformance as openid4vc  # noqa: E402
from oidf_evidence import sanitize_evidence_tree  # noqa: E402
from oidf_secret_input import (  # noqa: E402
    SecretInputError,
    read_secret_document,
    sanitized_environment,
)
from run_public_oidf_conformance import (  # noqa: E402
    PublicRunError,
    command,
    protect_directory,
    secret_pipe,
    validate_output_paths,
    verify_source,
    verify_suite,
    verify_suite_boundary,
)


SECRET_FIELDS = (
    "applicant_email",
    "applicant_password",
    "admin_email",
    "admin_password",
    "admin_mfa_totp_secret",
    "suite_token",
    "issuer_management_token",
    "verifier_management_token",
)
MAX_PUBLIC_PEM_BYTES = 1024 * 1024
MAX_PREPARED_FILE_BYTES = 1024 * 1024
PREPARED_PROFILE_FILE = "standards-full-profile.json"
PREPARED_TRUST_FILE = "openid4vc-conformance-trust.json"
PREPARED_MATERIAL_FILE = "openid4vc-run-material.json"
PREPARED_MANIFEST_FILE = "host-local-oidf-install-manifest.json"
VCI_SD_JWT_CONFIGURATION_ID = "eu.europa.ec.eudi.pid.1"
VCI_MDOC_CONFIGURATION_ID = "org.iso.18013.5.1.mDL"
PRIVATE_CONFIG_NAMES = frozenset(
    {
        "base-input.json",
        "driver-input.json",
        "openid4vc-driver.json",
        "openid4vc-plan-configs.json",
        "oidf-onboarding-manifest.json",
        "openid4vc-plan-set-manifest.json",
        "oidf-delivered-client-material.json",
        "oidf-onboarding-state.json",
        "approved-mtls-trust-anchors.pem",
        "oidf-runner.env",
    }
)


class HostLocalOpenid4vcError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise HostLocalOpenid4vcError(message)


def canonical_suite_origin(value: str) -> str:
    try:
        return install_profile.origin(value, "suite origin")
    except install_profile.ProfileError as error:
        raise HostLocalOpenid4vcError(str(error)) from error


def build_prepared_install_profile(
    material: dict[str, object], suite_origin: str
) -> dict[str, object]:
    """Build a standards-full baseline without persisting conformance trust keys."""
    validate_generated_material(material)
    suite = canonical_suite_origin(suite_origin)
    return {
        "credential_configurations": {
            VCI_SD_JWT_CONFIGURATION_ID: install_profile.credential_configuration(
                VCI_SD_JWT_CONFIGURATION_ID, "dc+sd-jwt"
            ),
            VCI_MDOC_CONFIGURATION_ID: install_profile.credential_configuration(
                VCI_MDOC_CONFIGURATION_ID, "mso_mdoc"
            ),
        },
        "wallet_authorization_origins": [suite],
        "ciba_notification_private_origins": [suite],
        "backchannel_logout_private_origins": [suite],
    }


def build_prepared_conformance_trust(
    material: dict[str, object], suite_origin: str
) -> dict[str, object]:
    validate_generated_material(material)
    suite = canonical_suite_origin(suite_origin)
    client_attestation = material["client_attestation"]
    key_attestation = material["key_attestation"]
    if not isinstance(client_attestation, dict) or not isinstance(key_attestation, dict):
        fail("generated OpenID4VC attestation material has an invalid shape")
    return {
        "schema": 1,
        "client_attestation_issuer": f"{suite}/",
        "client_attestation_jwks": {"keys": [public_jwk(client_attestation)]},
        "key_attestation_jwks": {"keys": [public_jwk(key_attestation)]},
        "credential_trust_anchor_pem": material["trust_anchor_pem"],
    }


def read_public_trust_anchor(path: Path) -> str:
    """Read one public request-object trust anchor without following links."""
    if not path.is_absolute():
        fail("request-object trust anchor path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HostLocalOpenid4vcError("request-object trust anchor is not readable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("request-object trust anchor must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_PUBLIC_PEM_BYTES:
        fail(
            "request-object trust anchor must contain 1 through "
            f"{MAX_PUBLIC_PEM_BYTES} bytes"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostLocalOpenid4vcError("request-object trust anchor is not readable") from error
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
        ):
            fail("request-object trust anchor changed while it was opened")
        payload = b""
        while len(payload) <= MAX_PUBLIC_PEM_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_PUBLIC_PEM_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        completed = os.fstat(descriptor)
        if (
            (completed.st_dev, completed.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(completed.st_mode)
            or completed.st_size != opened.st_size
            or len(payload) != completed.st_size
        ):
            fail("request-object trust anchor changed while it was read")
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise HostLocalOpenid4vcError("request-object trust anchor must be ASCII PEM") from error
    if "PRIVATE KEY" in text:
        fail("request-object trust anchor must not contain a private key")
    marker_begin = "-----BEGIN CERTIFICATE-----"
    marker_end = "-----END CERTIFICATE-----"
    certificates: list[str] = []
    remainder = text
    while marker_begin in remainder:
        prefix, remainder = remainder.split(marker_begin, 1)
        if prefix.strip():
            fail("request-object trust anchor contains non-PEM data")
        if marker_end not in remainder:
            fail("request-object trust anchor contains an incomplete certificate")
        encoded, remainder = remainder.split(marker_end, 1)
        certificate = f"{marker_begin}{encoded}{marker_end}\n"
        try:
            ssl.PEM_cert_to_DER_cert(certificate)
        except ValueError as error:
            raise HostLocalOpenid4vcError("request-object trust anchor contains malformed PEM") from error
        certificates.append(certificate)
    if not certificates or remainder.strip():
        fail("request-object trust anchor must contain only PEM certificates")
    return "".join(certificates)


def private_write_json(path: Path, value: object) -> None:
    onboarding.write_private_json(path, value)


def onboarding_namespace(args: argparse.Namespace) -> str:
    namespace = args.run_namespace.strip().lower()
    # Let materializer remain the single source of the namespace grammar.
    materializer.vci_client_ids("operator-black-box", namespace)
    return namespace


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def run_openssl(arguments: list[str], *, cwd: Path, capture: bool = False) -> bytes:
    """Use OpenSSL without putting key material in argv, env, or diagnostics."""
    completed = subprocess.run(
        ["openssl", *arguments],
        cwd=cwd,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("OpenSSL failed while generating isolated OpenID4VC material")
    return completed.stdout


def ec_p256_jwk(key_path: Path, *, kid: str, certificate_path: Path | None = None) -> dict[str, object]:
    private_der = run_openssl(["ec", "-in", str(key_path), "-outform", "DER"], cwd=key_path.parent, capture=True)
    marker = b"\x04\x20"
    index = private_der.find(marker)
    if index < 0 or index > 8 or len(private_der) < index + 34:
        fail("OpenSSL produced an unexpected P-256 private-key encoding")
    private_bytes = private_der[index + 2 : index + 34]
    if len(private_bytes) != 32:
        fail("OpenSSL produced an invalid P-256 private scalar")
    public_der = run_openssl(
        ["ec", "-in", str(key_path), "-pubout", "-outform", "DER"],
        cwd=key_path.parent,
        capture=True,
    )
    public_marker = b"\x03\x42\x00\x04"
    if not public_der.endswith(public_marker + public_der[-64:]) or len(public_der) < 68:
        fail("OpenSSL produced an unexpected P-256 public-key encoding")
    point = public_der[-64:]
    result: dict[str, object] = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x": b64url(point[:32]),
        "y": b64url(point[32:]),
        "d": b64url(private_bytes),
    }
    if certificate_path is not None:
        try:
            certificate_der = ssl.PEM_cert_to_DER_cert(certificate_path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise HostLocalOpenid4vcError("generated OpenID4VC certificate is malformed") from error
        result["x5c"] = [base64.b64encode(certificate_der).decode("ascii")]
    return result


def generate_certificate_material(
    work_dir: Path, *, suite_origin: str | None = None
) -> dict[str, object]:
    """Create fresh P-256 wallet/attestation/credential material for one run."""
    directory = work_dir / "generated-openid4vc-material"
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    root_key = directory / "run-ca.key"
    root_certificate = directory / "run-ca.pem"
    run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(root_key)], cwd=directory)
    run_openssl(
        [
            "req", "-new", "-x509", "-key", str(root_key), "-subj", "/CN=NazoAuth OpenID4VC ephemeral run CA",
            "-days", "2", "-sha256", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(root_certificate),
        ],
        cwd=directory,
    )
    extension_file = directory / "leaf.ext"
    extension_file.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="ascii",
    )
    extension_file.chmod(0o600)
    credential_extension_file = directory / "credential.ext"
    credential_san = ""
    if suite_origin is not None:
        parsed_suite = urlsplit(canonical_suite_origin(suite_origin))
        suite_host = parsed_suite.hostname
        if not suite_host:
            fail("conformance suite origin must contain a DNS host")
        credential_san = f"subjectAltName=DNS:{suite_host}\n"
    credential_extension_file.write_text(
        (
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=1.0.18013.5.1.2\n"
            + "subjectKeyIdentifier=hash\n"
            + "authorityKeyIdentifier=keyid,issuer\n"
        ),
        encoding="ascii",
    )
    credential_extension_file.chmod(0o600)
    generated: dict[str, object] = {"trust_anchor_pem": root_certificate.read_text(encoding="ascii")}
    for name in ("wallet_private", "wallet_attested", "client_attestation", "key_attestation", "credential"):
        key = directory / f"{name}.key"
        request = directory / f"{name}.csr"
        certificate = directory / f"{name}.pem"
        run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)], cwd=directory)
        run_openssl(
            [
                "req", "-new", "-key", str(key), "-subj", f"/CN=NazoAuth {name}",
                *(["-addext", credential_san.rstrip("\n")] if name == "credential" and credential_san else []),
                "-out", str(request),
            ],
            cwd=directory,
        )
        run_openssl(
            [
                "x509", "-req", "-in", str(request), "-CA", str(root_certificate), "-CAkey", str(root_key),
                "-CAcreateserial", "-days", "2", "-sha256", "-copy_extensions", "copy", "-extfile",
                str(credential_extension_file if name == "credential" else extension_file),
                "-out", str(certificate),
            ],
            cwd=directory,
        )
        run_openssl(["verify", "-CAfile", str(root_certificate), str(certificate)], cwd=directory)
        generated[name] = ec_p256_jwk(
            key,
            kid=f"nazo-openid4vc-{name}-{secure_random.token_hex(8)}",
            certificate_path=certificate,
        )
    validate_generated_material(generated)
    return generated


def validate_generated_material(material: dict[str, object]) -> None:
    names = ("wallet_private", "wallet_attested", "client_attestation", "key_attestation", "credential")
    public_coordinates: set[tuple[str, str]] = set()
    private_scalars: set[str] = set()
    kids: set[str] = set()
    for name in names:
        key = material.get(name)
        if not isinstance(key, dict):
            fail(f"generated OpenID4VC material lacks {name}")
        if any(key.get(field) != expected for field, expected in (("kty", "EC"), ("crv", "P-256"), ("alg", "ES256"), ("use", "sig"))):
            fail("generated OpenID4VC key does not have the required P-256 signature profile")
        if not all(isinstance(key.get(field), str) and key[field] for field in ("kid", "x", "y", "d")):
            fail("generated OpenID4VC key is incomplete")
        x5c = key.get("x5c")
        if not isinstance(x5c, list) or len(x5c) != 1 or not isinstance(x5c[0], str) or not x5c[0]:
            fail("generated OpenID4VC key lacks its required x5c certificate")
        coordinate = (str(key["x"]), str(key["y"]))
        if coordinate in public_coordinates or str(key["d"]) in private_scalars or str(key["kid"]) in kids:
            fail("generated OpenID4VC keys are not unique for this run")
        public_coordinates.add(coordinate)
        private_scalars.add(str(key["d"]))
        kids.add(str(key["kid"]))
    trust_anchor = material.get("trust_anchor_pem")
    if not isinstance(trust_anchor, str) or "BEGIN CERTIFICATE" not in trust_anchor:
        fail("generated OpenID4VC material lacks its run-local trust anchor")


def public_jwk(key: dict[str, object]) -> dict[str, object]:
    return {field: value for field, value in key.items() if field != "d"}


def read_protected_json(path: Path, label: str) -> tuple[dict[str, object], str]:
    """Read a bounded 0600 JSON object from one stable, non-symlink inode."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HostLocalOpenid4vcError(f"{label} is not readable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_PREPARED_FILE_BYTES:
        fail(f"{label} must contain 1 through {MAX_PREPARED_FILE_BYTES} bytes")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"{label} must have mode 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostLocalOpenid4vcError(f"{label} is not readable") from error
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
        ):
            fail(f"{label} changed while it was opened")
        payload = b""
        while len(payload) <= MAX_PREPARED_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_PREPARED_FILE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload += chunk
        completed = os.fstat(descriptor)
        if (
            (completed.st_dev, completed.st_ino) != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(completed.st_mode)
            or completed.st_size != opened.st_size
            or len(payload) != completed.st_size
        ):
            fail(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HostLocalOpenid4vcError(f"{label} must be strict JSON") from error
    if not isinstance(document, dict):
        fail(f"{label} must be a JSON object")
    return document, hashlib.sha256(payload).hexdigest()


def prepared_material(
    args: argparse.Namespace,
) -> tuple[dict[str, object], str, str]:
    directory = args.prepared_install_dir
    if directory is None:
        fail("--prepared-install-dir is required for the host-local matrix")
    if not directory.is_absolute():
        fail("--prepared-install-dir must be absolute")
    directory = directory.resolve()
    try:
        metadata = directory.lstat()
    except OSError as error:
        raise HostLocalOpenid4vcError("prepared install directory is not readable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("prepared install directory must be a non-symlink directory")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("prepared install directory must have mode 0700")
    expected_names = {
        PREPARED_PROFILE_FILE,
        PREPARED_TRUST_FILE,
        PREPARED_MATERIAL_FILE,
        PREPARED_MANIFEST_FILE,
    }
    try:
        observed_names = {path.name for path in directory.iterdir()}
    except OSError as error:
        raise HostLocalOpenid4vcError("prepared install directory is not readable") from error
    if observed_names != expected_names:
        fail("prepared install directory does not contain the exact expected file set")
    manifest, _ = read_protected_json(
        directory / PREPARED_MANIFEST_FILE, "prepared install manifest"
    )
    profile, profile_digest = read_protected_json(
        directory / PREPARED_PROFILE_FILE, "prepared standards-full profile"
    )
    trust, trust_digest = read_protected_json(
        directory / PREPARED_TRUST_FILE, "prepared OpenID4VC conformance trust"
    )
    material, material_digest = read_protected_json(
        directory / PREPARED_MATERIAL_FILE, "prepared OpenID4VC material"
    )
    expected_manifest = {
        "schema": 1,
        "source_commit": args.deployed_sha,
        "suite_origin": args.conformance_server,
        "files": {
            PREPARED_PROFILE_FILE: profile_digest,
            PREPARED_TRUST_FILE: trust_digest,
            PREPARED_MATERIAL_FILE: material_digest,
        },
    }
    if manifest != expected_manifest:
        fail("prepared install manifest does not match this source, Suite, and file set")
    validate_generated_material(material)
    if profile != build_prepared_install_profile(material, args.conformance_server):
        fail("prepared standards-full profile does not match the private run identity")
    if trust != build_prepared_conformance_trust(material, args.conformance_server):
        fail("prepared conformance trust does not match the private run identity")
    args.prepared_install_dir = directory
    return material, material_digest, trust_digest


def consume_prepared_material(directory: Path, expected_digest: str) -> None:
    path = directory / PREPARED_MATERIAL_FILE
    _, digest = read_protected_json(path, "prepared OpenID4VC material")
    if digest != expected_digest:
        fail("prepared OpenID4VC material changed before consumption")
    path.unlink()
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def consume_prepared_trust(directory: Path, expected_digest: str) -> None:
    path = directory / PREPARED_TRUST_FILE
    _, digest = read_protected_json(path, "prepared OpenID4VC conformance trust")
    if digest != expected_digest:
        fail("prepared OpenID4VC conformance trust changed before consumption")
    path.unlink()
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def build_base_input(
    material: dict[str, object],
    *,
    suite_origin: str,
    deployed_trust_anchor: str,
) -> dict[str, object]:
    validate_generated_material(material)
    wallet_private = material["wallet_private"]
    wallet_attested = material["wallet_attested"]
    attestation = material["client_attestation"]
    key_attestation = material["key_attestation"]
    credential = material["credential"]
    trust_anchor = material["trust_anchor_pem"]
    if not all(
        isinstance(value, dict)
        for value in (wallet_private, wallet_attested, attestation, key_attestation, credential)
    ) or not isinstance(trust_anchor, str):
        fail("generated OpenID4VC material has an invalid configuration shape")
    if "-----BEGIN CERTIFICATE-----" not in deployed_trust_anchor:
        fail("deployed OpenID4VC trust anchor is not a PEM certificate")
    def issuer_base(wallet: dict[str, object], *, attested: bool) -> dict[str, object]:
        config: dict[str, object] = {
            "alias": "nazo-openid4vc-vci-haip" if attested else "nazo-openid4vc-vci",
            "client": {"client_id": "generated", "scope": f"openid {VCI_SD_JWT_CONFIGURATION_ID} {VCI_MDOC_CONFIGURATION_ID}", "jwks": {"keys": [wallet]}},
            "client2": {"client_id": "generated-client2", "scope": f"openid {VCI_SD_JWT_CONFIGURATION_ID} {VCI_MDOC_CONFIGURATION_ID}", "jwks": {"keys": [wallet]}},
            # The Suite accepts this legacy location during its transition to
            # a top-level client_attestation object.  Keeping it here lets a
            # private_key_jwt client supply independent key-attestation proof
            # material without being misclassified as a HAIP client.
            "vci": {"key_attestation_jwks": {"keys": [key_attestation]}},
            # The Suite is the relying wallet in VCI plans, so it must trust the
            # deployed issuer's managed signing bundle, not this run's actor CA.
            "credential": {
                "trust_anchor_pem": deployed_trust_anchor,
                "status_list_trust_anchor_pem": deployed_trust_anchor,
            },
        }
        if attested:
            config["client_attestation"] = {
                "issuer": f"{suite_origin.rstrip('/')}/",
                "trust_anchor": trust_anchor,
                "key_attestation_trust_anchor_pem": trust_anchor,
                "attester_jwks": {"keys": [attestation]},
                "key_attestation_jwks": {"keys": [key_attestation]},
            }
        return config
    def verifier_base(*, haip: bool) -> dict[str, object]:
        return {
            "alias": "nazo-openid4vc-vp-haip" if haip else "nazo-openid4vc-vp",
            "client": {"client_id": "generated"},
            "credential": {
                "signing_jwk": credential,
                "trust_anchor_pem": trust_anchor,
                "status_list_trust_anchor_pem": trust_anchor,
            },
        }
    return {
        "vci": issuer_base(wallet_private, attested=False),
        "vci_haip": issuer_base(wallet_attested, attested=True),
        "vp": verifier_base(haip=False),
        "vp_haip": verifier_base(haip=True),
    }


def build_driver_input(secrets: dict[str, str], *, subject_id: str, trust_anchor: str) -> dict[str, object]:
    return {
        "hosted_authorization": {
            "email": secrets["applicant_email"],
            "password": secrets["applicant_password"],
        },
        "issuer": {
            "management_token": secrets["issuer_management_token"],
            "subject_id": subject_id,
            "dedicated_conformance_subject": True,
            "credential_configuration_ids": {
                "sd_jwt_vc": VCI_SD_JWT_CONFIGURATION_ID,
                "mdoc": VCI_MDOC_CONFIGURATION_ID,
            },
            "tx_code": f"{secure_random.randbelow(1_000_000):06d}",
        },
        "verifier": {
            "management_token": secrets["verifier_management_token"],
            "request_object_trust_anchor_pem": trust_anchor,
            "credential_type_values": {
                "sd_jwt_vc": materializer.OIDF_VP_SD_JWT_VCT,
                "iso_mdl": VCI_MDOC_CONFIGURATION_ID,
            },
        },
    }


def credential_document(secrets: dict[str, str]) -> dict[str, str]:
    return {
        "applicant_email": secrets["applicant_email"],
        "applicant_password": secrets["applicant_password"],
        "admin_email": secrets["admin_email"],
        "admin_password": secrets["admin_password"],
        "admin_mfa_totp_secret": secrets["admin_mfa_totp_secret"],
    }


@contextlib.contextmanager
def onboarding_credentials_fd(secrets: dict[str, str]) -> Iterator[int]:
    serialized = json.dumps(credential_document(secrets), separators=(",", ":"))
    with secret_pipe(serialized) as descriptor:
        yield descriptor


@contextlib.contextmanager
def admin_credentials_fd(secrets: dict[str, str]) -> Iterator[int]:
    serialized = json.dumps(
        {
            "admin_email": secrets["admin_email"],
            "admin_password": secrets["admin_password"],
            "admin_mfa_totp_secret": secrets["admin_mfa_totp_secret"],
        },
        separators=(",", ":"),
    )
    with secret_pipe(serialized) as descriptor:
        yield descriptor


def onboarding_args(
    action: str,
    work_dir: Path,
    issuer: str,
    descriptor: int,
    lease_id: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        command=action,
        target_issuer=issuer,
        lease_id=lease_id,
        credentials_stdin=False,
        credentials_fd=descriptor,
        manifest=work_dir / "oidf-onboarding-manifest.json",
        plan_configs=work_dir / "openid4vc-plan-configs.json",
        plan_set=work_dir / "openid4vc-plan-set.json",
        plan_manifest=work_dir / "openid4vc-plan-set-manifest.json",
        runner_env=work_dir / "oidf-runner.env",
        delivered_client_material=work_dir / "oidf-delivered-client-material.json",
        no_runner_env=True,
        state_file=work_dir / "oidf-onboarding-state.json",
        trust_bundle=work_dir / "approved-mtls-trust-anchors.pem",
    )


def assert_openid4vc_manifest_boundary(path: Path) -> None:
    manifest = onboarding.require_manifest(path)
    clients = manifest.get("clients")
    if not isinstance(clients, list) or len(clients) != 4:
        fail("OpenID4VC host-local onboarding requires exactly four wallet clients")
    if any(
        not isinstance(client, dict) or client.get("mtls_trust_anchor_pem") is not None
        for client in clients
    ):
        fail(
            "OpenID4VC 17-plan onboarding must not request mTLS trust; "
            "the 27-plan OIDC/FAPI runner owns proxy client-CA changes"
        )


def materialize_configs(
    args: argparse.Namespace,
    secrets: dict[str, str],
    subject_id: str,
    trust_anchor: str,
    supplied_material: dict[str, object] | None = None,
) -> dict[str, object]:
    material = supplied_material or generate_certificate_material(
        args.work_dir, suite_origin=args.conformance_server
    )
    validate_generated_material(material)
    private_write_json(
        args.work_dir / "base-input.json",
        build_base_input(
            material,
            suite_origin=args.conformance_server,
            deployed_trust_anchor=trust_anchor,
        ),
    )
    private_write_json(
        args.work_dir / "driver-input.json",
        build_driver_input(secrets, subject_id=subject_id, trust_anchor=trust_anchor),
    )
    command(
        [
            sys.executable,
            str(ROOT / "scripts" / "materialize_openid4vc_oidf_config.py"),
            "--base-config-json-file",
            str(args.work_dir / "base-input.json"),
            "--driver-config-json-file",
            str(args.work_dir / "driver-input.json"),
            "--credential-datasets-json-file",
            str(ROOT / "tests" / "contracts" / "openid4vc-conformance-datasets.json"),
            "--conformance-server",
            args.conformance_server,
            "--target-origin",
            args.target_issuer,
            "--onboarding-profile",
            "operator-black-box",
            "--run-namespace",
            args.run_namespace,
            "--subject-id",
            subject_id,
            "--output-dir",
            str(args.work_dir),
        ],
        env=sanitized_environment(),
    )
    protect_directory(args.work_dir)
    validate_materialized_configs(
        args.work_dir / "openid4vc-plan-configs.json",
        material,
        args.run_namespace,
        trust_anchor,
    )
    return material


def validate_materialized_configs(
    path: Path,
    material: dict[str, object],
    namespace: str,
    deployed_trust_anchor: str,
) -> None:
    """Prove the private suite inputs and public onboarding will share one fresh identity set."""
    document = json.loads(path.read_text(encoding="utf-8"))
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict) or len(configs) != len(materializer.matrix_cases()):
        fail("materialized OpenID4VC configs do not cover the fixed 17-plan registry")
    expected_ids = materializer.vci_client_ids("operator-black-box", namespace)
    expected_wallets = {
        expected_ids["private_key"]: material["wallet_private"],
        expected_ids["attested"]: material["wallet_attested"],
    }
    observed_public: dict[str, dict[str, object]] = {}
    observed_private_scalars: set[str] = set()
    run_trust_anchor = material.get("trust_anchor_pem")
    for filename, config in configs.items():
        if not isinstance(config, dict):
            fail("materialized OpenID4VC config is not an object")
        credential_config = config.get("credential")
        if not isinstance(credential_config, dict):
            fail("materialized OpenID4VC config lacks credential trust settings")
        expected_anchor = (
            deployed_trust_anchor
            if str(filename).startswith("openid4vc-vci-")
            else run_trust_anchor
        )
        if any(
            credential_config.get(field) != expected_anchor
            for field in ("trust_anchor_pem", "status_list_trust_anchor_pem")
        ):
            fail("materialized OpenID4VC credential trust escaped its issuer boundary")
        nazo = config.get("nazo")
        if not isinstance(nazo, dict):
            continue
        client = config.get("client")
        client2 = config.get("client2")
        if not isinstance(client, dict) or not isinstance(client2, dict):
            fail("materialized VCI config lacks its two wallet clients")
        client_id = client.get("client_id")
        client2_id = client2.get("client_id")
        if client_id not in expected_wallets or client2_id not in {expected_ids["private_key2"], expected_ids["attested2"]}:
            fail("materialized OpenID4VC config escaped the namespaced onboarding identities")
        for identifier, wallet in ((client_id, client), (client2_id, client2)):
            jwks = wallet.get("jwks") if isinstance(wallet, dict) else None
            keys = jwks.get("keys") if isinstance(jwks, dict) else None
            if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
                fail("materialized wallet client does not contain exactly one private JWK")
            key = keys[0]
            private = key.get("d")
            if not isinstance(private, str) or not private:
                fail("materialized wallet client lacks its generated private JWK")
            observed_private_scalars.add(private)
            public = public_jwk(key)
            existing = observed_public.setdefault(str(identifier), public)
            if existing != public:
                fail("one onboarding client maps to inconsistent private suite configurations")
    if set(observed_public) != set(expected_ids.values()) or len(observed_private_scalars) != 4:
        fail("materialized OpenID4VC wallet identities are incomplete or reused")
    for client_id, expected in expected_wallets.items():
        expected_public = public_jwk(expected) if isinstance(expected, dict) else None
        if observed_public.get(client_id) != expected_public:
            fail("generated wallet key does not match the materialized onboarding identity")
    for key_name in ("client_attestation", "key_attestation", "credential"):
        key = material.get(key_name)
        if not isinstance(key, dict):
            fail("generated material disappeared before configuration validation")
        expected_public = public_jwk(key)
        found = False
        for config in configs.values():
            if not isinstance(config, dict):
                continue
            if key_name == "credential":
                candidate = config.get("credential")
                observed = candidate.get("signing_jwk") if isinstance(candidate, dict) else None
            else:
                candidate = config.get("client_attestation")
                field = "attester_jwks" if key_name == "client_attestation" else "key_attestation_jwks"
                jwks = candidate.get(field) if isinstance(candidate, dict) else None
                if jwks is None and key_name == "key_attestation":
                    vci = config.get("vci")
                    jwks = vci.get("key_attestation_jwks") if isinstance(vci, dict) else None
                keys = jwks.get("keys") if isinstance(jwks, dict) else None
                observed = keys[0] if isinstance(keys, list) and len(keys) == 1 else None
            if observed == key:
                found = True
        if not found:
            fail("generated OpenID4VC private material is not bound to the suite configuration")


def assert_public_onboarding_key_alignment(path: Path, plan_configs: Path) -> None:
    manifest = onboarding.require_manifest(path)
    delivered = manifest.get("clients")
    if not isinstance(delivered, list) or len(delivered) != 4:
        fail("OpenID4VC onboarding did not produce the four required public clients")
    configs = json.loads(plan_configs.read_text(encoding="utf-8"))
    entries = configs.get("configs") if isinstance(configs, dict) else None
    if not isinstance(entries, dict):
        fail("cannot verify OpenID4VC onboarding key alignment without plan configs")
    expected: dict[str, dict[str, object]] = {}
    for config in entries.values():
        if not isinstance(config, dict) or not isinstance(config.get("nazo"), dict):
            continue
        for client_name in ("client", "client2"):
            client = config.get(client_name)
            jwks = client.get("jwks") if isinstance(client, dict) else None
            keys = jwks.get("keys") if isinstance(jwks, dict) else None
            client_id = client.get("client_id") if isinstance(client, dict) else None
            if isinstance(client_id, str) and isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], dict):
                public = public_jwk(keys[0])
                existing = expected.setdefault(client_id, public)
                if existing != public:
                    fail("public onboarding identity maps to different generated suite keys")
    actual: dict[str, dict[str, object]] = {}
    for client in delivered:
        if not isinstance(client, dict):
            fail("OpenID4VC onboarding client entry is invalid")
        request = client.get("request")
        client_id = client.get("logical_client_id")
        jwks = request.get("jwks") if isinstance(request, dict) else None
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(client_id, str) or not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
            fail("OpenID4VC onboarding client lacks a single public JWK")
        if "d" in keys[0]:
            fail("OpenID4VC public onboarding leaked a private JWK")
        actual[client_id] = keys[0]
    if actual != expected:
        fail("OpenID4VC public onboarding keys do not match generated private suite configuration")


def apply_public_onboarding(args: argparse.Namespace, secrets: dict[str, str]) -> None:
    public_onboarding.prepare_onboarding_bundle(
        plan_configs=args.work_dir / "openid4vc-plan-configs.json",
        plan_set=args.work_dir / "openid4vc-plan-set.json",
        target_issuer=args.target_issuer,
        suite_base_url=args.conformance_server,
        applicant_email=secrets["applicant_email"],
        output_dir=args.work_dir,
    )
    assert_openid4vc_manifest_boundary(args.work_dir / "oidf-onboarding-manifest.json")
    assert_public_onboarding_key_alignment(
        args.work_dir / "oidf-onboarding-manifest.json",
        args.work_dir / "openid4vc-plan-configs.json",
    )
    lease_id = create_conformance_lease(args)
    with onboarding_credentials_fd(secrets) as descriptor:
        onboarding.apply_onboarding(
            onboarding_args(
                "apply",
                args.work_dir,
                args.target_issuer,
                descriptor,
                lease_id,
            )
        )
    browser_credentials.apply_credentials(
        args.work_dir / "openid4vc-plan-configs.json",
        {
            "applicant_email": secrets["applicant_email"],
            "applicant_password": secrets["applicant_password"],
        },
    )
    protect_directory(args.work_dir)


def create_conformance_lease(args: argparse.Namespace) -> str:
    lease_id = create_lease(
        args.nazoauthctl,
        args.nazoauthctl_config,
        profile="openid4vc",
        material=args.prepared_install_dir / PREPARED_TRUST_FILE,
        ttl_seconds=args.lease_ttl_seconds,
        candidate=getattr(args, "candidate_target", None),
    )
    # Register the lease before consuming prepared trust.  If consumption fails,
    # the outer run() finally block must still have an id to revoke and clean up.
    args.active_lease_id = lease_id
    consume_prepared_trust(args.prepared_install_dir, args.prepared_trust_digest)
    return lease_id


def revoke_conformance_lease(args: argparse.Namespace, lease_id: str) -> None:
    revoke_and_cleanup(
        args.nazoauthctl,
        args.nazoauthctl_config,
        lease_id,
        candidate=getattr(args, "candidate_target", None),
    )


def aliases_from_configs(path: Path) -> dict[str, str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict):
        fail("materialized OpenID4VC configs must contain a configs object")
    aliases: dict[str, str] = {}
    for name, config in configs.items():
        alias = config.get("alias") if isinstance(config, dict) else None
        if not isinstance(name, str) or not isinstance(alias, str) or not alias:
            fail("materialized OpenID4VC config has no non-empty alias")
        aliases[name] = alias
    if len(aliases) != len(materializer.matrix_cases()) or len(set(aliases.values())) != len(aliases):
        fail("materialized OpenID4VC aliases do not cover the fixed 17-plan registry")
    return aliases


def run_matrix(args: argparse.Namespace, secrets: dict[str, str]) -> None:
    runner_args = [
        "--driver-config-json-file",
        str(args.work_dir / "openid4vc-driver.json"),
        "--operator-credentials-fd",
        "{credentials_fd}",
        "--suite-token-fd",
        "{suite_token_fd}",
        "--plan-group-size",
        str(args.plan_group_size),
        "--",
        "--suite-dir",
        str(args.suite_dir),
        "--suite-revision",
        args.suite_revision,
        "--conformance-server",
        args.conformance_server,
        "--target-issuer",
        args.target_issuer,
        "--config-json-file",
        str(args.work_dir / "openid4vc-plan-configs.json"),
        "--plan-set-json-file",
        str(args.work_dir / "openid4vc-plan-set.json"),
        "--expected-failures-file",
        str(args.work_dir / "openid4vc-expected-problems.json"),
        "--expected-skips-file",
        str(args.work_dir / "openid4vc-expected-skips.json"),
        "--export-dir",
        str(args.export_dir),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--monitor-interval-seconds",
        str(args.monitor_interval_seconds),
    ]
    with admin_credentials_fd(secrets) as credentials_fd, secret_pipe(secrets["suite_token"]) as token_fd:
        resolved = [
            str(credentials_fd) if value == "{credentials_fd}" else str(token_fd)
            if value == "{suite_token_fd}"
            else value
            for value in runner_args
        ]
        exit_code = openid4vc.main(resolved)
    if exit_code != 0:
        fail(f"host-local OpenID4VC official runner exited with {exit_code}")

    aliases = aliases_from_configs(args.work_dir / "openid4vc-plan-configs.json")
    failure = oidf.inspect_oidf_state(
        args.conformance_server,
        secrets["suite_token"],
        set(aliases.values()),
        final=True,
        allowed_reviews_by_alias=oidf.allowed_review_contexts_by_alias(aliases),
        allowed_expected_problems_by_alias=oidf.expected_problem_contexts_by_alias(
            args.work_dir / "openid4vc-expected-problems.json", aliases
        ),
        allowed_expected_skips_by_alias=oidf.expected_skip_contexts_by_alias(
            args.work_dir / "openid4vc-expected-skips.json", aliases
        ),
    )
    if failure:
        fail(f"OpenID4VC full-matrix final state check failed: {failure}")


def delete_private_configs(work_dir: Path) -> None:
    generated = work_dir / "generated-openid4vc-material"
    if generated.exists():
        shutil.rmtree(generated)
    for name in PRIVATE_CONFIG_NAMES:
        (work_dir / name).unlink(missing_ok=True)
    for path in work_dir.glob("openid4vc-*.json"):
        path.unlink(missing_ok=True)
    for path in work_dir.glob("oidf-*.json"):
        path.unlink(missing_ok=True)


def evidence_binding(manifest_path: Path | None) -> dict[str, object] | None:
    if manifest_path is None:
        return None
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("format_version") != 1:
        fail("OpenID4VC evidence manifest has an unsupported format")
    summary = payload.get("summary")
    archives = payload.get("archives")
    if not isinstance(summary, dict) or not isinstance(archives, list):
        fail("OpenID4VC evidence manifest is incomplete")
    plan_ids: set[str] = set()
    for archive in archives:
        modules = archive.get("modules") if isinstance(archive, dict) else None
        if not isinstance(modules, list):
            fail("OpenID4VC evidence manifest contains an invalid archive")
        for module in modules:
            test_info = module.get("test_info") if isinstance(module, dict) else None
            plan_id = test_info.get("planId") if isinstance(test_info, dict) else None
            if isinstance(plan_id, str) and plan_id:
                plan_ids.add(plan_id)
    if summary.get("plan_count") != len(plan_ids):
        fail("OpenID4VC evidence manifest plan summary is inconsistent")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return {
        "manifest": manifest_path.name,
        "manifest_sha256": digest,
        "plan_ids": sorted(plan_ids),
        "summary": summary,
    }


def write_receipt(
    args: argparse.Namespace,
    *,
    outcome: str,
    cleanup_complete: bool,
    manifest_path: Path | None,
) -> Path:
    evidence = evidence_binding(manifest_path)
    if outcome == "PASSED" and (
        evidence is None
        or len(evidence["plan_ids"]) != len(materializer.matrix_cases())
    ):
        fail("successful OpenID4VC receipt must bind all 17 independent plan IDs")
    receipt = {
        "format_version": 1,
        "runner": "host-local-openid4vc",
        "outcome": outcome,
        "deployed_sha": args.deployed_sha,
        "runner_sha": args.runner_sha,
        "suite_revision": args.suite_revision,
        "target_issuer": args.target_issuer,
        "conformance_server": args.conformance_server,
        "plan_registry_count": len(materializer.matrix_cases()),
        "plan_registry": sorted(case[1] for case in materializer.matrix_cases()),
        "mTLS_proxy_trust_touched": False,
        "public_onboarding_cleanup_complete": cleanup_complete,
        "evidence": evidence,
    }
    path = args.export_dir / "host-local-openid4vc-receipt.json"
    temporary = args.export_dir / ".host-local-openid4vc-receipt.json.tmp"
    temporary.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    with temporary.open("r+b") as handle:
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    if os.name == "posix":
        descriptor = os.open(args.export_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return path


def run(args: argparse.Namespace) -> None:
    args.candidate_target = candidate_target_from_args(args)
    if args.plan_group_size < 1:
        fail("--plan-group-size must be greater than zero")
    if not 60 <= args.lease_ttl_seconds <= 86_400:
        fail("--lease-ttl-seconds must be between 60 and 86400")
    args.target_issuer = onboarding.canonical_https_origin(args.target_issuer, label="--target-issuer")
    args.conformance_server = canonical_suite_origin(args.conformance_server)
    args.prepared_install_dir = getattr(args, "prepared_install_dir", None)
    args.work_dir = args.work_dir.resolve()
    args.export_dir = args.export_dir.resolve()
    args.suite_dir = args.suite_dir.resolve()
    args.deployed_source_dir = (args.deployed_source_dir or ROOT).resolve()
    args.nazoauthctl = args.nazoauthctl.resolve()
    if not args.nazoauthctl.is_file():
        fail("--nazoauthctl must resolve to a regular file")
    if args.nazoauthctl_config is not None:
        if not args.nazoauthctl_config.is_absolute():
            fail("--nazoauthctl-config must be absolute")
        args.nazoauthctl_config = args.nazoauthctl_config.resolve()
    args.runner_sha = args.runner_sha or args.deployed_sha
    if args.work_dir.exists() or args.export_dir.exists():
        fail("--work-dir and --export-dir must not already exist")
    validate_output_paths(args.work_dir, args.export_dir, args.suite_dir)
    verify_source(ROOT, args.runner_sha, "runner")
    if args.deployed_source_dir != ROOT or args.deployed_sha != args.runner_sha:
        verify_source(args.deployed_source_dir, args.deployed_sha, "deployed")
    verify_suite(args.suite_dir, args.suite_revision)
    supplied = prepared_material(args)
    args.prepared_trust_digest = supplied[2]
    args.active_lease_id = None
    namespace = onboarding_namespace(args)
    args.run_namespace = namespace
    trust_anchor = read_public_trust_anchor(args.request_object_trust_anchor_pem)
    secrets = read_secret_document(args, required_fields=SECRET_FIELDS)
    verify_suite_boundary(args.conformance_server, secrets["suite_token"])
    args.work_dir.mkdir(parents=True, mode=0o700)
    args.export_dir.mkdir(parents=True, mode=0o700)
    args.work_dir.chmod(0o700)
    args.export_dir.chmod(0o700)
    previous_umask = os.umask(0o077)
    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def interrupt_runner(signum, _frame):  # noqa: ANN001
        name = signal.Signals(signum).name
        raise InterruptedError(f"host-local OpenID4VC runner interrupted by {name}")

    signal.signal(signal.SIGINT, interrupt_runner)
    signal.signal(signal.SIGTERM, interrupt_runner)
    failure: BaseException | None = None
    cleanup_complete = False
    try:
        provisioned = applicant_provisioning.provision(args.target_issuer, credential_document(secrets))
        subject_id = provisioned["user_id"]
        materialize_configs(
            args,
            secrets,
            subject_id,
            trust_anchor,
            supplied_material=supplied[0],
        )
        consume_prepared_material(args.prepared_install_dir, supplied[1])
        apply_public_onboarding(args, secrets)
        run_matrix(args, secrets)
    except BaseException as error:
        failure = error
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup_errors: list[BaseException] = []
        manifest_path: Path | None = None
        try:
            config_path = args.work_dir / "openid4vc-plan-configs.json"
            if config_path.is_file():
                openid4vc.cleanup_suite_plan_configs(
                    openid4vc.suite_plan_config_paths(
                        [
                            "--suite-dir",
                            str(args.suite_dir),
                            "--config-json-file",
                            str(config_path),
                        ]
                    )
                )
            verify_suite(args.suite_dir, args.suite_revision)
        except BaseException as error:
            cleanup_errors.append(error)
        state_file = args.work_dir / "oidf-onboarding-state.json"
        if state_file.exists():
            try:
                with onboarding_credentials_fd(secrets) as descriptor:
                    onboarding.cleanup_onboarding(
                        onboarding_args("cleanup", args.work_dir, args.target_issuer, descriptor)
                    )
                cleanup_complete = True
            except BaseException as error:
                cleanup_errors.append(error)
        else:
            cleanup_complete = True
        if args.active_lease_id is not None:
            try:
                revoke_conformance_lease(args, args.active_lease_id)
            except BaseException as error:
                cleanup_complete = False
                cleanup_errors.append(error)
        try:
            manifest_path = sanitize_evidence_tree(args.export_dir)
            if manifest_path is None and failure is None:
                fail("successful OpenID4VC matrix produced no evidence archive")
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            delete_private_configs(args.work_dir)
            protect_directory(args.work_dir)
            protect_directory(args.export_dir)
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            write_receipt(
                args,
                outcome="PASSED" if failure is None and not cleanup_errors else "FAILED",
                cleanup_complete=cleanup_complete,
                manifest_path=manifest_path,
            )
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            os.umask(previous_umask)
            signal.signal(signal.SIGINT, previous_sigint)
            signal.signal(signal.SIGTERM, previous_sigterm)
        if cleanup_errors:
            raise ExceptionGroup("host-local OpenID4VC cleanup failed", cleanup_errors) from failure
    if failure is not None:
        raise failure


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument("--deployed-source-dir", type=Path)
    parser.add_argument("--runner-sha")
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--conformance-server", required=True)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--run-namespace", required=True)
    parser.add_argument(
        "--prepared-install-dir",
        type=Path,
        required=True,
        help="source-bound output from prepare_host_local_oidf_install.py",
    )
    parser.add_argument("--nazoauthctl", type=Path, required=True)
    parser.add_argument("--nazoauthctl-config", type=Path)
    add_candidate_target_arguments(parser)
    parser.add_argument("--lease-ttl-seconds", type=int, default=28_800)
    parser.add_argument(
        "--request-object-trust-anchor-pem",
        type=Path,
        required=True,
        help="public regular PEM certificate file used to verify VP request objects",
    )
    secret = parser.add_mutually_exclusive_group(required=True)
    secret.add_argument("--secrets-stdin", action="store_true")
    secret.add_argument("--secret-fd", type=int)
    parser.add_argument("--plan-group-size", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=int, default=4800)
    parser.add_argument("--monitor-interval-seconds", type=int, default=10)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args(argv))
    except (
        HostLocalOpenid4vcError,
        ConformanceLeaseControlError,
        PublicRunError,
        SecretInputError,
        onboarding.OnboardingError,
        applicant_provisioning.ProvisioningError,
        InterruptedError,
        subprocess.CalledProcessError,
    ) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
