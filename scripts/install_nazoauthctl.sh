#!/bin/sh
set -eu

repository="nazozero/NazoAuth"
version=""
install_path="/usr/local/sbin/nazoauthctl"
predicate_type="https://nazo.run/attestations/release-manifest/v1"
cosign_image="ghcr.io/sigstore/cosign/cosign@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository) repository="${2:?--repository requires OWNER/NAME}"; shift 2 ;;
    --version) version="${2:?--version requires vMAJOR.MINOR.PATCH}"; shift 2 ;;
    --install-path) install_path="${2:?--install-path requires an absolute path}"; shift 2 ;;
    *) printf '%s\n' "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$repository" in
  *[!A-Za-z0-9._/-]*|*/*/*|/*|*/|'')
    printf '%s\n' 'repository must be one safe OWNER/NAME pair' >&2
    exit 2
    ;;
esac
case "$install_path" in
  /|*/|*//*|*/./*|*/../*|*[!A-Za-z0-9._/-]*)
    printf '%s\n' 'unsafe install path' >&2
    exit 2
    ;;
  /*) ;;
  *) printf '%s\n' 'install path must be absolute' >&2; exit 2 ;;
esac

for dependency in curl python3 sha256sum install; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf '%s\n' "$dependency is required for verified bootstrap" >&2
    exit 1
  fi
done

umask 077
temporary="$(mktemp -d "${TMPDIR:-/tmp}/nazoauthctl-bootstrap.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

validate_effective_url() {
  python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import urlsplit

value = urlsplit(sys.argv[1])
kind = sys.argv[2]
allowed = {
    "api": {"api.github.com"},
    "asset": {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    },
}[kind]
if (
    value.scheme != "https"
    or value.hostname not in allowed
    or value.username is not None
    or value.password is not None
    or value.port not in (None, 443)
):
    raise SystemExit("HTTPS redirect escaped the closed GitHub host allowlist")
PY
}

download_https() {
  url=$1
  output=$2
  maximum=$3
  host_kind=$4
  effective="$({
    curl \
      --fail \
      --silent \
      --show-error \
      --location \
      --proto '=https' \
      --proto-redir '=https' \
      --tlsv1.2 \
      --connect-timeout 10 \
      --max-time 45 \
      --max-filesize "$maximum" \
      --retry 2 \
      --retry-delay 1 \
      --retry-max-time 45 \
      --header 'Accept: application/vnd.github+json' \
      --header 'X-GitHub-Api-Version: 2022-11-28' \
      --output "$output" \
      --write-out '%{url_effective}' \
      "$url"
  })"
  validate_effective_url "$effective" "$host_kind"
  python3 - "$output" "$maximum" <<'PY'
import os
import sys

size = os.stat(sys.argv[1]).st_size
if size <= 0 or size > int(sys.argv[2]):
    raise SystemExit("downloaded response violated its closed size bound")
PY
}

if [ -z "$version" ]; then
  download_https \
    "https://api.github.com/repos/$repository/releases/latest" \
    "$temporary/latest.json" \
    1048576 \
    api
  version="$(python3 - "$temporary/latest.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as source:
    value = json.load(source)
version = value.get("tag_name") if isinstance(value, dict) else None
if not isinstance(version, str):
    raise SystemExit("GitHub latest Release response has no tag_name")
print(version)
PY
  )"
fi

semantic=${version#v}
major=${semantic%%.*}
remainder=${semantic#*.}
minor=${remainder%%.*}
patch=${remainder#*.}
if [ "$semantic" = "$version" ] || [ "$remainder" = "$semantic" ] || [ "$patch" = "$remainder" ]; then
  printf '%s\n' 'version must be an immutable vMAJOR.MINOR.PATCH tag' >&2
  exit 2
fi
for component in "$major" "$minor" "$patch"; do
  case "$component" in
    ''|*[!0-9]*|0[0-9]*)
      printf '%s\n' 'version must be an immutable vMAJOR.MINOR.PATCH tag' >&2
      exit 2
      ;;
  esac
done

case "$(uname -s)" in
  Linux) ;;
  *) printf '%s\n' 'managed bootstrap currently requires Linux' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) architecture=x86_64 ;;
  aarch64|arm64) architecture=aarch64 ;;
  *) printf '%s\n' 'unsupported Linux architecture' >&2; exit 1 ;;
esac
if command -v getconf >/dev/null 2>&1 && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
  libc=gnu
else
  libc=musl
fi
target="$architecture-unknown-linux-$libc"
artifact="nazoauthctl-$target"
artifact_path="$temporary/$artifact"
download_https \
  "https://github.com/$repository/releases/download/$version/$artifact" \
  "$artifact_path" \
  67108864 \
  asset
artifact_digest="$(sha256sum "$artifact_path")"
artifact_digest=${artifact_digest%% *}

encoded_predicate='https%3A%2F%2Fnazo.run%2Fattestations%2Frelease-manifest%2Fv1'
download_https \
  "https://api.github.com/repos/$repository/attestations/sha256%3A$artifact_digest?per_page=21&predicate_type=$encoded_predicate" \
  "$temporary/attestations.json" \
  10485760 \
  api

cat > "$temporary/verify_attestations.py" <<'PY'
from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterator

PREDICATE = "https://nazo.run/attestations/release-manifest/v1"
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
RUNNER_ENVIRONMENT_OID = "1.3.6.1.4.1.57264.1.11"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_BUILD_ID = re.compile(r"^[0-9A-Za-z.:_@/+\-]{1,256}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def closed(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{name} has an unexpected closed schema")
    return value


def bounded_string(value: Any, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        fail(f"{name} must be a non-empty bounded string")
    return value


def der_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        fail("Release attestation certificate is truncated")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        fail("Release attestation certificate has no DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            fail("Release attestation certificate has an invalid DER length")
        if data[offset] == 0:
            fail("Release attestation certificate has a non-canonical DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        if length < 128:
            fail("Release attestation certificate has a non-canonical DER length")
    end = offset + length
    if end > len(data):
        fail("Release attestation certificate is truncated")
    return tag, offset, end


def der_children(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int]]:
    cursor = start
    while cursor < end:
        tag, content, child_end = der_tlv(data, cursor)
        if child_end > end:
            fail("Release attestation certificate has an invalid DER child")
        yield tag, content, child_end
        cursor = child_end
    if cursor != end:
        fail("Release attestation certificate has trailing DER data")


def decode_oid(value: bytes) -> str:
    if not value:
        fail("Release attestation certificate has an empty extension OID")
    first = value[0]
    parts = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    active = False
    for byte in value[1:]:
        active = True
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
            active = False
    if active:
        fail("Release attestation certificate has a truncated extension OID")
    return ".".join(str(part) for part in parts)


def runner_environment(certificate: bytes) -> str:
    root_tag, root_content, root_end = der_tlv(certificate, 0)
    if root_tag != 0x30 or root_end != len(certificate):
        fail("Release attestation certificate is not one closed DER sequence")
    root_children = list(der_children(certificate, root_content, root_end))
    if not root_children or root_children[0][0] != 0x30:
        fail("Release attestation certificate has no TBSCertificate")
    _, tbs_content, tbs_end = root_children[0]
    values: list[str] = []
    for tag, content, end in der_children(certificate, tbs_content, tbs_end):
        if tag != 0xA3:
            continue
        sequence_tag, sequence_content, sequence_end = der_tlv(certificate, content)
        if sequence_tag != 0x30 or sequence_end != end:
            fail("Release attestation certificate has invalid extensions")
        for extension_tag, extension_content, extension_end in der_children(
            certificate, sequence_content, sequence_end
        ):
            if extension_tag != 0x30:
                fail("Release attestation certificate has an invalid extension")
            fields = list(der_children(certificate, extension_content, extension_end))
            if len(fields) not in (2, 3) or fields[0][0] != 0x06 or fields[-1][0] != 0x04:
                fail("Release attestation certificate has an invalid extension schema")
            oid = decode_oid(certificate[fields[0][1] : fields[0][2]])
            if oid != RUNNER_ENVIRONMENT_OID:
                continue
            value_tag, value_content, value_end = der_tlv(certificate, fields[-1][1])
            if value_tag != 0x0C or value_end != fields[-1][2]:
                fail("Release attestation runner environment is not canonical UTF-8")
            try:
                values.append(certificate[value_content:value_end].decode("utf-8"))
            except UnicodeDecodeError as error:
                fail(f"Release attestation runner environment is invalid UTF-8: {error}")
    if values != ["github-hosted"]:
        fail("Release attestation was not created by a GitHub-hosted runner")
    return values[0]


def artifact_descriptor(value: Any, name: str, repository: str) -> dict[str, Any]:
    descriptor = closed(value, {"repository", "name", "sha256", "size"}, name)
    if descriptor["repository"] != repository:
        fail(f"{name}.repository is outside the requested repository")
    artifact_name = bounded_string(descriptor["name"], f"{name}.name", 255)
    if Path(artifact_name).name != artifact_name or "/" in artifact_name or "\\" in artifact_name:
        fail(f"{name}.name is not a plain file name")
    if not isinstance(descriptor["sha256"], str) or not HEX64.fullmatch(descriptor["sha256"]):
        fail(f"{name}.sha256 is not lowercase SHA-256")
    if (
        not isinstance(descriptor["size"], int)
        or isinstance(descriptor["size"], bool)
        or descriptor["size"] <= 0
    ):
        fail(f"{name}.size is not a positive integer")
    return descriptor


def validate_manifest(
    value: Any,
    repository: str,
    version: str,
    target: str,
    identity: str,
    artifact_name: str,
    digest: str,
    size: int,
) -> dict[str, Any]:
    manifest = closed(
        value,
        {
            "schema",
            "version",
            "target",
            "backend_commit",
            "release_identity",
            "embedded",
            "artifacts",
            "frontend",
            "oci",
            "rollback",
        },
        "ReleaseManifest",
    )
    commit = manifest["backend_commit"]
    if (
        manifest["schema"] != 4
        or manifest["version"] != version
        or manifest["target"] != target
        or manifest["release_identity"] != identity
        or not isinstance(commit, str)
        or not HEX40.fullmatch(commit)
    ):
        fail("ReleaseManifest identity does not match the requested Release")
    embedded = closed(
        manifest["embedded"], {"release", "revision", "protocol", "build_id"}, "embedded identity"
    )
    if (
        embedded["release"] != version
        or embedded["revision"] != commit
        or embedded["protocol"] != 1
        or not isinstance(embedded["build_id"], str)
        or not SAFE_BUILD_ID.fullmatch(embedded["build_id"])
    ):
        fail("ReleaseManifest embedded identity is invalid")
    artifacts = closed(manifest["artifacts"], {"binary", "updater"}, "ReleaseManifest artifacts")
    artifact_descriptor(artifacts["binary"], "binary artifact", repository)
    updater = artifact_descriptor(artifacts["updater"], "updater artifact", repository)
    if updater["name"] != artifact_name or updater["sha256"] != digest or updater["size"] != size:
        fail("ReleaseManifest does not bind the downloaded updater")
    frontend = closed(
        manifest["frontend"],
        {"repository", "version", "commit", "release_identity", "artifact"},
        "frontend release",
    )
    bounded_string(frontend["repository"], "frontend.repository")
    bounded_string(frontend["version"], "frontend.version")
    if not isinstance(frontend["commit"], str) or not HEX40.fullmatch(frontend["commit"]):
        fail("frontend.commit is not a full lowercase Git commit")
    bounded_string(frontend["release_identity"], "frontend.release_identity")
    artifact_descriptor(frontend["artifact"], "frontend artifact", frontend["repository"])
    oci = closed(manifest["oci"], {"repository", "index_digest", "platform_manifests"}, "OCI release")
    bounded_string(oci["repository"], "oci.repository")
    if not isinstance(oci["index_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", oci["index_digest"]):
        fail("OCI index digest is invalid")
    platforms = closed(oci["platform_manifests"], {"linux/amd64", "linux/arm64"}, "OCI platforms")
    if any(not isinstance(item, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in platforms.values()):
        fail("OCI platform digest is invalid")
    rollback = closed(
        manifest["rollback"],
        {
            "artifact",
            "schema_compatible",
            "database_restore",
            "irreversible_migration",
            "minimum_supported_version",
            "migration_floor",
            "rationale",
        },
        "rollback policy",
    )
    if any(not isinstance(rollback[field], bool) for field in ("artifact", "schema_compatible", "irreversible_migration")):
        fail("rollback policy booleans are invalid")
    if rollback["database_restore"] not in {"backup", "pitr", "none"}:
        fail("rollback database_restore is invalid")
    if rollback["irreversible_migration"] and rollback["schema_compatible"]:
        fail("irreversible migration cannot claim schema-compatible rollback")
    if rollback["schema_compatible"] and not rollback["artifact"]:
        fail("schema-compatible rollback requires a retained artifact")
    bounded_string(rollback["minimum_supported_version"], "minimum_supported_version")
    bounded_string(rollback["migration_floor"], "migration_floor")
    bounded_string(rollback["rationale"], "rollback rationale")
    return manifest


def main() -> None:
    if len(sys.argv) != 9:
        fail("internal attestation verifier received the wrong argument count")
    response_path, artifact_path, repository, version, target, identity, digest, output_directory = sys.argv[1:]
    artifact = Path(artifact_path)
    output = Path(output_directory)
    with open(response_path, "r", encoding="utf-8") as source:
        response = closed(json.load(source), {"attestations"}, "GitHub attestation response")
    attestations = response["attestations"]
    if not isinstance(attestations, list) or not 1 <= len(attestations) <= 20:
        fail("GitHub returned no bounded Release attestation set")
    artifact_size = artifact.stat().st_size
    accepted: str | None = None
    records: list[tuple[str, str]] = []
    for index, item in enumerate(attestations):
        attestation = closed(item, {"bundle_url", "repository_id", "initiator", "bundle"}, "attestation")
        if (
            not isinstance(attestation["repository_id"], int)
            or isinstance(attestation["repository_id"], bool)
            or attestation["repository_id"] <= 0
        ):
            fail("GitHub returned invalid attestation repository metadata")
        bounded_string(attestation["bundle_url"], "attestation.bundle_url")
        bounded_string(attestation["initiator"], "attestation.initiator")
        bundle = closed(
            attestation["bundle"], {"mediaType", "verificationMaterial", "dsseEnvelope"}, "Sigstore bundle"
        )
        if bundle["mediaType"] != BUNDLE_MEDIA_TYPE:
            fail("GitHub returned an unsupported Sigstore bundle")
        material = closed(
            bundle["verificationMaterial"],
            {"tlogEntries", "timestampVerificationData", "certificate"},
            "Sigstore verification material",
        )
        certificate = closed(material["certificate"], {"rawBytes"}, "Sigstore certificate")
        try:
            certificate_bytes = base64.b64decode(certificate["rawBytes"], validate=True)
        except (TypeError, ValueError) as error:
            fail(f"Release attestation certificate is not canonical base64: {error}")
        runner_environment(certificate_bytes)
        envelope = closed(bundle["dsseEnvelope"], {"payload", "payloadType", "signatures"}, "DSSE envelope")
        if envelope["payloadType"] != "application/vnd.in-toto+json":
            fail("Release attestation DSSE payload type is invalid")
        try:
            statement_value = json.loads(base64.b64decode(envelope["payload"], validate=True))
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"Release attestation DSSE payload is invalid: {error}")
        statement = closed(statement_value, {"_type", "subject", "predicateType", "predicate"}, "in-toto statement")
        if statement["_type"] != "https://in-toto.io/Statement/v1" or statement["predicateType"] != PREDICATE:
            continue
        subjects = statement["subject"]
        if not isinstance(subjects, list) or not subjects:
            fail("Release attestation has no subject")
        subject_match = False
        for subject_value in subjects:
            subject = closed(subject_value, {"name", "digest"}, "in-toto subject")
            digest_map = closed(subject["digest"], {"sha256"}, "in-toto subject digest")
            if subject["name"] == artifact.name and digest_map["sha256"] == digest:
                subject_match = True
        if not subject_match:
            fail("Release attestation subject does not bind the downloaded updater")
        manifest = validate_manifest(
            statement["predicate"], repository, version, target, identity, artifact.name, digest, artifact_size
        )
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        if accepted is not None and canonical != accepted:
            fail("matching Release attestations contain conflicting predicates")
        accepted = canonical
        bundle_name = f"release-attestation-{index}.json"
        bundle_path = output / bundle_name
        with bundle_path.open("x", encoding="utf-8") as destination:
            json.dump(bundle, destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
        os.chmod(bundle_path, 0o600)
        records.append((bundle_name, manifest["backend_commit"]))
    if accepted is None or not records:
        fail("no Release attestation matched the requested target")
    records_path = output / "verified-attestation-candidates"
    with records_path.open("x", encoding="ascii") as destination:
        for bundle_name, commit in records:
            destination.write(f"{bundle_name} {commit}\n")
    os.chmod(records_path, 0o600)


if __name__ == "__main__":
    main()
PY

identity="https://github.com/$repository/.github/workflows/release-security.yml@refs/tags/$version"
python3 "$temporary/verify_attestations.py" \
  "$temporary/attestations.json" \
  "$artifact_path" \
  "$repository" \
  "$version" \
  "$target" \
  "$identity" \
  "$artifact_digest" \
  "$temporary"

if command -v podman >/dev/null 2>&1; then
  cosign_engine=podman
  cosign_mount="$temporary:/work:ro,Z"
elif command -v docker >/dev/null 2>&1; then
  cosign_engine=docker
  cosign_mount="$temporary:/work:ro"
elif command -v cosign >/dev/null 2>&1; then
  cosign_engine=cosign
else
  printf '%s\n' 'Podman, Docker, or a trusted local Cosign is required for verified bootstrap' >&2
  exit 1
fi

while IFS=' ' read -r bundle_name backend_commit; do
  if [ "$cosign_engine" = cosign ]; then
    cosign verify-blob-attestation \
      --bundle "$temporary/$bundle_name" \
      --type "$predicate_type" \
      --certificate-identity "$identity" \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      --certificate-github-workflow-repository "$repository" \
      --certificate-github-workflow-ref "refs/tags/$version" \
      --certificate-github-workflow-sha "$backend_commit" \
      --timeout 2m \
      "$artifact_path"
  else
    "$cosign_engine" run \
      --rm \
      --user 0:0 \
      --cap-drop ALL \
      --read-only \
      --security-opt no-new-privileges \
      --pids-limit 64 \
      --tmpfs /root/.sigstore:rw,noexec,nosuid,nodev,size=16m \
      -v "$cosign_mount" \
      "$cosign_image" \
      verify-blob-attestation \
      --bundle "/work/$bundle_name" \
      --type "$predicate_type" \
      --certificate-identity "$identity" \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      --certificate-github-workflow-repository "$repository" \
      --certificate-github-workflow-ref "refs/tags/$version" \
      --certificate-github-workflow-sha "$backend_commit" \
      --timeout 2m \
      "/work/$artifact"
  fi
done < "$temporary/verified-attestation-candidates"

install -o root -g root -m 0755 "$artifact_path" "$install_path"
"$install_path" --help >/dev/null
printf 'installed verified nazoauthctl %s at %s\n' "$version" "$install_path"
