#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
IN_TOTO = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPES = {
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
}
ATTESTATION_TYPE = "attestation-manifest"
ATTESTATION_PREDICATES = {
    "https://spdx.dev/Document",
    "https://slsa.dev/provenance/v1",
}
PLATFORMS = {"linux/amd64", "linux/arm64"}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024


class OciValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise OciValidationError(message)


def _closed_object(value: Any, required: set[str], allowed: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(allowed):
        _fail(f"{name} has an unexpected closed schema")
    return value


def _bounded_string(value: Any, name: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(f"{name} must be a non-empty bounded string")
    return value


def _annotations(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 128:
        _fail(f"{name} must be a bounded string map")
    result: dict[str, str] = {}
    for key, item in value.items():
        result[_bounded_string(key, f"{name} key", 256)] = _bounded_string(
            item, f"{name}.{key}", 4096
        )
    return result


def _json_object(payload: bytes, name: str) -> dict[str, Any]:
    if len(payload) > MAX_JSON_BYTES:
        _fail(f"{name} exceeds the bounded JSON size")

    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"{name} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=closed_pairs,
            parse_constant=lambda constant: _fail(
                f"{name} contains non-finite JSON value {constant}"
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"{name} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{name} must be a JSON object")
    return value


def _json_file(path: Path, name: str) -> dict[str, Any]:
    with path.open("rb") as source:
        payload = source.read(MAX_JSON_BYTES + 1)
    return _json_object(payload, name)


def extract_archive(archive: Path, layout: Path) -> Path:
    if not archive.is_file() or archive.is_symlink():
        _fail("OCI candidate must be one regular non-symlink archive")
    if not layout.is_dir() or layout.is_symlink():
        _fail("OCI extraction destination must be a regular directory")
    layout = layout.resolve(strict=True)
    if any(layout.iterdir()):
        _fail("OCI extraction directory must start empty")

    try:
        source = tarfile.open(archive, mode="r:*")
    except (OSError, tarfile.TarError) as error:
        _fail(f"OCI candidate is not a readable tar archive: {error}")
    with source:
        members = source.getmembers()
        if not members:
            _fail("OCI archive is empty")
        if len(members) > MAX_ARCHIVE_MEMBERS:
            _fail("OCI archive contains too many members")
        total_size = 0
        seen: set[str] = set()
        normalized_members: list[tuple[tarfile.TarInfo, str]] = []
        for member in members:
            path = PurePosixPath(member.name)
            parts = tuple(part for part in path.parts if part not in ("", "."))
            if (
                path.is_absolute()
                or not parts
                or ".." in parts
                or "\\" in member.name
                or not (member.isfile() or member.isdir())
            ):
                _fail(f"unsafe OCI archive member: {member.name!r}")
            normalized = PurePosixPath(*parts).as_posix()
            if member.name not in {normalized, f"{normalized}/"}:
                _fail(f"non-canonical OCI archive member: {member.name!r}")
            if normalized in seen:
                _fail(f"duplicate OCI archive member: {normalized}")
            seen.add(normalized)
            if member.isfile():
                if member.size < 0:
                    _fail(f"OCI archive member has a negative size: {member.name!r}")
                total_size += member.size
                if total_size > MAX_ARCHIVE_BYTES:
                    _fail("OCI archive expands beyond the bounded size")
            normalized_members.append((member, normalized))

        for member, normalized in normalized_members:
            destination = layout.joinpath(*PurePosixPath(normalized).parts)
            try:
                destination.relative_to(layout)
            except ValueError:
                _fail(f"OCI archive member escapes extraction root: {member.name!r}")
            if member.isdir():
                if destination.exists() and not destination.is_dir():
                    _fail(f"OCI archive directory collides with a file: {member.name!r}")
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                _fail(f"OCI archive file collides with an existing path: {member.name!r}")
            extracted = source.extractfile(member)
            if extracted is None:
                _fail(f"OCI archive member cannot be read: {member.name!r}")
            with extracted, destination.open("xb") as output:
                shutil.copyfileobj(extracted, output, length=1024 * 1024)
            if destination.stat().st_size != member.size:
                _fail(f"OCI archive member size changed during extraction: {member.name!r}")
    return layout


class Layout:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.blob_root = root / "blobs" / "sha256"
        self.blobs: dict[str, tuple[Path, int]] = {}
        self.referenced: set[str] = set()

    @classmethod
    def load(cls, root: Path) -> "Layout":
        if {entry.name for entry in root.iterdir()} != {"blobs", "index.json", "oci-layout"}:
            _fail("OCI layout has unexpected root entries")
        for entry in root.rglob("*"):
            if entry.is_symlink():
                _fail(f"OCI layout contains a symbolic link: {entry}")

        metadata = _json_file(root / "oci-layout", "OCI layout metadata")
        if metadata != {"imageLayoutVersion": "1.0.0"}:
            _fail("OCI layout metadata is not the closed 1.0.0 schema")

        layout = cls(root)
        if not layout.blob_root.is_dir():
            _fail("OCI layout has no sha256 blob directory")
        for entry in root.rglob("*"):
            if entry.is_dir():
                if entry not in {root / "blobs", layout.blob_root}:
                    _fail(f"OCI layout contains an unexpected directory: {entry}")
                continue
            if entry in {root / "index.json", root / "oci-layout"}:
                continue
            if not entry.is_file() or entry.parent != layout.blob_root or not HEX_SHA256.fullmatch(entry.name):
                _fail(f"OCI layout contains an unexpected file: {entry}")
            digest = hashlib.sha256()
            size = 0
            with entry.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if digest.hexdigest() != entry.name:
                _fail(f"OCI blob digest mismatch: {entry.name}")
            layout.blobs[f"sha256:{entry.name}"] = (entry, size)
        return layout

    def descriptor(self, value: Any, name: str) -> dict[str, Any]:
        descriptor = _closed_object(
            value,
            {"mediaType", "digest", "size"},
            {"mediaType", "digest", "size", "annotations", "artifactType", "platform"},
            name,
        )
        _bounded_string(descriptor["mediaType"], f"{name}.mediaType", 256)
        digest = descriptor["digest"]
        size = descriptor["size"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            _fail(f"{name}.digest must be a lowercase sha256 digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _fail(f"{name}.size must be a non-negative integer")
        blob = self.blobs.get(digest)
        if blob is None or blob[1] != size:
            _fail(f"{name} is not digest-and-size bound to one local blob: {digest}")
        if "annotations" in descriptor:
            _annotations(descriptor["annotations"], f"{name}.annotations")
        if "artifactType" in descriptor:
            _bounded_string(descriptor["artifactType"], f"{name}.artifactType", 256)
        self.referenced.add(digest)
        return descriptor

    def json_blob(self, digest: str, name: str) -> dict[str, Any]:
        blob = self.blobs.get(digest)
        if blob is None:
            _fail(f"{name} does not resolve to a local blob: {digest}")
        if blob[1] > MAX_JSON_BYTES:
            _fail(f"{name} exceeds the bounded JSON size")
        return _json_file(blob[0], name)

    def close(self) -> None:
        orphaned = set(self.blobs) - self.referenced
        if orphaned:
            _fail(
                "OCI layout contains unreferenced blobs: "
                + ", ".join(sorted(orphaned))
            )


def _index(value: Any, name: str) -> dict[str, Any]:
    index = _closed_object(
        value,
        {"schemaVersion", "mediaType", "manifests"},
        {"schemaVersion", "mediaType", "manifests", "annotations"},
        name,
    )
    if index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX:
        _fail(f"{name} is not an OCI image index")
    if not isinstance(index["manifests"], list) or not index["manifests"]:
        _fail(f"{name}.manifests must be a non-empty list")
    if "annotations" in index:
        _annotations(index["annotations"], f"{name}.annotations")
    return index


def _platform(value: Any, name: str) -> str:
    platform = _closed_object(value, {"os", "architecture"}, {"os", "architecture"}, name)
    operating_system = _bounded_string(platform["os"], f"{name}.os", 64)
    architecture = _bounded_string(platform["architecture"], f"{name}.architecture", 64)
    return f"{operating_system}/{architecture}"


def _manifest(
    layout: Layout,
    descriptor: dict[str, Any],
    name: str,
    *,
    platform: str,
    attestation: bool,
    attested_image_digest: str | None = None,
) -> None:
    manifest = _closed_object(
        layout.json_blob(descriptor["digest"], name),
        {"schemaVersion", "mediaType", "config", "layers"},
        {"schemaVersion", "mediaType", "config", "layers"},
        name,
    )
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
        _fail(f"{name} is not an OCI image manifest")
    config = layout.descriptor(manifest["config"], f"{name}.config")
    if config["mediaType"] != OCI_CONFIG or set(config) != {"mediaType", "digest", "size"}:
        _fail(f"{name}.config is not an OCI image config descriptor")
    operating_system, architecture = platform.split("/", 1)
    config_document = layout.json_blob(config["digest"], f"{name}.config document")
    if (
        config_document.get("os") != operating_system
        or config_document.get("architecture") != architecture
    ):
        _fail(f"{name}.config document does not match its index platform")
    layers = manifest["layers"]
    if not isinstance(layers, list) or not layers:
        _fail(f"{name}.layers must be a non-empty list")

    predicates: set[str] = set()
    for position, value in enumerate(layers):
        layer = layout.descriptor(value, f"{name}.layers[{position}]")
        if "platform" in layer or "artifactType" in layer:
            _fail(f"{name}.layers[{position}] contains unsupported routing metadata")
        if not attestation:
            if layer["mediaType"] != OCI_LAYER_GZIP or "annotations" in layer:
                _fail(f"{name}.layers[{position}] is not the expected image layer")
            continue
        if layer["mediaType"] != IN_TOTO:
            _fail(f"{name}.layers[{position}] is not an in-toto attestation layer")
        annotations = layer.get("annotations")
        if not isinstance(annotations, dict) or set(annotations) != {"in-toto.io/predicate-type"}:
            _fail(f"{name}.layers[{position}] lacks the closed BuildKit predicate annotation")
        predicate_type = annotations["in-toto.io/predicate-type"]
        if predicate_type not in ATTESTATION_PREDICATES or predicate_type in predicates:
            _fail(f"{name}.layers[{position}] has an unexpected or duplicate predicate")
        statement = _closed_object(
            layout.json_blob(layer["digest"], f"{name}.layers[{position}] statement"),
            {"_type", "predicateType", "subject", "predicate"},
            {"_type", "predicateType", "subject", "predicate"},
            f"{name}.layers[{position}] statement",
        )
        if statement["_type"] not in IN_TOTO_STATEMENT_TYPES:
            _fail(
                f"{name}.layers[{position}] has unsupported in-toto statement type "
                f"{statement['_type']!r}"
            )
        if statement["predicateType"] != predicate_type:
            _fail(f"{name}.layers[{position}] predicate does not match its descriptor")
        if not isinstance(statement["predicate"], dict):
            _fail(f"{name}.layers[{position}] predicate is not an object")
        subjects = statement["subject"]
        if (
            attested_image_digest is None
            or not isinstance(subjects, list)
            or not subjects
        ):
            _fail(f"{name}.layers[{position}] must bind image-manifest subjects")
        # BuildKit may emit more than one name for the same output.  Names are
        # aliases only: every declared subject must bind the referenced image.
        for subject_position, value in enumerate(subjects):
            subject_name = f"{name}.layers[{position}] subjects[{subject_position}]"
            subject = _closed_object(
                value,
                {"name", "digest"},
                {"name", "digest"},
                subject_name,
            )
            _bounded_string(subject["name"], f"{subject_name}.name", 4096)
            digest = _closed_object(
                subject["digest"],
                {"sha256"},
                {"sha256"},
                f"{subject_name}.digest",
            )
            if digest["sha256"] != attested_image_digest.removeprefix("sha256:"):
                _fail(
                    f"{name}.layers[{position}] subject does not bind its image manifest "
                    f"at position {subject_position}"
                )
        predicates.add(predicate_type)
    if attestation and predicates != ATTESTATION_PREDICATES:
        _fail(f"{name} must bind exactly the configured SBOM and provenance predicates")


def validate_layout(root: Path, expected_index_digest: str, repository: str) -> dict[str, Any]:
    if not SHA256.fullmatch(expected_index_digest):
        _fail("expected index digest must be a lowercase sha256 digest")
    repository = _bounded_string(repository, "repository", 512)
    layout = Layout.load(root)
    root_index = _index(
        _json_file(root / "index.json", "OCI layout root index"),
        "OCI layout root index",
    )
    if len(root_index["manifests"]) != 1:
        _fail("OCI layout root index must contain exactly one release index descriptor")
    release_descriptor = layout.descriptor(
        root_index["manifests"][0], "OCI layout root release descriptor"
    )
    if (
        release_descriptor["mediaType"] != OCI_INDEX
        or release_descriptor["digest"] != expected_index_digest
        or "platform" in release_descriptor
        or "artifactType" in release_descriptor
    ):
        _fail("OCI layout root does not bind the expected Buildx release index digest")

    release_index = _index(
        layout.json_blob(expected_index_digest, "OCI release index"),
        "OCI release index",
    )
    if len(release_index["manifests"]) != 4:
        _fail("OCI release index must contain exactly two images and two attestations")

    images: dict[str, dict[str, Any]] = {}
    attestations: dict[str, dict[str, Any]] = {}
    attestation_digests: set[str] = set()
    for position, value in enumerate(release_index["manifests"]):
        descriptor = layout.descriptor(value, f"OCI release descriptor[{position}]")
        if descriptor["mediaType"] != OCI_MANIFEST or "artifactType" in descriptor:
            _fail(f"OCI release descriptor[{position}] is not an image manifest descriptor")
        platform = _platform(descriptor.get("platform"), f"OCI release descriptor[{position}].platform")
        annotations = descriptor.get("annotations")
        if platform in PLATFORMS:
            if annotations is not None or platform in images:
                _fail(f"OCI release index has duplicate or annotated image platform {platform}")
            images[platform] = descriptor
            continue
        if platform != "unknown/unknown" or not isinstance(annotations, dict):
            _fail(f"OCI release index contains unsupported platform {platform}")
        if set(annotations) != {"vnd.docker.reference.digest", "vnd.docker.reference.type"}:
            _fail("BuildKit attestation descriptor has unexpected annotations")
        referenced_image = annotations["vnd.docker.reference.digest"]
        if (
            annotations["vnd.docker.reference.type"] != ATTESTATION_TYPE
            or not isinstance(referenced_image, str)
            or not SHA256.fullmatch(referenced_image)
            or referenced_image in attestations
            or descriptor["digest"] in attestation_digests
        ):
            _fail(
                "BuildKit attestation descriptors must uniquely reference one image "
                "and one attestation manifest"
            )
        attestations[referenced_image] = descriptor
        attestation_digests.add(descriptor["digest"])

    if set(images) != PLATFORMS:
        _fail("OCI release index must contain exactly linux/amd64 and linux/arm64 images")
    image_digests = {descriptor["digest"] for descriptor in images.values()}
    if set(attestations) != image_digests:
        _fail("OCI release index must contain one BuildKit attestation per image manifest")

    for platform, descriptor in images.items():
        _manifest(
            layout,
            descriptor,
            f"OCI {platform} image manifest",
            platform=platform,
            attestation=False,
            attested_image_digest=None,
        )
        _manifest(
            layout,
            attestations[descriptor["digest"]],
            f"OCI {platform} BuildKit attestation manifest",
            platform="unknown/unknown",
            attestation=True,
            attested_image_digest=descriptor["digest"],
        )
    layout.close()
    return {
        "repository": repository,
        "index_digest": expected_index_digest,
        "platform_manifests": {
            platform: images[platform]["digest"] for platform in sorted(images)
        },
    }


def validate_archive(
    archive: Path,
    layout: Path,
    expected_index_digest: str,
    repository: str,
) -> dict[str, Any]:
    return validate_layout(
        extract_archive(archive, layout), expected_index_digest, repository
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        descriptor = validate_archive(
            args.archive,
            args.layout,
            args.expected_index_digest,
            args.repository,
        )
        if args.output.exists() and args.output.is_symlink():
            _fail("OCI descriptor output must not be a symbolic link")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(descriptor, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, OciValidationError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
