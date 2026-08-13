from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from scripts import validate_release_oci as validator


REPOSITORY = "ghcr.io/nazozero/nazoauth"


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class OciFixture:
    def __init__(
        self, statement_type: str = "https://in-toto.io/Statement/v1"
    ) -> None:
        self.blobs: dict[str, bytes] = {}
        self.images: dict[str, str] = {}
        self.release_descriptors: list[dict[str, Any]] = []
        self.statement_type = statement_type
        for architecture in ("amd64", "arm64"):
            self._add_platform(architecture)

    def blob(self, payload: bytes | dict[str, Any]) -> tuple[str, int]:
        if isinstance(payload, dict):
            payload = json_bytes(payload)
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.blobs[digest] = payload
        return digest, len(payload)

    @staticmethod
    def descriptor(media_type: str, blob: tuple[str, int], **extra: Any) -> dict[str, Any]:
        digest, size = blob
        return {"mediaType": media_type, "digest": digest, "size": size, **extra}

    def _add_platform(self, architecture: str) -> None:
        config = self.descriptor(
            validator.OCI_CONFIG,
            self.blob({"os": "linux", "architecture": architecture}),
        )
        layer = self.descriptor(
            validator.OCI_LAYER_GZIP,
            self.blob(f"image-layer-{architecture}".encode("ascii")),
        )
        manifest = {
            "schemaVersion": 2,
            "mediaType": validator.OCI_MANIFEST,
            "config": config,
            "layers": [layer],
        }
        image = self.descriptor(
            validator.OCI_MANIFEST,
            self.blob(manifest),
            platform={"os": "linux", "architecture": architecture},
        )
        self.images[architecture] = image["digest"]
        self.release_descriptors.append(image)

        attestation_layers = []
        for predicate_type in sorted(validator.ATTESTATION_PREDICATES):
            statement = {
                "_type": self.statement_type,
                "predicateType": predicate_type,
                "subject": [
                    {
                        "name": f"pkg:docker/{REPOSITORY}?platform=linux/{architecture}",
                        "digest": {
                            "sha256": image["digest"].removeprefix("sha256:")
                        },
                    }
                ],
                "predicate": {"fixture": architecture},
            }
            attestation_layers.append(
                self.descriptor(
                    validator.IN_TOTO,
                    self.blob(statement),
                    annotations={"in-toto.io/predicate-type": predicate_type},
                )
            )
        attestation = {
            "schemaVersion": 2,
            "mediaType": validator.OCI_MANIFEST,
            "config": self.descriptor(
                validator.OCI_CONFIG,
                self.blob(
                    {
                        "os": "unknown",
                        "architecture": "unknown",
                        "config": {},
                    }
                ),
            ),
            "layers": attestation_layers,
        }
        self.release_descriptors.append(
            self.descriptor(
                validator.OCI_MANIFEST,
                self.blob(attestation),
                annotations={
                    "vnd.docker.reference.digest": image["digest"],
                    "vnd.docker.reference.type": validator.ATTESTATION_TYPE,
                },
                platform={"os": "unknown", "architecture": "unknown"},
            )
        )

    def mismatch_image_config_platform(self, architecture: str) -> None:
        image = next(
            descriptor
            for descriptor in self.release_descriptors
            if descriptor.get("platform") == {"os": "linux", "architecture": architecture}
        )
        previous_digest = image["digest"]
        manifest = json.loads(self.blobs[previous_digest])
        manifest["config"] = self.descriptor(
            validator.OCI_CONFIG,
            self.blob(
                {
                    "os": "linux",
                    "architecture": "arm64" if architecture == "amd64" else "amd64",
                }
            ),
        )
        replacement_digest, replacement_size = self.blob(manifest)
        image["digest"] = replacement_digest
        image["size"] = replacement_size
        self.images[architecture] = replacement_digest
        for descriptor in self.release_descriptors:
            annotations = descriptor.get("annotations")
            if isinstance(annotations, dict) and annotations.get(
                "vnd.docker.reference.digest"
            ) == previous_digest:
                annotations["vnd.docker.reference.digest"] = replacement_digest

    def mismatch_attestation_subject(
        self, architecture: str, subject_position: int = 0
    ) -> None:
        image_digest = self.images[architecture]
        descriptor = next(
            item
            for item in self.release_descriptors
            if item.get("annotations", {}).get("vnd.docker.reference.digest") == image_digest
        )
        manifest = json.loads(self.blobs[descriptor["digest"]])
        layer = manifest["layers"][0]
        statement = json.loads(self.blobs[layer["digest"]])
        statement["subject"][subject_position]["digest"]["sha256"] = "0" * 64
        layer["digest"], layer["size"] = self.blob(statement)
        descriptor["digest"], descriptor["size"] = self.blob(manifest)

    def add_attestation_subject_alias(self, architecture: str) -> None:
        image_digest = self.images[architecture]
        descriptor = next(
            item
            for item in self.release_descriptors
            if item.get("annotations", {}).get("vnd.docker.reference.digest") == image_digest
        )
        previous_manifest_digest = descriptor["digest"]
        manifest = json.loads(self.blobs[previous_manifest_digest])
        for layer in manifest["layers"]:
            previous_layer_digest = layer["digest"]
            statement = json.loads(self.blobs[previous_layer_digest])
            alias = json.loads(json.dumps(statement["subject"][0]))
            alias["name"] += "&alias=release"
            statement["subject"].append(alias)
            layer["digest"], layer["size"] = self.blob(statement)
            del self.blobs[previous_layer_digest]
        descriptor["digest"], descriptor["size"] = self.blob(manifest)
        del self.blobs[previous_manifest_digest]

    def write(
        self,
        archive: Path,
        *,
        mutate_release: Callable[[list[dict[str, Any]]], None] | None = None,
        mutate_root: Callable[[dict[str, Any]], None] | None = None,
        orphan: bool = False,
    ) -> str:
        release_descriptors = json.loads(json.dumps(self.release_descriptors))
        if mutate_release is not None:
            mutate_release(release_descriptors)
        release_index = {
            "schemaVersion": 2,
            "mediaType": validator.OCI_INDEX,
            "manifests": release_descriptors,
        }
        release_blob = self.blob(release_index)
        root = {
            "schemaVersion": 2,
            "mediaType": validator.OCI_INDEX,
            "manifests": [
                self.descriptor(
                    validator.OCI_INDEX,
                    release_blob,
                    annotations={"org.opencontainers.image.created": "fixture"},
                )
            ],
        }
        if mutate_root is not None:
            mutate_root(root)
        if orphan:
            self.blob(b"not-referenced")

        with tarfile.open(archive, "w") as output:
            self._tar_file(output, "oci-layout", json_bytes({"imageLayoutVersion": "1.0.0"}))
            self._tar_file(output, "index.json", json_bytes(root))
            for digest, payload in sorted(self.blobs.items()):
                self._tar_file(output, f"blobs/sha256/{digest.removeprefix('sha256:')}", payload)
        return release_blob[0]

    @staticmethod
    def _tar_file(output: tarfile.TarFile, name: str, payload: bytes) -> None:
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        member.mode = 0o644
        output.addfile(member, io.BytesIO(payload))


class ReleaseOciTests(unittest.TestCase):
    def validate(self, archive: Path, expected: str, root: Path) -> dict[str, Any]:
        layout = root / "layout"
        layout.mkdir()
        return validator.validate_archive(archive, layout, expected, REPOSITORY)

    def test_accepts_nested_buildx_index_and_emits_existing_descriptor_schema(self) -> None:
        for statement_type in sorted(validator.IN_TOTO_STATEMENT_TYPES):
            with self.subTest(statement_type=statement_type), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "candidate.oci.tar"
                fixture = OciFixture(statement_type)
                expected = fixture.write(archive)

                descriptor = self.validate(archive, expected, root)

                self.assertEqual(
                    descriptor,
                    {
                        "repository": REPOSITORY,
                        "index_digest": expected,
                        "platform_manifests": {
                            "linux/amd64": fixture.images["amd64"],
                            "linux/arm64": fixture.images["arm64"],
                        },
                    },
                )

    def test_rejects_unreviewed_in_toto_statement_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            fixture = OciFixture("https://in-toto.io/Statement/v2")
            expected = fixture.write(archive)

            with self.assertRaisesRegex(
                validator.OciValidationError,
                "unsupported in-toto statement type",
            ):
                self.validate(archive, expected, root)

    def test_binds_buildx_digest_to_the_single_root_release_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            expected = OciFixture().write(archive)

            with self.assertRaisesRegex(
                validator.OciValidationError,
                "does not bind the expected Buildx release index digest",
            ):
                self.validate(archive, "sha256:" + "0" * 64, root)
            self.assertRegex(expected, r"^sha256:[0-9a-f]{64}$")

    def test_rejects_descriptor_size_mismatch_and_unreferenced_blob(self) -> None:
        cases = {
            "size": dict(
                mutate_root=lambda root: root["manifests"][0].__setitem__(
                    "size", root["manifests"][0]["size"] + 1
                ),
                error="not digest-and-size bound",
            ),
            "orphan": dict(orphan=True, error="unreferenced blobs"),
        }
        for name, options in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "candidate.oci.tar"
                expected = OciFixture().write(
                    archive,
                    mutate_root=options.get("mutate_root"),
                    orphan=bool(options.get("orphan")),
                )
                with self.assertRaisesRegex(validator.OciValidationError, options["error"]):
                    self.validate(archive, expected, root)

    def test_rejects_missing_or_misdirected_buildkit_attestation(self) -> None:
        def remove_attestation(descriptors: list[dict[str, Any]]) -> None:
            descriptors.pop()

        def redirect_attestation(descriptors: list[dict[str, Any]]) -> None:
            attestations = [item for item in descriptors if item["platform"]["os"] == "unknown"]
            attestations[1]["annotations"]["vnd.docker.reference.digest"] = attestations[0][
                "annotations"
            ]["vnd.docker.reference.digest"]

        def reuse_attestation_manifest(descriptors: list[dict[str, Any]]) -> None:
            attestations = [item for item in descriptors if item["platform"]["os"] == "unknown"]
            attestations[1]["digest"] = attestations[0]["digest"]
            attestations[1]["size"] = attestations[0]["size"]

        cases = {
            "missing": (remove_attestation, "exactly two images and two attestations"),
            "redirected": (redirect_attestation, "must uniquely reference one image"),
            "reused-manifest": (
                reuse_attestation_manifest,
                "and one attestation manifest",
            ),
        }
        for name, (mutation, error) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "candidate.oci.tar"
                expected = OciFixture().write(archive, mutate_release=mutation)
                with self.assertRaisesRegex(validator.OciValidationError, error):
                    self.validate(archive, expected, root)

    def test_rejects_image_config_that_disagrees_with_index_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            fixture = OciFixture()
            fixture.mismatch_image_config_platform("amd64")
            expected = fixture.write(archive)

            with self.assertRaisesRegex(
                validator.OciValidationError,
                "config document does not match its index platform",
            ):
                self.validate(archive, expected, root)

    def test_rejects_attestation_subject_for_another_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            fixture = OciFixture()
            fixture.mismatch_attestation_subject("amd64")
            expected = fixture.write(archive)

            with self.assertRaisesRegex(
                validator.OciValidationError,
                "subject does not bind its image manifest",
            ):
                self.validate(archive, expected, root)

    def test_accepts_multiple_names_only_when_every_subject_binds_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            fixture = OciFixture()
            fixture.add_attestation_subject_alias("amd64")
            expected = fixture.write(archive)

            descriptor = self.validate(archive, expected, root)

            self.assertEqual(
                descriptor["platform_manifests"]["linux/amd64"],
                fixture.images["amd64"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "candidate.oci.tar"
            fixture = OciFixture()
            fixture.add_attestation_subject_alias("amd64")
            fixture.mismatch_attestation_subject("amd64", subject_position=1)
            expected = fixture.write(archive)
            with self.assertRaisesRegex(
                validator.OciValidationError,
                "subject does not bind its image manifest at position 1",
            ):
                self.validate(archive, expected, root)

    def test_rejects_unsafe_tar_members_before_extraction(self) -> None:
        cases = {
            "traversal": ("../escape", tarfile.REGTYPE),
            "symlink": ("index.json", tarfile.SYMTYPE),
        }
        for name, (member_name, member_type) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "candidate.oci.tar"
                member = tarfile.TarInfo(member_name)
                member.type = member_type
                member.linkname = "outside"
                with tarfile.open(archive, "w") as output:
                    output.addfile(member)
                layout = root / "layout"
                layout.mkdir()
                with self.assertRaisesRegex(validator.OciValidationError, "unsafe OCI archive member"):
                    validator.extract_archive(archive, layout)
                self.assertEqual(list(layout.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
