from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UPDATER = ROOT / "deploy" / "update" / "nazoauthctl"
MANIFEST_BUILDER = ROOT / "scripts" / "build_release_manifest.py"


def bash() -> str:
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.exists() else "bash"


def bash_path(path: Path) -> str:
    if os.name != "nt":
        return path.as_posix()
    return subprocess.run(
        [bash(), "-lc", 'cygpath -u "$1"', "_", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class FakeUpdate:
    backend_commit = "b" * 40
    old_commit = "a" * 40
    old_image = "sha256:" + "1" * 64

    def __init__(self, root: Path) -> None:
        self.root = root
        self.release = root / "release"
        self.release.mkdir()
        self.fake_state = root / "state"
        self.fake_state.mkdir()
        self.fake_bin = root / "bin"
        self.fake_bin.mkdir()
        self.runtime = root / "runtime"
        self.keys = self.runtime / "keys"
        self.avatars = self.runtime / "avatars"
        self.keys.mkdir(parents=True)
        self.avatars.mkdir()
        (self.keys / "keyset.json").write_text("previous-keyset\n", encoding="utf-8")
        self.config_mount = root / "server.yaml"
        self.config_mount.write_text("server: {}\n", encoding="utf-8")
        self.ui_releases = root / "ui-releases"
        self.ui_releases.mkdir()
        self.old_ui = self.ui_releases / "old"
        self.old_ui.mkdir()
        (self.old_ui / "index.html").write_text("old-ui\n", encoding="utf-8")
        self.ui_path = root / "ui"
        subprocess.run(
            [
                bash(),
                "-lc",
                'export MSYS=winsymlinks:sys; ln -s "$1" "$2"',
                "_",
                bash_path(self.old_ui),
                bash_path(self.ui_path),
            ],
            check=True,
            capture_output=True,
        )
        self._write_release()
        self._write_fake_commands()
        self.config = root / "update.json"
        self.installed_updater = root / "installed" / "nazoauthctl"
        self.installed_updater.parent.mkdir()
        self.config.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "nazozero/NazoAuth",
                    "updater_install_path": bash_path(self.installed_updater),
                    "backup_root": bash_path(root / "backups"),
                    "deployment_root": bash_path(root / "deployments"),
                    "runtime": {
                        "engine": "podman",
                        "container_name": "nazo-oauth-server",
                        "network": "nazo_oauth_net",
                        "ip_address": "10.101.0.20",
                        "health_url": "http://10.101.0.20:8000/ready",
                        "readiness_attempts": 2,
                        "readiness_interval_seconds": 0,
                        "public_discovery_url": (
                            "https://issuer.example/.well-known/openid-configuration"
                        ),
                        "expected_issuer": "https://issuer.example",
                        "mounts": [
                            {
                                "source": bash_path(self.config_mount),
                                "target": "/app/.env.yaml",
                                "mode": "ro",
                            },
                            {
                                "source": bash_path(self.keys),
                                "target": "/var/lib/nazo_oauth/keys",
                                "mode": "rw",
                            },
                            {
                                "source": bash_path(self.avatars),
                                "target": "/var/lib/nazo_oauth/avatars",
                                "mode": "rw",
                            },
                        ],
                        "snapshot_paths": [bash_path(self.keys)],
                        "environment": {},
                    },
                    "postgres": {
                        "container_name": "postgres",
                        "database": "oauth",
                        "user": "nazoauth",
                        "validation_image": "postgres:18",
                    },
                    "valkey": {
                        "container_name": "valkey",
                        "rdb_path": "/data/dump.rdb",
                        "password_file": "",
                    },
                    "ui": {
                        "active_path": bash_path(self.ui_path),
                        "releases_root": bash_path(self.ui_releases),
                    },
                }
            ),
            encoding="utf-8",
        )
        for name, value in (
            ("revision", self.old_commit),
            ("image-id", self.old_image),
            ("image-name", "localhost/nazo-oauth-server:v0.9.0"),
            ("container-id", "old-container"),
            ("lastsave", "100"),
        ):
            (self.fake_state / name).write_text(value + "\n", encoding="utf-8")
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": str(self.fake_bin) + os.pathsep + self.env["PATH"],
                "FAKE_RELEASE": bash_path(self.release),
                "FAKE_STATE": bash_path(self.fake_state),
                "FAKE_BACKEND_COMMIT": self.backend_commit,
                "FAKE_OLD_COMMIT": self.old_commit,
                "FAKE_OLD_IMAGE": self.old_image,
                "NAZOAUTHCTL_TESTING": "1",
                "MSYS": "winsymlinks:sys",
            }
        )

    def _write_release(self) -> None:
        image = self.release / "nazo-oauth-server-image.tar"
        image.write_text("image\n", encoding="utf-8")
        binary = self.release / "nazoauth"
        binary.write_text("binary\n", encoding="utf-8")
        updater = self.release / "nazoauthctl"
        shutil.copyfile(UPDATER, updater)
        sbom = self.release / "nazoauth.cdx.json"
        sbom.write_text("{}\n", encoding="utf-8")
        ui_source = self.root / "ui-source"
        ui_source.mkdir()
        (ui_source / "index.html").write_text("new-ui\n", encoding="utf-8")
        ui = self.release / "nazoauth-ui.tar.gz"
        with tarfile.open(ui, "w:gz") as archive:
            archive.add(ui_source / "index.html", arcname="index.html")
        subprocess.run(
            [
                shutil.which("python") or "python",
                str(MANIFEST_BUILDER),
                "--version",
                "v1.0.0",
                "--backend-commit",
                self.backend_commit,
                "--frontend-commit",
                "c" * 40,
                "--image",
                str(image),
                "--ui",
                str(ui),
                "--binary",
                str(binary),
                "--updater",
                str(updater),
                "--sbom",
                str(sbom),
                "--policy",
                str(ROOT / "release" / "update-policy.json"),
                "--output",
                str(self.release / "release-manifest.json"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        (self.release / "release-manifest.json.bundle").write_text(
            "test-bundle\n", encoding="utf-8"
        )

    def _write_fake_commands(self) -> None:
        curl = self.fake_bin / "curl"
        curl.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
output=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[$i]}" = --output ]; then output="${args[$((i+1))]}"; fi
done
url="${args[$((${#args[@]}-1))]}"
if [[ "$url" == *"/releases/latest" ]]; then printf '%s\n' '{"tag_name":"v1.0.0"}'; exit 0; fi
if [[ "$url" == *"/releases/download/"* ]]; then
  cp -- "$FAKE_RELEASE/${url##*/}" "$output"
  exit 0
fi
if [[ "$url" == *"openid-configuration" ]]; then
  printf '%s\n' '{"issuer":"https://issuer.example"}'
  exit 0
fi
if [[ "$url" == *"/ready" ]]; then
  revision="$(cat "$FAKE_STATE/revision")"
  if [ "${FAIL_NEW_HEALTH:-0}" = 1 ] && [ "$revision" = "$FAKE_BACKEND_COMMIT" ]; then
    exit 22
  fi
  printf '%s\n' '{"status":"ready"}'
  exit 0
fi
exit 22
''',
            encoding="utf-8",
            newline="\n",
        )
        cosign = self.fake_bin / "cosign"
        cosign.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        podman = self.fake_bin / "podman"
        podman.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
state="$FAKE_STATE"
case "${1:-}" in
  inspect)
    args="$*"
    if [[ "$args" == *"org.opencontainers.image.revision"* ]]; then cat "$state/revision"
    elif [[ "$args" == *"{{.ImageName}}"* ]]; then cat "$state/image-name"
    elif [[ "$args" == *"{{.Image}}"* ]]; then cat "$state/image-id"
    elif [[ "$args" == *"{{.Id}}"* ]]; then cat "$state/container-id"
    else exit 1; fi
    ;;
  image)
    [ "${2:-}" = inspect ]
    cat "$state/candidate-revision"
    ;;
  load)
    printf '%s\n' "$FAKE_BACKEND_COMMIT" >"$state/candidate-revision"
    ;;
  exec)
    if [[ " $* " == *" pg_dump "* ]]; then printf 'fake-postgresql-dump'; exit 0; fi
    if [[ " $* " == *" LASTSAVE "* ]]; then cat "$state/lastsave"; exit 0; fi
    if [[ " $* " == *" BGSAVE "* ]]; then printf '101\n' >"$state/lastsave"; printf 'OK\n'; exit 0; fi
    exit 1
    ;;
  cp)
    printf 'fake-valkey-rdb' >"${@: -1}"
    ;;
  rm)
    :
    ;;
  run)
    if [[ " $* " == *" pg_restore --list "* ]]; then exit 0; fi
    if [[ " $* " == *" nazoauth migrate "* ]]; then
      printf 'candidate-keyset\n' >"$FAKE_KEYS/keyset.json"
      exit 0
    fi
    if [[ " $* " == *" nazoauth server "* ]]; then
      if [[ " $* " == *" $FAKE_OLD_IMAGE "* ]]; then
        printf '%s\n' "$FAKE_OLD_COMMIT" >"$state/revision"
        printf '%s\n' "$FAKE_OLD_IMAGE" >"$state/image-id"
        printf '%s\n' 'localhost/nazo-oauth-server:v0.9.0' >"$state/image-name"
      else
        printf '%s\n' "$FAKE_BACKEND_COMMIT" >"$state/revision"
        printf '%s\n' 'sha256:2222' >"$state/image-id"
        printf '%s\n' 'localhost/nazo-oauth-server:v1.0.0' >"$state/image-name"
      fi
      printf '%s\n' "container-$RANDOM" >"$state/container-id"
      exit 0
    fi
    exit 1
    ;;
  *) exit 1 ;;
esac
''',
            encoding="utf-8",
            newline="\n",
        )
        for path in (curl, cosign, podman):
            path.chmod(0o755)

    def run(self, *, fail_health: bool = False) -> subprocess.CompletedProcess[str]:
        environment = self.env.copy()
        environment["FAKE_KEYS"] = bash_path(self.keys)
        if fail_health:
            environment["FAIL_NEW_HEALTH"] = "1"
        return subprocess.run(
            [
                bash(),
                bash_path(UPDATER),
                "--config",
                bash_path(self.config),
                "update",
                "--to",
                "v1.0.0",
            ],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            env=environment,
        )


class ReleaseUpdateTests(unittest.TestCase):
    def test_updater_is_valid_bash_and_has_no_executable_config_loading(self) -> None:
        subprocess.run(
            [bash(), "-n", str(UPDATER)],
            check=True,
            capture_output=True,
            text=True,
        )
        source = UPDATER.read_text(encoding="utf-8")
        self.assertNotIn("source \"$CONFIG_PATH\"", source)
        self.assertNotIn("eval ", source)
        self.assertNotIn("| bash", source)
        self.assertIn("cosign verify-blob", source)
        self.assertIn(
            "ghcr.io/sigstore/cosign/cosign@sha256:"
            "de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00",
            source,
        )
        self.assertIn("--certificate-identity", source)
        self.assertIn("--certificate-oidc-issuer", source)
        self.assertIn("sha256sum -c", source)
        self.assertIn("flock -n", source)
        self.assertIn("pg_restore --list", source)
        self.assertIn("restore_snapshots", source)
        self.assertIn("rollback_after_error", source)

    def test_help_does_not_require_runtime_dependencies_or_config(self) -> None:
        completed = subprocess.run(
            [bash(), str(UPDATER), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("nazoauthctl", completed.stdout)
        self.assertIn("update", completed.stdout)

    def test_manifest_is_deterministic_and_binds_all_update_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = {}
            for name in ("image.tar", "ui.tar.gz", "nazoauth", "nazoauthctl", "sbom.json"):
                path = root / name
                path.write_bytes((name + "\n").encode())
                artifacts[name] = path
            output = root / "release-manifest.json"
            command = [
                shutil.which("python") or "python",
                str(MANIFEST_BUILDER),
                "--version",
                "v1.2.3",
                "--backend-commit",
                "a" * 40,
                "--frontend-commit",
                "b" * 40,
                "--image",
                str(artifacts["image.tar"]),
                "--ui",
                str(artifacts["ui.tar.gz"]),
                "--binary",
                str(artifacts["nazoauth"]),
                "--updater",
                str(artifacts["nazoauthctl"]),
                "--sbom",
                str(artifacts["sbom.json"]),
                "--policy",
                str(ROOT / "release" / "update-policy.json"),
                "--output",
                str(output),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            first = output.read_bytes()
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(output.read_bytes(), first)
            manifest = json.loads(first)

        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["version"], "v1.2.3")
        self.assertEqual(
            manifest["image_ref"],
            "localhost/nazo-oauth-server:v1.2.3",
        )
        self.assertEqual(
            set(manifest["artifacts"]),
            {"image", "ui", "binary", "updater", "sbom"},
        )
        self.assertTrue(manifest["rollback"]["database_compatible"])
        self.assertEqual(manifest["rollback"]["migration_floor"], "20260731000200")
        self.assertEqual(len(manifest["artifacts"]["image"]["sha256"]), 64)

    def test_manifest_rejects_non_tag_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.write_text("x", encoding="utf-8")
            completed = subprocess.run(
                [
                    shutil.which("python") or "python",
                    str(MANIFEST_BUILDER),
                    "--version",
                    "latest",
                    "--backend-commit",
                    "a" * 40,
                    "--frontend-commit",
                    "b" * 40,
                    "--image",
                    str(artifact),
                    "--ui",
                    str(artifact),
                    "--binary",
                    str(artifact),
                    "--updater",
                    str(artifact),
                    "--sbom",
                    str(artifact),
                    "--policy",
                    str(ROOT / "release" / "update-policy.json"),
                    "--output",
                    str(root / "manifest.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("immutable", completed.stderr)

    def test_release_workflow_publishes_without_overwriting_assets(self) -> None:
        source = (
            ROOT / ".github" / "workflows" / "release-security.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("release/frontend.lock", source)
        self.assertIn("scripts/build_release_manifest.py", source)
        self.assertIn("release-manifest.json.bundle", source)
        self.assertIn("gh release upload", source)
        self.assertNotIn("gh release upload \"$GITHUB_REF_NAME\" --repo \"$GITHUB_REPOSITORY\" --clobber", source)
        self.assertIn("org.opencontainers.image.revision=${{ github.sha }}", source)

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    def test_full_fake_update_switches_verified_image_and_ui(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory))
            completed = update.run()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (update.fake_state / "revision").read_text().strip(),
                update.backend_commit,
            )
            self.assertEqual(
                (update.keys / "keyset.json").read_text(encoding="utf-8"),
                "candidate-keyset\n",
            )
            linked = subprocess.run(
                [bash(), "-lc", 'readlink "$1"', "_", bash_path(update.ui_path)],
                check=True,
                capture_output=True,
                text=True,
                env=update.env,
            ).stdout.strip()
            self.assertTrue(linked.endswith("c" * 40))
            self.assertTrue(update.installed_updater.is_file())
            records = list((update.root / "deployments").glob("v1.0.0-*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(
                json.loads(records[0].read_text())["status"],
                "deployment-success",
            )
            backups = list((update.root / "backups").glob("*-before-v1.0.0"))
            self.assertEqual(len(backups), 1)
            self.assertTrue((backups[0] / "postgresql.dump").is_file())
            self.assertTrue((backups[0] / "valkey-dump.rdb").is_file())

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    def test_failed_candidate_health_restores_snapshot_and_old_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory))
            completed = update.run(fail_health=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(
                (update.fake_state / "revision").read_text().strip(),
                update.old_commit,
            )
            self.assertEqual(
                (update.keys / "keyset.json").read_text(encoding="utf-8"),
                "previous-keyset\n",
            )
            linked = subprocess.run(
                [bash(), "-lc", 'readlink "$1"', "_", bash_path(update.ui_path)],
                check=True,
                capture_output=True,
                text=True,
                env=update.env,
            ).stdout.strip()
            self.assertEqual(linked, bash_path(update.old_ui))
            records = list((update.root / "deployments").glob("v1.0.0-*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(
                json.loads(records[0].read_text())["status"],
                "rollback-after-update-failure",
            )


if __name__ == "__main__":
    unittest.main()
