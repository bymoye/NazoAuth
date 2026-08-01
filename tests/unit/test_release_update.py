from __future__ import annotations

import json
import base64
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_BUILDER = ROOT / "scripts" / "build_release_manifest.py"


def updater() -> Path:
    override = os.environ.get("NAZOAUTHCTL_TEST_BINARY")
    if override:
        return Path(override)
    executable = ROOT / "target" / "debug" / (
        "nazoauthctl.exe" if os.name == "nt" else "nazoauthctl"
    )
    if not executable.is_file():
        subprocess.run(
            ["cargo", "build", "--package", "nazoauthctl", "--bin", "nazoauthctl"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    return executable


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

    def __init__(self, root: Path, *, engine: str = "podman") -> None:
        self.root = root
        self.engine = engine
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
        self.operator = root / "operator"
        self.operator.mkdir()
        encoded_private = base64.urlsafe_b64encode(bytes([7]) * 32).decode().rstrip("=")
        encoded_public = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        for name in ("controller", "receipt", "audit", "break-glass"):
            (self.operator / f"{name}.key").write_text(encoded_private, encoding="utf-8")
            (self.operator / f"{name}.pub").write_text(encoded_public, encoding="utf-8")
        for name, value in (
            ("deployment-id", "deployment-test"),
            ("controller.kid", "controller-test"),
            ("receipt.kid", "receipt-test"),
            ("audit.kid", "audit-test"),
            ("break-glass.kid", "break-glass-test"),
            ("secret-revision", "secret-test"),
        ):
            (self.operator / name).write_text(value, encoding="utf-8")
        self.audit = root / "audit"
        self.audit.mkdir()
        self.deployments = root / "deployments"
        self.deployments.mkdir()
        self.installed_updater = root / "installed" / "nazoauthctl"
        self.installed_updater.parent.mkdir()
        self.config.write_text(
            json.dumps(
                {
                    "schema": 2,
                    "repository": "nazozero/NazoAuth",
                    "updater_install_path": bash_path(self.installed_updater),
                    "backup_root": bash_path(root / "backups"),
                    "deployment_root": bash_path(self.deployments),
                    "operator": {
                        "deployment_id": "deployment-test",
                        "controller_key_id": "controller-test",
                        "controller_private_key": bash_path(self.operator / "controller.key"),
                        "controller_public_key": bash_path(self.operator / "controller.pub"),
                        "receipt_key_id": "receipt-test",
                        "receipt_private_key": bash_path(self.operator / "receipt.key"),
                        "receipt_public_key": bash_path(self.operator / "receipt.pub"),
                        "audit_key_id": "audit-test",
                        "audit_private_key": bash_path(self.operator / "audit.key"),
                        "audit_public_key": bash_path(self.operator / "audit.pub"),
                        "break_glass_key_id": "break-glass-test",
                        "break_glass_private_key": bash_path(self.operator / "break-glass.key"),
                        "break_glass_public_key": bash_path(self.operator / "break-glass.pub"),
                        "secret_revision_file": bash_path(self.operator / "secret-revision"),
                        "state_directory": bash_path(root / "operator-state"),
                        "audit_directory": bash_path(self.audit),
                        "trust_state_file": bash_path(self.operator / "release-trust.json"),
                    },
                    "dependencies": {
                        "mode": "managed",
                        "database_url_file": bash_path(root / "database-url"),
                        "migration_database_url_file": bash_path(root / "database-migration-url"),
                        "valkey_url_file": bash_path(root / "valkey-url"),
                    },
                    "runtime": {
                        "engine": self.engine,
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
        active_release = json.loads(
            (self.release / "release-manifest.json").read_text(encoding="utf-8")
        )
        active_release["version"] = "v0.9.0"
        active_release["backend_commit"] = self.old_commit
        active_release["image_ref"] = "localhost/nazo-oauth-server:v0.9.0"
        active_release["image_oci_digest"] = "sha256:" + "1" * 64
        active_release["release_identity"] = (
            "https://github.com/nazozero/NazoAuth/"
            ".github/workflows/release-security.yml@refs/tags/v0.9.0"
        )
        active_release["embedded"].update(
            {"release": "v0.9.0", "revision": self.old_commit, "build_id": "github:122:1"}
        )
        (self.deployments / "active-release.json").write_text(
            json.dumps(active_release), encoding="utf-8"
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
        binary.write_text(
            "#!/usr/bin/env bash\n"
            "case \"${1:-}\" in\n"
            "  --help) printf 'nazoauth test binary\\n' ;;\n"
            "  server) exit 0 ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
            newline="\n",
        )
        binary.chmod(0o755)
        updater_artifact = self.release / "nazoauthctl"
        shutil.copyfile(updater(), updater_artifact)
        updater_artifact.chmod(0o755)
        bootstrap = self.release / "install_nazoauthctl.sh"
        bootstrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        updater_sbom = self.release / "nazoauthctl.cdx.json"
        updater_sbom.write_text("{}\n", encoding="utf-8")
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
                sys.executable,
                str(MANIFEST_BUILDER),
                "--version",
                "v1.0.0",
                "--backend-commit",
                self.backend_commit,
                "--build-id",
                "github:123:1",
                "--image-digest",
                "sha256:" + "d" * 64,
                "--frontend-commit",
                "c" * 40,
                "--image",
                str(image),
                "--ui",
                str(ui),
                "--binary",
                str(binary),
                "--bootstrap",
                str(bootstrap),
                "--updater",
                str(updater_artifact),
                "--updater-sbom",
                str(updater_sbom),
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
if [[ "$url" == *"/ui/" ]]; then
  printf '%s\n' '<!doctype html><title>NazoAuth</title>'
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
        pg_dump = self.fake_bin / "pg_dump"
        pg_dump.write_text(
            "#!/usr/bin/env bash\nprintf 'fake-external-postgresql-dump'\n",
            encoding="utf-8",
            newline="\n",
        )
        pg_restore = self.fake_bin / "pg_restore"
        pg_restore.write_text(
            "#!/usr/bin/env bash\nexit 0\n",
            encoding="utf-8",
            newline="\n",
        )
        valkey_cli = self.fake_bin / "valkey-cli"
        valkey_cli.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[$i]}" = --rdb ]; then
    printf 'fake-external-valkey-rdb' >"${args[$((i+1))]}"
    exit 0
  fi
done
exit 1
''',
            encoding="utf-8",
            newline="\n",
        )
        systemctl = self.fake_bin / "systemctl"
        systemctl.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  start|restart)
    if [ -n "${NAZOAUTH_BINARY_INSTALL_PATH:-}" ] &&
       [ -L "$NAZOAUTH_BINARY_INSTALL_PATH" ]; then
      target="$(readlink -f "$NAZOAUTH_BINARY_INSTALL_PATH")"
      basename "$(dirname "$target")" >"$FAKE_STATE/revision"
    fi
    ;;
esac
exit 0
''',
            encoding="utf-8",
            newline="\n",
        )
        systemd_run = self.fake_bin / "systemd-run"
        systemd_run.write_text(
            "#!/usr/bin/env bash\nexit 0\n",
            encoding="utf-8",
            newline="\n",
        )
        fake_id = self.fake_bin / "id"
        fake_id.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        useradd = self.fake_bin / "useradd"
        useradd.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        chown = self.fake_bin / "chown"
        chown.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        container_engine = self.fake_bin / self.engine
        container_engine.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
state="$FAKE_STATE"
case "${1:-}" in
  inspect)
    args="$*"
    if [[ "$args" == *"io.nazoauth.managed"* ]]; then printf 'true\n'
    elif [[ "$args" == *"org.opencontainers.image.revision"* ]]; then cat "$state/revision"
    elif [[ "$args" == *"{{.ImageName}}"* ]] || [[ "$args" == *"{{.Config.Image}}"* ]]; then cat "$state/image-name"
    elif [[ "$args" == *"{{.Image}}"* ]]; then cat "$state/image-id"
    elif [[ "$args" == *"{{.Id}}"* ]]; then cat "$state/container-id"
    elif [ "$#" -eq 2 ]; then printf '%s\n' '{}'
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
    if [[ " $* " == *" pg_dump "* ]]; then
      if [ "${FAIL_BACKUP:-0}" = 1 ]; then exit 9; fi
      printf 'fake-postgresql-dump'
      exit 0
    fi
    if [[ " $* " == *" pg_isready "* ]]; then exit 0; fi
    if [[ " $* " == *" psql "* ]]; then cat >/dev/null; exit 0; fi
    if [[ " $* " == *" PING "* ]]; then printf 'PONG\n'; exit 0; fi
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
    if [[ " $* " == *" --name nazo-oauth-postgres "* ]] ||
       [[ " $* " == *" --name nazo-oauth-valkey "* ]]; then exit 0; fi
    if [[ " $* " == *" pg_restore --list "* ]]; then exit 0; fi
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
  network)
    if [ "${2:-}" = inspect ]; then exit 1; fi
    if [ "${2:-}" = create ]; then exit 0; fi
    exit 1
    ;;
  volume)
    if [ "${2:-}" = inspect ]; then exit 1; fi
    if [ "${2:-}" = create ]; then exit 0; fi
    exit 1
    ;;
  start)
    exit 0
    ;;
  restart)
    exit 0
    ;;
  *) exit 1 ;;
esac
''',
            encoding="utf-8",
            newline="\n",
        )
        for path in (
            curl,
            cosign,
            container_engine,
            pg_dump,
            pg_restore,
            valkey_cli,
            systemctl,
            systemd_run,
            fake_id,
            useradd,
            chown,
        ):
            path.chmod(0o755)

    def run(self, *, fail_health: bool = False) -> subprocess.CompletedProcess[str]:
        environment = self.env.copy()
        environment["FAKE_KEYS"] = bash_path(self.keys)
        if fail_health:
            environment["FAIL_NEW_HEALTH"] = "1"
        return subprocess.run(
            [
                str(updater()),
                "--config",
                bash_path(self.config),
                "update",
                "--yes",
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

    def run_install(
        self, *, external: bool = False, runtime: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        environment = self.env.copy()
        managed_root = self.root / "managed"
        install_config = self.root / "install-config" / "update.json"
        install_config.parent.mkdir()
        environment["FAKE_KEYS"] = bash_path(managed_root / "app" / "keys")
        environment["NAZOAUTHCTL_INSTALL_LOCK"] = bash_path(self.root / "install.lock")
        installed_updater = self.root / "fresh-installed" / "nazoauthctl"
        installed_updater.parent.mkdir()
        environment["NAZOAUTH_UPDATER_INSTALL_PATH"] = bash_path(installed_updater)
        selected_runtime = runtime or self.engine
        if selected_runtime == "host":
            environment["NAZOAUTH_BINARY_INSTALL_PATH"] = bash_path(
                self.root / "host-bin" / "nazoauth"
            )
            environment["NAZOAUTH_BINARY_RELEASES"] = bash_path(
                self.root / "host-releases"
            )
            environment["NAZOAUTH_SYSTEMD_UNIT_DIR"] = bash_path(
                self.root / "systemd"
            )
        command = [
            str(updater()),
            "--config",
            bash_path(install_config),
            "install",
            "--runtime",
            selected_runtime,
            "--data-root",
            bash_path(managed_root),
            "--public-url",
            "https://issuer.example",
            "--to",
            "v1.0.0",
        ]
        secret_input = None
        if external:
            command.extend(["--external-dependencies", "--secrets-stdin"])
            secret_input = json.dumps(
                {
                    "database_url": "postgresql://runtime:secret@db.example/oauth",
                    "migration_database_url": "postgresql://migrator:secret@db.example/oauth",
                    "valkey_url": "rediss://default:secret@cache.example/0",
                }
            )
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            env=environment,
            input=secret_input,
        )
        self.last_install_env = environment
        self.last_install_command = command
        self.last_install_input = secret_input
        return completed, install_config, installed_updater


class ReleaseUpdateTests(unittest.TestCase):
    def test_updater_is_a_rust_binary_with_no_shell_config_evaluation(self) -> None:
        completed = subprocess.run(
            [str(updater()), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "crates" / "nazoauthctl" / "src").glob("*.rs")
        )
        self.assertNotIn("source \"$CONFIG_PATH\"", source)
        self.assertNotIn("eval ", source)
        self.assertNotIn("| bash", source)
        self.assertIn("\"verify-blob\"", source)
        self.assertIn(
            "ghcr.io/sigstore/cosign/cosign@sha256:"
            "de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00",
            source,
        )
        self.assertIn(
            "docker.io/library/postgres:18@sha256:"
            "3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a",
            source,
        )
        self.assertIn(
            "docker.io/valkey/valkey:8-alpine@sha256:"
            "a038175878d66b9d274fbf8be73c0305e93798b83917647f167e18cef3c71eec",
            source,
        )
        self.assertIn("--certificate-identity", source)
        self.assertIn("--certificate-oidc-issuer", source)
        bootstrap = (ROOT / "scripts" / "install_nazoauthctl.sh").read_text(
            encoding="utf-8"
        )
        for hardened_argument in (
            "--user 0:0",
            "--cap-drop ALL",
            "--read-only",
            "--security-opt no-new-privileges",
            "--pids-limit 64",
            "--tmpfs /root/.sigstore:rw,noexec,nosuid,nodev,size=16m",
        ):
            self.assertIn(hardened_argument, bootstrap)
        for hardened_argument in (
            '"0:0"',
            '"--cap-drop"',
            '"--read-only"',
            '"no-new-privileges"',
            '"--pids-limit"',
            '"/root/.sigstore:rw,noexec,nosuid,nodev,size=16m"',
        ):
            self.assertIn(hardened_argument, source)
        self.assertIn("try_lock()", source)
        self.assertIn("\"pg_restore\"", source)
        self.assertIn("restore_snapshots", source)
        self.assertIn("fn rollback(", source)

    def test_help_does_not_require_runtime_dependencies_or_config(self) -> None:
        completed = subprocess.run(
            [str(updater()), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("nazoauthctl", completed.stdout)
        self.assertIn("update", completed.stdout)

    def test_keys_delegate_only_to_the_signed_operator_task_sandbox(self) -> None:
        runtime = (ROOT / "crates" / "nazoauthctl" / "src" / "runtime.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn('args(["nazoauth", "operator-task"])', runtime)
        self.assertIn('"--cap-drop"', runtime)
        self.assertIn('"no-new-privileges"', runtime)
        self.assertNotIn('arg("keyctl")', runtime)

    def test_manifest_is_deterministic_and_binds_all_update_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = {}
            for name in (
                "image.tar",
                "ui.tar.gz",
                "nazoauth",
                "nazoauthctl",
                "install_nazoauthctl.sh",
                "nazoauthctl-sbom.json",
                "sbom.json",
            ):
                path = root / name
                path.write_bytes((name + "\n").encode())
                artifacts[name] = path
            output = root / "release-manifest.json"
            command = [
                sys.executable,
                str(MANIFEST_BUILDER),
                "--version",
                "v1.2.3",
                "--backend-commit",
                "a" * 40,
                "--build-id",
                "github:123:1",
                "--image-digest",
                "sha256:" + "c" * 64,
                "--frontend-commit",
                "b" * 40,
                "--image",
                str(artifacts["image.tar"]),
                "--ui",
                str(artifacts["ui.tar.gz"]),
                "--binary",
                str(artifacts["nazoauth"]),
                "--bootstrap",
                str(artifacts["install_nazoauthctl.sh"]),
                "--updater",
                str(artifacts["nazoauthctl"]),
                "--updater-sbom",
                str(artifacts["nazoauthctl-sbom.json"]),
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

        self.assertEqual(manifest["schema"], 3)
        self.assertEqual(manifest["version"], "v1.2.3")
        self.assertEqual(
            manifest["image_ref"],
            "localhost/nazo-oauth-server:v1.2.3",
        )
        self.assertEqual(
            set(manifest["artifacts"]),
            {"image", "ui", "binary", "bootstrap", "updater", "updater_sbom", "sbom"},
        )
        self.assertTrue(manifest["rollback"]["artifact"])
        self.assertTrue(manifest["rollback"]["schema_compatible"])
        self.assertEqual(manifest["rollback"]["database_restore"], "backup")
        self.assertFalse(manifest["rollback"]["irreversible_migration"])
        self.assertEqual(manifest["image_oci_digest"], "sha256:" + "c" * 64)
        self.assertEqual(manifest["embedded"]["build_id"], "github:123:1")
        self.assertEqual(manifest["rollback"]["migration_floor"], "20260731000200")
        self.assertEqual(len(manifest["artifacts"]["image"]["sha256"]), 64)

    def test_manifest_rejects_non_tag_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.write_text("x", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(MANIFEST_BUILDER),
                    "--version",
                    "latest",
                    "--backend-commit",
                    "a" * 40,
                    "--build-id",
                    "github:123:1",
                    "--image-digest",
                    "sha256:" + "c" * 64,
                    "--frontend-commit",
                    "b" * 40,
                    "--image",
                    str(artifact),
                    "--ui",
                    str(artifact),
                    "--binary",
                    str(artifact),
                    "--bootstrap",
                    str(artifact),
                    "--updater",
                    str(artifact),
                    "--updater-sbom",
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

    def test_manifest_semver_parser_rejects_leading_zero_and_empty_identifiers(self) -> None:
        version = runpy.run_path(str(MANIFEST_BUILDER))["VERSION"]
        for value in ("v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-", "v1.2.3+bad..id"):
            self.assertIsNone(version.fullmatch(value), value)
        for value in ("v0.0.0", "v1.2.3-rc.1", "v1.2.3+build.7"):
            self.assertIsNotNone(version.fullmatch(value), value)

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
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
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
            backups = list((update.root / "backups").glob("*-before-v1.0.0.*"))
            self.assertEqual(len(backups), 1)
            self.assertTrue((backups[0] / "postgresql.dump").is_file())
            self.assertTrue((backups[0] / "valkey-dump.rdb").is_file())

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
    def test_full_fake_docker_update_uses_the_same_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory), engine="docker")
            completed = update.run()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (update.fake_state / "revision").read_text().strip(),
                update.backend_commit,
            )
            self.assertTrue(update.installed_updater.is_file())

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
    def test_fresh_docker_install_generates_owned_state_and_ready_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            install = FakeUpdate(Path(directory), engine="docker")
            completed, config_path, installed_updater = install.run_install()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertTrue(config["managed_install"])
            self.assertEqual(config["runtime"]["engine"], "docker")
            self.assertEqual(config["dependencies"]["mode"], "managed")
            self.assertEqual(
                (install.fake_state / "revision").read_text().strip(),
                install.backend_commit,
            )
            self.assertTrue(installed_updater.is_file())
            records = list(
                (
                    config_path.parent.parent / "managed" / "deployments"
                ).glob("v1.0.0-*.json")
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(
                json.loads(records[0].read_text(encoding="utf-8"))["status"],
                "install-success",
            )
            deployments = config_path.parent.parent / "managed" / "deployments"
            completion = deployments / "managed-install-complete.json"
            self.assertTrue(completion.is_file())
            repeated = subprocess.run(
                install.last_install_command,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
                env=install.last_install_env,
                input=install.last_install_input,
            )
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertIn("already installed and ready", repeated.stdout)
            self.assertEqual(len(list(deployments.glob("v1.0.0-*.json"))), 1)

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
    def test_external_urls_skip_managed_dependencies_and_are_persisted_privately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            install = FakeUpdate(Path(directory), engine="docker")
            completed, config_path, _ = install.run_install(external=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(config["dependencies"]["mode"], "external")
            self.assertNotIn("db.example", json.dumps(config))
            self.assertNotIn("cache.example", json.dumps(config))
            secrets = config_path.parent / "secrets"
            self.assertEqual(
                (secrets / "database-url").read_text(encoding="utf-8"),
                "postgresql://runtime:secret@db.example/oauth",
            )
            self.assertEqual(
                (secrets / "valkey-url").read_text(encoding="utf-8"),
                "rediss://default:secret@cache.example/0",
            )
            self.assertFalse((secrets / "postgres-password").exists())

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "host runtime requires Linux")
    def test_host_install_with_external_urls_needs_no_container_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            install = FakeUpdate(Path(directory), engine="docker")
            completed, config_path, _ = install.run_install(
                external=True,
                runtime="host",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(config["runtime"]["engine"], "host")
            self.assertEqual(config["runtime"]["dependency_engine"], "")
            binary_path = Path(config["runtime"]["binary_path"])
            self.assertTrue(binary_path.is_symlink())
            self.assertEqual(
                binary_path.resolve().parent.name,
                install.backend_commit,
            )

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "host runtime requires Linux")
    def test_host_update_swaps_the_verified_binary_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory), engine="docker")
            installed, config_path, _ = update.run_install(
                external=True,
                runtime="host",
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["runtime"]["readiness_attempts"] = 2
            config["runtime"]["readiness_interval_seconds"] = 0
            config_path.write_text(json.dumps(config), encoding="utf-8")
            binary_path = Path(config["runtime"]["binary_path"])
            old_release = (
                Path(config["runtime"]["binary_releases"])
                / update.old_commit
                / "nazoauth"
            )
            old_release.parent.mkdir(parents=True)
            shutil.copyfile(update.release / "nazoauth", old_release)
            old_release.chmod(0o755)
            binary_path.unlink()
            binary_path.symlink_to(old_release)
            (update.fake_state / "revision").write_text(
                update.old_commit + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(updater()),
                    "--config",
                    bash_path(config_path),
                    "update",
                    "--yes",
                    "--to",
                    "v1.0.0",
                ],
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
                env=update.last_install_env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(binary_path.resolve().parent.name, update.backend_commit)
            self.assertEqual(
                (update.fake_state / "revision").read_text(encoding="utf-8").strip(),
                update.backend_commit,
            )

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "host runtime requires Linux")
    def test_failed_host_health_restores_binary_and_persistent_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory), engine="docker")
            installed, config_path, _ = update.run_install(
                external=True,
                runtime="host",
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["runtime"]["readiness_attempts"] = 2
            config["runtime"]["readiness_interval_seconds"] = 0
            config_path.write_text(json.dumps(config), encoding="utf-8")
            binary_path = Path(config["runtime"]["binary_path"])
            old_release = (
                Path(config["runtime"]["binary_releases"])
                / update.old_commit
                / "nazoauth"
            )
            old_release.parent.mkdir(parents=True)
            shutil.copyfile(update.release / "nazoauth", old_release)
            old_release.chmod(0o755)
            binary_path.unlink()
            binary_path.symlink_to(old_release)
            (update.fake_state / "revision").write_text(
                update.old_commit + "\n",
                encoding="utf-8",
            )
            managed_keys = config_path.parent.parent / "managed" / "app" / "keys"
            (managed_keys / "keyset.json").write_text(
                "previous-host-keyset\n",
                encoding="utf-8",
            )
            environment = update.last_install_env.copy()
            environment["FAIL_NEW_HEALTH"] = "1"
            completed = subprocess.run(
                [
                    str(updater()),
                    "--config",
                    bash_path(config_path),
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
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(binary_path.resolve(), old_release)
            self.assertEqual(
                (update.fake_state / "revision").read_text(encoding="utf-8").strip(),
                update.old_commit,
            )
            self.assertEqual(
                (managed_keys / "keyset.json").read_text(encoding="utf-8"),
                "previous-host-keyset\n",
            )

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
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

    @unittest.skipUnless(shutil.which("jq"), "requires jq")
    @unittest.skipUnless(os.name != "nt", "lifecycle controller targets Linux")
    def test_backup_failure_restarts_old_runtime_without_running_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            update = FakeUpdate(Path(directory))
            environment = update.env.copy()
            environment.update(
                {
                    "FAIL_BACKUP": "1",
                    "FAKE_KEYS": bash_path(update.keys),
                }
            )
            completed = subprocess.run(
                [
                    str(updater()),
                    "--config",
                    bash_path(update.config),
                    "update",
                    "--yes",
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
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("previous runtime was restored", completed.stderr)
            self.assertEqual(
                (update.fake_state / "revision").read_text(encoding="utf-8").strip(),
                update.old_commit,
            )
            self.assertEqual(
                (update.keys / "keyset.json").read_text(encoding="utf-8"),
                "previous-keyset\n",
            )


if __name__ == "__main__":
    unittest.main()
