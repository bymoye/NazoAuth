from __future__ import annotations

import json
import base64
import hashlib
import os
import platform
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_BUILDER = ROOT / "scripts" / "build_release_attestation.py"


def host_release_target() -> str:
    machine = platform.machine().lower()
    architecture = "aarch64" if machine in {"aarch64", "arm64"} else "x86_64"
    if sys.platform == "win32":
        return f"{architecture}-pc-windows-msvc"
    if sys.platform == "darwin":
        return f"{architecture}-apple-darwin"
    return f"{architecture}-unknown-linux-gnu"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_fake_nazoauth(
    path: Path, *, release: str, revision: str, build_id: str
) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "case \"${1:-}\" in\n"
        "  --help) printf 'nazoauth test binary\\n' ;;\n"
        "  build-identity) printf '%s\\n' "
        f"'{{\"release\":\"{release}\",\"revision\":\"{revision}\","
        f"\"protocol\":1,\"build_id\":\"{build_id}\"}}' ;;\n"
        "  migrate) mkdir -p \"$FAKE_KEYS\"; "
        "printf 'candidate-keyset\\n' >\"$FAKE_KEYS/keyset.json\" ;;\n"
        "  server) exit 0 ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
        newline="\n",
    )
    path.chmod(0o755)


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
    frontend_commit = "c" * 40
    old_frontend_commit = "e" * 40
    old_frontend_artifact_sha = "9" * 64
    old_image = "sha256:" + "1" * 64
    oci_index = "sha256:" + "d" * 64
    oci_amd64 = "sha256:" + "3" * 64

    def __init__(self, root: Path, *, engine: str = "podman") -> None:
        self.root = root
        self.engine = engine
        self.target = host_release_target()
        self.candidate_image = self.oci_amd64
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
        self.old_ui = self.ui_releases / self.old_frontend_artifact_sha
        self.old_ui.mkdir()
        (self.old_ui / "index.html").write_text("old-ui\n", encoding="utf-8")
        self._write_release()
        self._write_fake_commands()
        self.config = root / "update.json"
        self.operator = root / "operator"
        self.operator.mkdir()
        encoded_private = base64.urlsafe_b64encode(bytes([7]) * 32).decode().rstrip("=")
        encoded_public = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        identity_suffix = hashlib.sha256(
            base64.urlsafe_b64decode(encoded_public + "=")
        ).hexdigest()[:16]
        controller_key_id = f"controller-{identity_suffix}"
        audit_key_id = f"audit-{identity_suffix}"
        break_glass_key_id = f"break-glass-{identity_suffix}"
        for name in ("controller", "receipt", "audit", "break-glass"):
            (self.operator / f"{name}.key").write_text(encoded_private, encoding="utf-8")
            (self.operator / f"{name}.pub").write_text(encoded_public, encoding="utf-8")
        for name, value in (
            ("deployment-id", "deployment-test"),
            ("controller.kid", controller_key_id),
            ("receipt.kid", "receipt-test"),
            ("audit.kid", audit_key_id),
            ("break-glass.kid", break_glass_key_id),
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
                        "controller_key_id": controller_key_id,
                        "controller_private_key": bash_path(self.operator / "controller.key"),
                        "controller_public_key": bash_path(self.operator / "controller.pub"),
                        "receipt_key_id": "receipt-test",
                        "receipt_private_key": bash_path(self.operator / "receipt.key"),
                        "receipt_public_key": bash_path(self.operator / "receipt.pub"),
                        "audit_key_id": audit_key_id,
                        "audit_private_key": bash_path(self.operator / "audit.key"),
                        "audit_public_key": bash_path(self.operator / "audit.pub"),
                        "break_glass_key_id": break_glass_key_id,
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
        active_release["oci"]["index_digest"] = "sha256:" + "1" * 64
        active_release["oci"]["platform_manifests"].update(
            {
                "linux/amd64": self.old_image,
                "linux/arm64": "sha256:" + "2" * 64,
            }
        )
        active_release["frontend"].update(
            {
                "version": "v0.1.0",
                "commit": self.old_frontend_commit,
                "release_identity": (
                    "https://github.com/nazozero/NazoAuthWeb/"
                    ".github/workflows/release.yml@refs/tags/v0.1.0"
                ),
            }
        )
        active_release["frontend"]["artifact"].update(
            {"sha256": self.old_frontend_artifact_sha, "size": 7}
        )
        active_release["release_identity"] = (
            "https://github.com/nazozero/NazoAuth/"
            ".github/workflows/release-security.yml@refs/tags/v0.9.0"
        )
        active_release["embedded"].update(
            {"release": "v0.9.0", "revision": self.old_commit, "build_id": "github:122:1"}
        )
        self.old_release_manifest = active_release
        (self.deployments / "active-release.json").write_text(
            json.dumps(active_release), encoding="utf-8"
        )
        (self.old_ui / ".nazoauth-ui.json").write_text(
            json.dumps({"schema": 1, **active_release["frontend"]}),
            encoding="utf-8",
        )
        for name, value in (
            ("revision", self.old_commit),
            ("image-id", self.old_image),
            (
                "image-name",
                "ghcr.io/nazozero/nazoauth@" + "sha256:" + "1" * 64,
            ),
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
                "FAKE_CANDIDATE_IMAGE": self.candidate_image,
                "FAKE_OLD_IMAGE_REF": (
                    "ghcr.io/nazozero/nazoauth@" + "sha256:" + "1" * 64
                ),
                "FAKE_CANDIDATE_IMAGE_REF": (
                    "ghcr.io/nazozero/nazoauth@" + self.oci_amd64
                ),
                "FAKE_FRONTEND_DESCRIPTOR": bash_path(
                    self.release / "frontend.json"
                ),
                "FAKE_UI_RELEASES": bash_path(self.ui_releases),
                "NAZOAUTHCTL_TESTING": "1",
                "NAZOAUTHCTL_LOCK": bash_path(root / "nazoauthctl.lock"),
                "MSYS": "winsymlinks:sys",
            }
        )
        recovered = subprocess.run(
            [
                str(updater()),
                "--config",
                bash_path(self.config),
                "recover-identity",
                "--yes",
            ],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            env=self.env,
        )
        if recovered.returncode != 0:
            raise RuntimeError(
                f"failed to adopt the legacy fixture identity: {recovered.stderr}"
            )

    def _write_release(self) -> None:
        target = self.target
        suffix = ".exe" if "windows" in target else ""
        binary = self.release / f"nazoauth-{target}{suffix}"
        self.binary_artifact = binary
        write_fake_nazoauth(
            binary,
            release="v1.0.0",
            revision=self.backend_commit,
            build_id="github:123:1",
        )
        updater_artifact = self.release / f"nazoauthctl-{target}{suffix}"
        shutil.copyfile(updater(), updater_artifact)
        updater_artifact.chmod(0o755)
        ui_source = self.root / "ui-source"
        ui_source.mkdir()
        (ui_source / "index.html").write_text("new-ui\n", encoding="utf-8")
        ui = self.release / "nazoauth-web.tar.gz"
        with tarfile.open(ui, "w:gz") as archive:
            archive.add(ui_source / "index.html", arcname="index.html")
        frontend = self.release / "frontend.json"
        frontend.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "nazozero/NazoAuthWeb",
                    "version": "v0.2.0",
                    "commit": self.frontend_commit,
                    "release_identity": (
                        "https://github.com/nazozero/NazoAuthWeb/"
                        ".github/workflows/release.yml@refs/tags/v0.2.0"
                    ),
                    "artifact": {
                        "repository": "nazozero/NazoAuthWeb",
                        "name": ui.name,
                        "sha256": sha256(ui),
                        "size": ui.stat().st_size,
                    },
                }
            ),
            encoding="utf-8",
        )
        oci = self.release / "oci.json"
        oci.write_text(
            json.dumps(
                {
                    "repository": "ghcr.io/nazozero/nazoauth",
                    "index_digest": self.oci_index,
                    "platform_manifests": {
                        "linux/amd64": self.oci_amd64,
                        "linux/arm64": "sha256:" + "4" * 64,
                    },
                }
            ),
            encoding="utf-8",
        )
        manifest_path = self.release / "release-manifest.json"
        subprocess.run(
            [
                sys.executable,
                str(MANIFEST_BUILDER),
                "--version",
                "v1.0.0",
                "--target",
                target,
                "--backend-commit",
                self.backend_commit,
                "--build-id",
                "github:123:1",
                "--binary",
                str(binary),
                "--updater",
                str(updater_artifact),
                "--frontend",
                str(frontend),
                "--oci",
                str(oci),
                "--policy",
                str(ROOT / "release" / "update-policy.json"),
                "--output",
                str(manifest_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": updater_artifact.name,
                    "digest": {"sha256": sha256(updater_artifact)},
                }
            ],
            "predicateType": "https://nazo.run/attestations/release-manifest/v1",
            "predicate": manifest,
        }
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {
                "payload": base64.b64encode(
                    json.dumps(statement, separators=(",", ":")).encode()
                ).decode(),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [],
            }
        }
        (self.release / "attestations.json").write_text(
            json.dumps(
                {
                    "attestations": [
                        {
                            "bundle_url": "https://attestations.example/unused",
                            "initiator": "github-actions",
                            "repository_id": 1,
                            "bundle": bundle,
                        }
                    ]
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def _write_fake_commands(self) -> None:
        curl = self.fake_bin / "curl"
        curl.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
output=""
args=("$@")
printf '%q ' "$@" >>"$FAKE_STATE/curl-commands"
printf '\n' >>"$FAKE_STATE/curl-commands"
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[$i]}" = --output ]; then output="${args[$((i+1))]}"; fi
done
url="${args[$((${#args[@]}-1))]}"
if [[ "$url" == *"/releases/latest" ]]; then printf '%s\n' '{"tag_name":"v1.0.0"}'; exit 0; fi
if [[ "$url" == *"/attestations/sha256%3A"* ]]; then
  if [[ " $* " != *" X-GitHub-Api-Version: 2022-11-28 "* ]]; then
    printf 'unexpected GitHub API version header: %q\n' "$*" >&2
    exit 1
  fi
  if [[ "$url" != *"?per_page=21&predicate_type=https%3A%2F%2Fnazo.run%2Fattestations%2Frelease-manifest%2Fv1" ]]; then
    printf 'unexpected attestation query: %s\n' "$url" >&2
    exit 1
  fi
  cat "$FAKE_RELEASE/attestations.json"
  exit 0
fi
if [[ "$url" == *"/releases/download/"* ]]; then
  cp -- "$FAKE_RELEASE/${url##*/}" "$output"
  exit 0
fi
if [[ "$url" == *"openid-configuration" ]]; then
  printf '%s\n' '{"issuer":"https://issuer.example"}'
  exit 0
fi
if [[ "$url" == *"/ui/" ]]; then
  if [ "$(cat "$FAKE_STATE/revision")" = "$FAKE_BACKEND_COMMIT" ]; then
    printf 'new-ui\n'
  else
    printf 'old-ui\n'
  fi
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
        cosign.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
args=" $* "
[[ "$args" == *" verify-blob-attestation "* ]]
[[ "$args" == *" --type https://nazo.run/attestations/release-manifest/v1 "* ]]
[[ "$args" == *" --certificate-identity https://github.com/nazozero/NazoAuth/.github/workflows/release-security.yml@refs/tags/v1.0.0 "* ]]
[[ "$args" == *" --certificate-oidc-issuer https://token.actions.githubusercontent.com "* ]]
bundle=""
values=("$@")
for ((i=0; i<${#values[@]}; i++)); do
  if [ "${values[$i]}" = --bundle ]; then bundle="${values[$((i+1))]}"; fi
done
[ -s "$bundle" ]
[[ "${values[-1]##*/}" == nazoauthctl-* ]]
''',
            encoding="utf-8",
            newline="\n",
        )
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
    if [ "$(cat "$FAKE_STATE/revision")" = "$FAKE_BACKEND_COMMIT" ]; then
      artifact_sha="$(jq -r .artifact.sha256 "$FAKE_FRONTEND_DESCRIPTOR")"
      mkdir -p "$FAKE_UI_RELEASES/$artifact_sha"
      printf 'new-ui\n' >"$FAKE_UI_RELEASES/$artifact_sha/index.html"
      cp -- "$FAKE_FRONTEND_DESCRIPTOR" "$FAKE_UI_RELEASES/$artifact_sha/.nazoauth-ui.json"
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
        systemd = self.fake_bin / "systemd"
        systemd.write_text(
            "#!/usr/bin/env bash\nprintf 'systemd 257\\n'\n",
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
printf '%q ' "$@" >>"$state/engine-commands"
printf '\n' >>"$state/engine-commands"
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
    if [[ " $* " == *" $FAKE_OLD_IMAGE_REF "* ]]; then
      selected_ref="$FAKE_OLD_IMAGE_REF"
      selected_digest="$FAKE_OLD_IMAGE"
      selected_revision="$FAKE_OLD_COMMIT"
    else
      selected_ref="$FAKE_CANDIDATE_IMAGE_REF"
      selected_digest="$FAKE_CANDIDATE_IMAGE"
      selected_revision="$FAKE_BACKEND_COMMIT"
    fi
    if [[ " $* " == *" {{json .RepoDigests}} "* ]]; then
      printf '["%s"]\n' "$selected_ref"
    elif [[ " $* " == *" {{.Digest}} "* ]]; then
      printf '%s\n' "$selected_digest"
    else
      printf '%s\n' "$selected_revision"
    fi
    ;;
  pull)
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
    if [[ " $* " == *" nazoauth build-identity "* ]]; then
      if [[ " $* " == *" $FAKE_OLD_IMAGE_REF "* ]]; then
        printf '{"release":"v0.9.0","revision":"%s","protocol":1,"build_id":"github:122:1"}\n' "$FAKE_OLD_COMMIT"
      else
        printf '{"release":"v1.0.0","revision":"%s","protocol":1,"build_id":"github:123:1"}\n' "$FAKE_BACKEND_COMMIT"
      fi
      exit 0
    fi
    if [[ " $* " == *" nazoauth migrate "* ]]; then
      mkdir -p "$FAKE_KEYS"
      printf 'candidate-keyset\n' >"$FAKE_KEYS/keyset.json"
      exit 0
    fi
    if [[ " $* " == *" nazoauth server "* ]]; then
      if [[ " $* " == *" $FAKE_OLD_IMAGE_REF "* ]]; then
        printf '%s\n' "$FAKE_OLD_COMMIT" >"$state/revision"
        printf '%s\n' "$FAKE_OLD_IMAGE" >"$state/image-id"
        printf '%s\n' "$FAKE_OLD_IMAGE_REF" >"$state/image-name"
      else
        printf '%s\n' "$FAKE_BACKEND_COMMIT" >"$state/revision"
        printf '%s\n' "$FAKE_CANDIDATE_IMAGE" >"$state/image-id"
        printf '%s\n' "$FAKE_CANDIDATE_IMAGE_REF" >"$state/image-name"
        artifact_sha="$(jq -r .artifact.sha256 "$FAKE_FRONTEND_DESCRIPTOR")"
        mkdir -p "$FAKE_UI_RELEASES/$artifact_sha"
        printf 'new-ui\n' >"$FAKE_UI_RELEASES/$artifact_sha/index.html"
        cp -- "$FAKE_FRONTEND_DESCRIPTOR" "$FAKE_UI_RELEASES/$artifact_sha/.nazoauth-ui.json"
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
            systemd,
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
        environment["FAKE_UI_RELEASES"] = bash_path(managed_root / "ui-releases")
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
        self.assertIn("\"verify-blob-attestation\"", source)
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
        self.assertIn('artifact="nazoauthctl-$target"', bootstrap)
        self.assertNotIn("gh attestation verify", bootstrap)
        self.assertIn("/attestations/sha256%3A$artifact_digest", bootstrap)
        self.assertIn("verify-blob-attestation", bootstrap)
        self.assertIn("--certificate-github-workflow-ref", bootstrap)
        self.assertIn("--certificate-github-workflow-sha", bootstrap)
        self.assertIn('values != ["github-hosted"]', bootstrap)
        self.assertNotIn("nazoauthctl.bundle", bootstrap)
        for hardened_argument in (
            '"0:0"',
            '"--cap-drop"',
            '"--read-only"',
            '"no-new-privileges"',
            '"--pids-limit"',
            '"/root/.sigstore:rw,noexec,nosuid,nodev,size=16m"',
        ):
            self.assertIn(hardened_argument, source)
        self.assertIn('format!("{}:/work:ro,Z", work.display())', source)
        self.assertIn('"--proto-redir"', source)
        self.assertIn('"--max-filesize"', source)
        self.assertIn("artifact.size,", source)
        self.assertIn("served frontend does not match the signed runtime cache", source)
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
            target = "x86_64-unknown-linux-gnu"
            binary = root / f"nazoauth-{target}"
            updater_artifact = root / f"nazoauthctl-{target}"
            binary.write_bytes(b"server\n")
            updater_artifact.write_bytes(b"controller\n")
            frontend = root / "frontend.json"
            frontend.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "repository": "nazozero/NazoAuthWeb",
                        "version": "v0.2.0",
                        "commit": "b" * 40,
                        "release_identity": (
                            "https://github.com/nazozero/NazoAuthWeb/"
                            ".github/workflows/release.yml@refs/tags/v0.2.0"
                        ),
                        "artifact": {
                            "repository": "nazozero/NazoAuthWeb",
                            "name": "nazoauth-web.tar.gz",
                            "sha256": "e" * 64,
                            "size": 123,
                        },
                    }
                ),
                encoding="utf-8",
            )
            oci = root / "oci.json"
            oci.write_text(
                json.dumps(
                    {
                        "repository": "ghcr.io/nazozero/nazoauth",
                        "index_digest": "sha256:" + "c" * 64,
                        "platform_manifests": {
                            "linux/amd64": "sha256:" + "d" * 64,
                            "linux/arm64": "sha256:" + "f" * 64,
                        },
                    }
                ),
                encoding="utf-8",
            )
            output = root / "release-manifest.json"
            command = [
                sys.executable,
                str(MANIFEST_BUILDER),
                "--version",
                "v1.2.3",
                "--target",
                target,
                "--backend-commit",
                "a" * 40,
                "--build-id",
                "github:123:1",
                "--binary",
                str(binary),
                "--updater",
                str(updater_artifact),
                "--frontend",
                str(frontend),
                "--oci",
                str(oci),
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

        self.assertEqual(manifest["schema"], 4)
        self.assertEqual(manifest["version"], "v1.2.3")
        self.assertEqual(
            manifest["oci"]["index_digest"],
            "sha256:" + "c" * 64,
        )
        self.assertEqual(set(manifest["artifacts"]), {"binary", "updater"})
        self.assertTrue(manifest["rollback"]["artifact"])
        self.assertTrue(manifest["rollback"]["schema_compatible"])
        self.assertEqual(manifest["rollback"]["database_restore"], "backup")
        self.assertFalse(manifest["rollback"]["irreversible_migration"])
        self.assertEqual(manifest["target"], target)
        self.assertEqual(manifest["embedded"]["build_id"], "github:123:1")
        self.assertEqual(manifest["rollback"]["migration_floor"], "20260801000100")
        self.assertIn(
            "refuses schema downgrade",
            manifest["rollback"]["rationale"],
        )
        self.assertEqual(len(manifest["artifacts"]["binary"]["sha256"]), 64)

    def test_manifest_rejects_non_tag_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.write_text("x", encoding="utf-8")
            frontend = root / "frontend.json"
            frontend.write_text("{}", encoding="utf-8")
            oci = root / "oci.json"
            oci.write_text("{}", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(MANIFEST_BUILDER),
                    "--version",
                    "latest",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--backend-commit",
                    "a" * 40,
                    "--build-id",
                    "github:123:1",
                    "--binary",
                    str(artifact),
                    "--updater",
                    str(artifact),
                    "--frontend",
                    str(frontend),
                    "--oci",
                    str(oci),
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
        self.assertIn("release/frontend.json", source)
        self.assertIn("scripts/build_release_attestation.py", source)
        self.assertIn("https://nazo.run/attestations/release-manifest/v1", source)
        self.assertIn("existing OCI tag has a different digest", source)
        self.assertIn("existing GitHub Release asset differs", source)
        self.assertIn("gh release upload", source)
        self.assertNotIn("gh release upload \"$GITHUB_REF_NAME\" --repo \"$GITHUB_REPOSITORY\" --clobber", source)
        self.assertIn("org.opencontainers.image.revision=${{ github.sha }}", source)

    def test_attestation_lookup_uses_supported_api_and_detects_overflow(self) -> None:
        source = (
            ROOT / "crates" / "nazoauthctl" / "src" / "release.rs"
        ).read_text(encoding="utf-8")
        self.assertIn('"X-GitHub-Api-Version: 2022-11-28"', source)
        self.assertIn("const MAX_ATTESTATIONS: usize = 20;", source)
        self.assertIn(
            "const ATTESTATION_PAGE_SIZE: usize = MAX_ATTESTATIONS + 1;", source
        )
        self.assertIn("per_page={ATTESTATION_PAGE_SIZE}", source)
        self.assertNotIn("X-GitHub-Api-Version: 2026-03-10", source)

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
            frontend = json.loads(
                (update.release / "frontend.json").read_text(encoding="utf-8")
            )
            cached_ui = update.ui_releases / frontend["artifact"]["sha256"]
            self.assertEqual(
                (cached_ui / "index.html").read_text(encoding="utf-8"),
                "new-ui\n",
            )
            self.assertEqual(
                json.loads(
                    (cached_ui / ".nazoauth-ui.json").read_text(encoding="utf-8")
                ),
                frontend,
            )
            self.assertTrue(update.installed_updater.is_file())
            records = list((update.root / "deployments").glob("update-*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(
                json.loads(records[0].read_text())["status"],
                "deployment-success",
            )
            backups = list((update.root / "backups").glob("*-before-v1.0.0.*"))
            self.assertEqual(len(backups), 1)
            self.assertTrue((backups[0] / "postgresql.dump").is_file())
            self.assertTrue((backups[0] / "valkey-dump.rdb").is_file())
            engine_commands = (update.fake_state / "engine-commands").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                f"pull ghcr.io/nazozero/nazoauth@{update.oci_amd64}",
                engine_commands,
            )
            self.assertNotIn(
                f"pull ghcr.io/nazozero/nazoauth@{update.oci_index}",
                engine_commands,
            )

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
            (Path(config["deployment_root"]) / "active-release.json").write_text(
                json.dumps(update.old_release_manifest), encoding="utf-8"
            )
            binary_path = Path(config["runtime"]["binary_path"])
            old_release = (
                Path(config["runtime"]["binary_releases"])
                / update.old_commit
                / "nazoauth"
            )
            old_release.parent.mkdir(parents=True)
            write_fake_nazoauth(
                old_release,
                release="v0.9.0",
                revision=update.old_commit,
                build_id="github:122:1",
            )
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
            (Path(config["deployment_root"]) / "active-release.json").write_text(
                json.dumps(update.old_release_manifest), encoding="utf-8"
            )
            binary_path = Path(config["runtime"]["binary_path"])
            old_release = (
                Path(config["runtime"]["binary_releases"])
                / update.old_commit
                / "nazoauth"
            )
            old_release.parent.mkdir(parents=True)
            write_fake_nazoauth(
                old_release,
                release="v0.9.0",
                revision=update.old_commit,
                build_id="github:122:1",
            )
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
            self.assertEqual(
                (update.old_ui / "index.html").read_text(encoding="utf-8"),
                "old-ui\n",
            )
            self.assertTrue((update.old_ui / ".nazoauth-ui.json").is_file())
            active = json.loads(
                (update.deployments / "active-release.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(active["backend_commit"], update.old_commit)
            self.assertTrue(list((update.audit / "management").glob("*.jws")))

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
