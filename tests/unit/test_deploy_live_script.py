import hashlib
import http.server
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "deploy_live.ps1"


EXPECTED_BRANCH = "codex/modular-workspace-architecture"


def init_repo(
    path: Path,
    files: dict[str, str],
    *,
    branch: str = EXPECTED_BRANCH,
    remote_url: str | None = None,
) -> str:
    path.mkdir()
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "deploy-test@example.invalid"],
        ["git", "config", "user.name", "Deploy Test"],
        ["git", "add", "."],
        ["git", "commit", "-qm", "fixture"],
        ["git", "branch", "-M", branch],
    ):
        subprocess.run(command, cwd=path, check=True, capture_output=True)
    repository = (
        "NazoAuthWeb"
        if path.name == "frontend" or path.name.startswith("NazoAuthWeb")
        else "NazoAuth"
    )
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            remote_url or f"https://github.com/nazozero/{repository}",
        ],
        cwd=path, check=True, capture_output=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    for command in (
        ["git", "update-ref", f"refs/remotes/origin/{branch}", commit],
        ["git", "config", f"branch.{branch}.remote", "origin"],
        ["git", "config", f"branch.{branch}.merge", f"refs/heads/{branch}"],
    ):
        subprocess.run(command, cwd=path, check=True, capture_output=True)
    return commit


def write_frontend_manifest(dist: Path, commit: str) -> None:
    entries = []
    for path in sorted(item for item in dist.rglob("*") if item.is_file()):
        if path.name == ".nazo-build.json":
            continue
        relative = path.relative_to(dist).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{relative}\t{digest}\n")
    artifact_digest = hashlib.sha256("".join(entries).encode()).hexdigest()
    (dist / ".nazo-build.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "source_commit": commit,
                "artifact_sha256": artifact_digest,
            }
        ),
        encoding="utf-8",
    )


def create_oidf_artifact(root: Path, artifact: Path, source_commit: str) -> None:
    fixture = root / "oidf-artifact-fixture"
    fixture.mkdir()
    ca_key = fixture / "ca.key"
    ca_cert = fixture / "ca.pem"
    leaf_key = fixture / "leaf.key"
    leaf_csr = fixture / "leaf.csr"
    leaf_cert = fixture / "leaf.pem"
    extensions = fixture / "leaf.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="ascii",
    )
    for command in (
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
            "-subj", "/CN=deploy fixture CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(leaf_key), "-out", str(leaf_csr),
            "-subj", "/CN=deploy fixture client",
        ],
        [
            "openssl", "x509", "-req", "-in", str(leaf_csr),
            "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(leaf_cert), "-days", "1", "-extfile", str(extensions),
        ],
    ):
        subprocess.run(command, check=True, capture_output=True)
    rendered = fixture / "configs.json"
    rendered.write_text(
        json.dumps(
            {
                "configs": {
                    "fixture-plan-config.json": {
                        "alias": "fixture",
                        "mtls": {
                            "ca": ca_cert.read_text(encoding="ascii"),
                            "cert": leaf_cert.read_text(encoding="ascii"),
                            "key": leaf_key.read_text(encoding="ascii"),
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "python",
            str(ROOT / "scripts" / "export_oidf_public_plan_configs.py"),
            "--config-json-file",
            str(rendered),
            "--output-dir",
            str(artifact),
            "--source-commit",
            source_commit,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def git_bash() -> str:
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.exists() else "bash"


def bash_path(path: Path) -> str:
    completed = subprocess.run(
        [git_bash(), "-lc", 'cygpath -u "$1"', "_", str(path)],
        capture_output=True, text=True, check=True,
    )
    return completed.stdout.strip()


def windows_path(path: str) -> Path:
    completed = subprocess.run(
        [git_bash(), "-lc", 'cygpath -w "$1"', "_", path],
        capture_output=True, text=True, check=True,
    )
    return Path(completed.stdout.strip())


def render_fixture(
    root: Path,
    extra_arguments: list[str] | None = None,
    *,
    skip_migrate: bool = True,
    oidf_artifact: Path | None = None,
) -> Path:
    backend = root / "backend"
    frontend = root / "frontend"
    backend_commit = init_repo(
        backend,
        {
            "Containerfile": "FROM scratch\n",
            "scripts/oidf_mtls_ca_bundle.py": (
                ROOT / "scripts" / "oidf_mtls_ca_bundle.py"
            ).read_text(encoding="utf-8"),
        },
    )
    frontend_commit = init_repo(frontend, {".gitignore": "dist/\n"})
    if oidf_artifact is not None:
        create_oidf_artifact(root, oidf_artifact, backend_commit)
    ui = frontend / "dist"
    ui.mkdir()
    (ui / "index.html").write_text("ok", encoding="utf-8")
    write_frontend_manifest(ui, frontend_commit)
    rendered = root / "deploy.sh"
    command = [
        "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
        "-RemoteHost", "render-only",
        "-BackendCommit", backend_commit,
        "-FrontendCommit", frontend_commit,
        "-LocalBackendWorktree", str(backend),
        "-LocalFrontendWorktree", str(frontend),
        "-LocalUiDist", str(ui),
        "-RenderRemoteScriptPath", str(rendered),
        "-SkipBuild", "-SkipFrontendBuild",
    ]
    if skip_migrate:
        command.append("-SkipMigrate")
    command.extend(extra_arguments or [])
    if oidf_artifact is not None:
        command.extend(["-OidfPublicSeedArtifactDirectory", str(oidf_artifact)])
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, errors="replace",
        timeout=20, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return rendered


def run_render_only(
    root: Path,
    backend: Path,
    backend_commit: str,
    frontend_commit: str,
    *,
    frontend: Path | None = None,
    ui: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    rendered = root / "deploy.sh"
    command = [
        "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
        "-RemoteHost", "render-only",
        "-BackendCommit", backend_commit,
        "-FrontendCommit", frontend_commit,
        "-LocalBackendWorktree", str(backend),
        "-RenderRemoteScriptPath", str(rendered),
        "-SkipBuild", "-SkipFrontendBuild", "-SkipMigrate",
    ]
    if frontend is not None:
        command.extend(["-LocalFrontendWorktree", str(frontend)])
    if ui is not None:
        command.extend(["-LocalUiDist", str(ui)])
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, errors="replace",
        timeout=20, check=False,
    )


class FakeLifecycle:
    OLD_IMAGE = "sha256:" + "1" * 64

    def __init__(
        self,
        root: Path,
        *,
        lease_seconds: int = 30,
        skip_migrate: bool = False,
        enable_oidf_ca: bool = False,
    ):
        self.root = root
        self.deployment = root / "remote-deployment"
        self.remote_temp = root / "remote-temp"
        self.public_root = root / "public"
        self.web_root = self.public_root / "auth"
        self.ui_path = self.web_root / "ui"
        self.ui_releases = self.public_root / "auth-releases"
        self.keys = self.deployment / "runtime" / "keys"
        self.avatars = self.deployment / "runtime" / "avatars"
        self.keys.mkdir(parents=True)
        self.avatars.mkdir(parents=True)
        self.ui_path.parent.mkdir(parents=True, mode=0o755)
        (self.deployment / ".env.yaml").write_text("server: {}\n", encoding="utf-8")
        self.remote_temp.mkdir()
        render_arguments = [
                "-RenderRemoteTempDir", bash_path(self.remote_temp),
                "-RemoteDeploymentRoot", bash_path(self.deployment),
                "-RemoteConfigPath", bash_path(self.deployment / ".env.yaml"),
                "-RemoteKeysPath", bash_path(self.keys),
                "-RemoteAvatarsPath", bash_path(self.avatars),
                "-RemoteUiPath", bash_path(self.ui_path),
                "-RemoteUiReleasesRoot", bash_path(self.ui_releases),
                "-VerificationLeaseSeconds", str(lease_seconds),
        ]
        self.oidf_ca_target: Path | None = None
        self.previous_oidf_ca: bytes | None = None
        if enable_oidf_ca:
            artifact = root / "oidf-public-plan-configs"
            angie_root = root / "angie"
            angie_root.mkdir()
            self.oidf_ca_target = angie_root / "oidf-mtls-ca.crt"
            old_key = angie_root / "old-ca.key"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(old_key), "-out", str(self.oidf_ca_target),
                    "-days", "1", "-subj", "/CN=old deployment CA",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                ],
                check=True,
                capture_output=True,
            )
            old_key.unlink()
            self.previous_oidf_ca = self.oidf_ca_target.read_bytes()
            self.angie_oidf_config = angie_root / "auth.nazo.run.conf"
            self.angie_oidf_config.write_text(
                f"ssl_client_certificate {self.oidf_ca_target.as_posix()};\n"
                "proxy_set_header X-SSL-Client-Verify $ssl_client_verify;\n"
                "proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;\n",
                encoding="utf-8",
            )
            render_arguments.extend(
                [
                    "-RemoteOidfMtlsCaPath", bash_path(self.oidf_ca_target),
                    "-RemoteAngieOidfConfigPath", bash_path(self.angie_oidf_config),
                ]
            )
        rendered = render_fixture(
            root,
            render_arguments,
            skip_migrate=skip_migrate,
            oidf_artifact=artifact if enable_oidf_ca else None,
        )
        if enable_oidf_ca:
            shutil.copytree(
                root / "oidf-public-plan-configs",
                self.remote_temp / "oidf-public-plan-configs",
            )
            shutil.copyfile(
                ROOT / "scripts" / "oidf_mtls_ca_bundle.py",
                self.remote_temp / "oidf_mtls_ca_bundle.py",
            )
        source = rendered.read_text(encoding="utf-8")
        self.backend_commit = re.search(r"^BACKEND_COMMIT='([^']+)'", source, re.M).group(1)
        def assigned(name: str) -> Path:
            return windows_path(re.search(rf"^{name}='([^']+)'", source, re.M).group(1))
        self.script = assigned("REMOTE_SCRIPT")
        self.state = assigned("STATE_FILE")
        self.ui_archive = assigned("REMOTE_UI_ARCHIVE")
        self.image_archive = assigned("REMOTE_ARCHIVE")
        self.oidf_ca_backup = assigned("OIDF_CA_BACKUP")
        shutil.copyfile(rendered, self.script)
        ui_source = root / "candidate-ui"
        ui_source.mkdir()
        (ui_source / "index.html").write_text("candidate", encoding="utf-8")
        subprocess.run(
            [git_bash(), "-lc", 'tar -czf "$1" -C "$2" .', "_", bash_path(self.ui_archive), bash_path(ui_source)],
            check=True, capture_output=True,
        )
        self.image_archive.touch()
        self.fake_state = root / "fake-state"
        self.fake_state.mkdir()
        (self.fake_state / "container-image").write_text(self.OLD_IMAGE, encoding="utf-8")
        (self.fake_state / "container-id").write_text("old-container", encoding="utf-8")
        (self.fake_state / "worker-generation").write_text("200\n201\n", encoding="utf-8")
        self.fake_bin = root / "fake-bin"
        self.fake_bin.mkdir()
        self._write_fake_commands()
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": str(self.fake_bin) + os.pathsep + self.env["PATH"],
                "FAKE_STATE": bash_path(self.fake_state),
                "FAKE_BACKEND_COMMIT": self.backend_commit,
                "FAKE_OLD_IMAGE": self.OLD_IMAGE,
                "FAKE_ANGIE_CONFIG": bash_path(self.angie_oidf_config)
                if enable_oidf_ca
                else "",
                "MSYS": "winsymlinks:sys",
            }
        )

    def _write_fake_commands(self) -> None:
        podman = self.fake_bin / "podman"
        podman.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
state="$FAKE_STATE"
printf '%q ' "$@" >>"$state/podman.log"; printf '\n' >>"$state/podman.log"
case "${1:-} ${2:-}" in
  "network exists") exit 0 ;;
  "network inspect") printf '%s\n' '[{"name":"nazo_oauth_net","ipv6_enabled":false,"subnets":[{"subnet":"10.101.0.0/24","gateway":"10.101.0.1"}]}]'; exit 0 ;;
  "container exists") test -f "$state/container-image"; exit ;;
  "image exists")
    if [ "${FAIL_OLD_IMAGE_EXISTS:-0}" = 1 ] && [ "${3:-}" = "$FAKE_OLD_IMAGE" ]; then exit 1; fi
    exit 0 ;;
  "image inspect")
    args="$*"
    if [[ "$args" == *org.opencontainers.image.revision* ]]; then printf '%s\n' "$FAKE_BACKEND_COMMIT"; else printf '%s\n' "$(printf '0%.0s' {1..64})"; fi
    exit 0 ;;
esac
case "${1:-}" in
  inspect)
    args="$*"
    if [[ "$args" == *NetworkSettings.Networks* ]]; then printf '%s\n' '10.101.0.20';
    elif [[ "$args" == *HostConfig.RestartPolicy.Name* ]]; then printf '%s\n' 'unless-stopped';
    elif [[ "$args" == *ImageName* ]]; then printf '%s\n' 'localhost/old:stable';
    elif [[ "$args" == *"{{.Image}}"* ]]; then cat "$state/container-image";
    elif [[ "$args" == *"{{.Id}}"* ]]; then cat "$state/container-id";
    else exit 1; fi
    ;;
  load|update) exit 0 ;;
  exec) printf '%s\n' PONG ;;
  rm) rm -f "$state/container-image" "$state/container-id" ;;
  run)
    args=("$@")
    if [[ " $* " == *" nazo-oauth-migrate "* ]]; then
      count=0; [ ! -f "$state/migrations" ] || count="$(cat "$state/migrations")"
      printf '%s\n' "$((count + 1))" >"$state/migrations"; exit 0
    fi
    if [[ " $* " == *" pg_isready "* ]]; then exit 0; fi
    selected="${args[$((${#args[@]} - 2))]}"
    [ -n "$selected" ] || exit 0
    printf 'selected=%q old=%q\n' "$selected" "$FAKE_OLD_IMAGE" >>"$state/podman.log"
    if [ "$selected" = "$FAKE_OLD_IMAGE" ] && [ "${FAIL_OLD_IMAGE_RUN:-0}" = 1 ]; then exit 1; fi
    if [ "$selected" = "$FAKE_OLD_IMAGE" ]; then image="$FAKE_OLD_IMAGE"; else image="sha256:$(printf '0%.0s' {1..64})"; fi
    printf '%s\n' "$image" >"$state/container-image"
    printf '%s\n' "container-$RANDOM" >"$state/container-id"
    printf '%s\n' fake-container
    ;;
  *) exit 1 ;;
esac
''', encoding="utf-8", newline="\n")
        curl = self.fake_bin / "curl"
        curl.write_text(
            r'''#!/usr/bin/env bash
set -euo pipefail
url="${*: -1}"
if [[ "$url" == *openid-configuration ]]; then printf '%s\n' '{"issuer":"https://auth.nazo.run"}'; exit 0; fi
if [ "${FAIL_ROLLBACK_HEALTH:-0}" = 1 ] && [ "$(cat "$FAKE_STATE/container-image" 2>/dev/null || true)" = "$FAKE_OLD_IMAGE" ]; then exit 22; fi
printf '%s\n' ok
''', encoding="utf-8", newline="\n")
        flock = self.fake_bin / "flock"
        flock.write_text(
            "#!/usr/bin/env bash\n"
            "if [ \"${1:-}\" = -x ]; then while ! mkdir \"$FAKE_STATE/flock-held\" 2>/dev/null; do sleep 0.01; done; exit 0; fi\n"
            "if [ \"${1:-}\" = -u ]; then rmdir \"$FAKE_STATE/flock-held\" 2>/dev/null || true; exit 0; fi\n"
            "exit 2\n",
            encoding="utf-8", newline="\n",
        )
        runuser = self.fake_bin / "runuser"
        runuser.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%q ' \"$@\" >>\"$FAKE_STATE/runuser.log\"; printf '\\n' >>\"$FAKE_STATE/runuser.log\"\n"
            "[ \"${1:-}\" = -u ] && [ \"${2:-}\" = www ] && [ \"${3:-}\" = -- ]\n"
            "shift 3\n"
            "exec \"$@\"\n",
            encoding="utf-8", newline="\n",
        )
        systemctl = self.fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%q ' \"$@\" >>\"$FAKE_STATE/systemctl.log\"; printf '\\n' >>\"$FAKE_STATE/systemctl.log\"\n"
            "if [ \"${1:-}\" = enable ] && [ \"${2:-}\" = podman-restart.service ]; then exit 0; fi\n"
            "if [ \"${1:-}\" = show ] && [ \"${*: -1}\" = nginx.service ]; then printf '%s\\n' 100; exit 0; fi\n"
            "if [ \"${1:-}\" = reload ] && [ \"${2:-}\" = nginx.service ]; then\n"
            "  if [ \"${MUTATE_ANGIE_CONFIG_ON_RELOAD:-0}\" = 1 ] "
            "&& [ ! -e \"$FAKE_STATE/angie-config-reload-mutated\" ]; then\n"
            "    printf '%s\\n' 'proxy_set_header x-ssl-client-verify $http_x_ssl_client_verify;' >>\"$FAKE_ANGIE_CONFIG\"\n"
            "    : >\"$FAKE_STATE/angie-config-reload-mutated\"\n"
            "  fi\n"
            "  cp -- \"$FAKE_ANGIE_CONFIG\" \"$FAKE_STATE/active-angie-config\"\n"
            "  if [ \"${RELOAD_DROPS_OLD_ONLY:-0}\" = 1 ] "
            "&& [ ! -e \"$FAKE_STATE/reload-dropped-old-only\" ]; then\n"
            "    tail -n 1 \"$FAKE_STATE/worker-generation\" >\"$FAKE_STATE/worker-generation.next\"\n"
            "    mv \"$FAKE_STATE/worker-generation.next\" \"$FAKE_STATE/worker-generation\"\n"
            "    : >\"$FAKE_STATE/reload-dropped-old-only\"\n"
            "  elif [ \"${RELOAD_RETAINS_OLD_WITH_NEW:-0}\" = 1 ] "
            "&& [ ! -e \"$FAKE_STATE/reload-retained-old-with-new\" ]; then\n"
            "    generation=\"$(tail -n 1 \"$FAKE_STATE/worker-generation\")\"\n"
            "    cp -- \"$FAKE_STATE/worker-generation\" \"$FAKE_STATE/worker-generation.next\"\n"
            "    printf '%s\\n' \"$((generation + 1))\" >>\"$FAKE_STATE/worker-generation.next\"\n"
            "    mv \"$FAKE_STATE/worker-generation.next\" \"$FAKE_STATE/worker-generation\"\n"
            "    : >\"$FAKE_STATE/reload-retained-old-with-new\"\n"
            "  else\n"
            "    generation=\"$(tail -n 1 \"$FAKE_STATE/worker-generation\")\"\n"
            "    printf '%s\\n' \"$((generation + 1))\" >\"$FAKE_STATE/worker-generation\"\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8", newline="\n",
        )
        pgrep = self.fake_bin / "pgrep"
        pgrep.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "[ \"${1:-}\" = -P ] && [ \"${2:-}\" = 100 ]\n"
            "cat \"$FAKE_STATE/worker-generation\"\n",
            encoding="utf-8", newline="\n",
        )
        angie = self.fake_bin / "angie"
        angie.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [ \"${1:-}\" = -t ]; then\n"
            "  if [ \"${MUTATE_ANGIE_CONFIG_ON_TEST:-0}\" = 1 ] "
            "&& [ ! -e \"$FAKE_STATE/angie-config-mutated\" ]; then\n"
            "    printf '%s\\n' 'proxy_set_header x-ssl-client-verify $http_x_ssl_client_verify;' >>\"$FAKE_ANGIE_CONFIG\"\n"
            "    : >\"$FAKE_STATE/angie-config-mutated\"\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"${1:-}\" = -T ] && [ -n \"${FAKE_ANGIE_CONFIG:-}\" ]; then\n"
            "  printf '# configuration file %s:\\n' \"$FAKE_ANGIE_CONFIG\"\n"
            "  cat \"$FAKE_ANGIE_CONFIG\"\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n",
            encoding="utf-8", newline="\n",
        )
        sha256sum = self.fake_bin / "sha256sum"
        sha256sum.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [ -n \"${FAKE_SHA256_FAILURE_PATTERN:-}\" ] "
            "&& [[ \"$*\" == *\"$FAKE_SHA256_FAILURE_PATTERN\"* ]]; then\n"
            "  /usr/bin/sha256sum \"$@\"\n"
            "  exit 2\n"
            "fi\n"
            "if [ -n \"${FAKE_SHA256_GARBAGE_PATTERN:-}\" ] "
            "&& [[ \"$*\" == *\"$FAKE_SHA256_GARBAGE_PATTERN\"* ]]; then\n"
            "  /usr/bin/sha256sum \"$@\"\n"
            "  printf '%s\\n' garbage\n"
            "  exit 0\n"
            "fi\n"
            "exec /usr/bin/sha256sum \"$@\"\n",
            encoding="utf-8", newline="\n",
        )
        podman.chmod(0o755)
        curl.chmod(0o755)
        flock.chmod(0o755)
        runuser.chmod(0o755)
        systemctl.chmod(0o755)
        pgrep.chmod(0o755)
        angie.chmod(0o755)
        sha256sum.chmod(0o755)

    def run(self, action: str, **flags: str) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env.update(flags)
        return subprocess.run(
            [git_bash(), "-lc", 'export PATH="$1:$PATH"; exec bash "$2" "$3"', "_", bash_path(self.fake_bin), bash_path(self.script), action],
            capture_output=True, text=True, errors="replace", timeout=60, check=False, env=env,
        )

    def record_status(self) -> str:
        records = [
            record
            for record in (self.deployment / "deployments").glob("*.json")
            if record.name != "current.json"
        ]
        self.assert_one(records)
        return json.loads(records[0].read_text(encoding="utf-8"))["status"]

    def deployment_record(self) -> Path:
        records = [
            record
            for record in (self.deployment / "deployments").glob("*.json")
            if record.name != "current.json"
        ]
        self.assert_one(records)
        return records[0]

    @staticmethod
    def assert_one(items: list[Path]) -> None:
        if len(items) != 1:
            raise AssertionError(f"expected one item, got {items}")


class DeployLiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_oidf_ca_bundle_is_part_of_the_existing_deployment_transaction(self) -> None:
        self.assertIn("OidfPublicSeedArtifactDirectory", self.source)
        self.assertIn("--artifact-directory", self.source)
        self.assertIn("OIDF_CA_SHA256", self.source)
        self.assertIn("ANGIE_OIDF_CONFIG", self.source)
        self.assertIn('mktemp "`$target_dir/.oidf-mtls-ca.XXXXXX"', self.source)
        self.assertIn('mv -f "`$temporary" "`$OIDF_CA_TARGET"', self.source)
        self.assertIn("ca_switched", self.source)
        self.assertIn("restore_oidf_ca", self.source)
        self.assertIn("cp --preserve=mode,ownership,timestamps", self.source)
        self.assertIn('[string]$AngieServiceName = "nginx.service"', self.source)
        self.assertIn('systemctl reload "`$ANGIE_SERVICE"', self.source)
        self.assertIn("certificate verification must not be overridden with SUCCESS", self.source)
        self.assertIn("ANGIE_CONFIG_BACKUP", self.source)
        self.assertIn("reload_angie_and_wait", self.source)
        self.assertIn("old_worker_remaining", self.source)
        self.assertIn("previous_ca_sha256", self.source)
        self.assertIn("OidfPublicSeedWorkflowRunId", self.source)
        self.assertIn("OidfPublicSeedArtifactId", self.source)
        self.assertIn("OidfPublicSeedArtifactDigest", self.source)
        self.assertIn("oidf_manifest_sha256", self.source)
        self.assertIn("Get-GitHubApiJson", self.source)
        self.assertIn("artifact archive digest does not match GitHub metadata", self.source)
        self.assertIn("--expected-source-commit", self.source)
        self.assertNotIn("optional_no_ca", self.source)

    def test_exact_commits_are_mandatory_and_used_in_release_paths(self) -> None:
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\]\$BackendCommit",
        )
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\]\$FrontendCommit",
        )
        self.assertIn('/usr/local/angie/html/auth-releases', self.source)
        self.assertIn("FrontendCommit", self.source)

    def test_public_ui_defaults_are_worker_traversable_and_probed_before_commit(self) -> None:
        self.assertIn('[string]$RemoteUiPath = "/usr/local/angie/html/auth/ui"', self.source)
        self.assertIn('[string]$AngieWorkerUser = "www"', self.source)
        self.assertIn('[string]$UiUrl = "https://auth.nazo.run/ui/auth"', self.source)
        worker_probe = self.source.index('runuser -u "`$ANGIE_WORKER_USER" -- test -r "`$UI_PATH/index.html"')
        public_probe = self.source.index("Invoke-WebRequest -Uri $UiUrl")
        asset_probe = self.source.index("Invoke-WebRequest -Uri $assetUrl")
        commit = self.source.index('Invoke-Checked ssh $RemoteHost @($commitCommand)')
        self.assertLess(worker_probe, public_probe)
        self.assertLess(public_probe, asset_probe)
        self.assertLess(asset_probe, commit)
        self.assertIn("/ui/assets/", self.source)

    def test_remote_host_rejects_ssh_options_and_shell_metacharacters(self) -> None:
        valid_commit = "0" * 40
        for remote_host in (
            "-oProxyCommand=malicious",
            "hostinger;touch-owned",
            "user@host extra",
            "user@@host",
            "/tmp/socket",
        ):
            with self.subTest(remote_host=remote_host):
                completed = subprocess.run(
                    [
                        "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
                        "-File", str(SCRIPT), "-RemoteHost", remote_host,
                        "-BackendCommit", valid_commit,
                        "-FrontendCommit", valid_commit,
                    ],
                    cwd=ROOT, capture_output=True, text=True, errors="replace",
                    timeout=10, check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "RemoteHost must be a safe SSH host alias, hostname, or user@host",
                    completed.stdout + completed.stderr,
                )

    def test_source_commits_are_bound_to_clean_worktrees_and_frontend_manifest(self) -> None:
        self.assertIn("Unable to discover a unique synchronized sibling NazoAuthWeb worktree", self.source)
        self.assertIn("remote\", \"get-url\", \"origin", self.source)
        self.assertIn("branch\", \"--show-current", self.source)
        self.assertIn("HEAD...@{upstream}", self.source)
        self.assertIn("status --porcelain=v1", self.source)
        self.assertIn("Get-FileHash", self.source)
        self.assertIn(".nazo-build.json", self.source)
        self.assertIn("source_commit", self.source)
        self.assertIn("artifact_sha256", self.source)
        self.assertIn('Join-Path $frontendBuildContext "package.json"', self.source)
        self.assertIn('Join-Path $frontendBuildContext "package-lock.json"', self.source)
        self.assertIn("packageManager must pin an exact npm version", self.source)
        self.assertIn("deployment host has npm", self.source)
        self.assertIn("must define the verified aggregate test script", self.source)
        self.assertIn('"run", "test"', self.source)
        self.assertIn('"archive", "--format=tar"', self.source)
        self.assertIn('Join-Path $backendBuildContext "Containerfile"', self.source)
        self.assertIn('$backendBuildContext', self.source)
        self.assertIn('ExpectedBackendRemote = "https://github.com/nazozero/NazoAuth"', self.source)
        self.assertIn('ExpectedBackendBranch = "codex/modular-workspace-architecture"', self.source)
        self.assertIn('ExpectedFrontendRemote = "https://github.com/nazozero/NazoAuthWeb"', self.source)
        self.assertIn("Assert-GitOrigin", self.source)

    def test_ssh_remote_action_is_one_argument_without_bash_lc_boundary_ambiguity(self) -> None:
        self.assertIn('Invoke-Checked ssh $RemoteHost @($deployCommand)', self.source)
        self.assertIn('Invoke-Checked ssh $RemoteHost @($commitCommand)', self.source)
        self.assertIn('& ssh $RemoteHost $rollbackCommand', self.source)
        self.assertNotIn('& ssh $RemoteHost bash -lc', self.source)

    def test_prebuilt_artifacts_are_not_accepted_for_a_real_deployment(self) -> None:
        self.assertIn("SkipBuild is only allowed when rendering", self.source)
        self.assertIn("SkipFrontendBuild is only allowed when rendering", self.source)
        self.assertIn("EXPECTED_IMAGE_ID", self.source)
        self.assertIn('test "`$actual_image_id" = "`$EXPECTED_IMAGE_ID"', self.source)
        self.assertIn('tar -xOf $Archive "manifest.json"', self.source)
        self.assertIn("Get-ArchiveImageConfigId", self.source)

    def test_remote_transaction_records_and_restores_both_targets(self) -> None:
        for marker in (
            "previous_image",
            "previous_container_id",
            "previous_ui_target",
            "candidate_image",
            "backend_commit",
            "frontend_commit",
            "rollback",
        ):
            self.assertIn(marker, self.source)
        self.assertRegex(self.source, r"trap\s+['\"]?rollback")

    def test_rollback_uses_the_previous_immutable_image_id(self) -> None:
        self.assertIn("previous_image_id", self.source)
        self.assertIn("--format '{{.Image}}'", self.source)
        self.assertIn('run_server "`$previous_image_id"', self.source)
        self.assertIn('podman image exists "`$previous_image_id"', self.source)
        self.assertNotIn('run_server "`$previous_image"', self.source)

    def test_server_survives_process_exit_and_host_restart(self) -> None:
        self.assertIn("--restart=unless-stopped", self.source)
        self.assertIn("{{.HostConfig.RestartPolicy.Name}}", self.source)
        self.assertIn("systemctl enable podman-restart.service", self.source)
        self.assertIn("podman update --restart=unless-stopped nazo-oauth-postgres", self.source)
        self.assertIn("podman update --restart=unless-stopped nazo-oauth-valkey", self.source)
        self.assertNotIn(
            "podman update --restart=unless-stopped nazo-oauth-postgres nazo-oauth-valkey",
            self.source,
        )
        deploy_body = self.source[self.source.index("deploy() {") :]
        self.assertLess(
            deploy_body.index("systemctl enable podman-restart.service"),
            deploy_body.index('podman rm -f "`$CONTAINER_NAME"'),
        )

    def test_verification_lease_is_atomically_claimed_by_commit_or_rollback(self) -> None:
        self.assertIn("VerificationLeaseSeconds", self.source)
        self.assertIn("LEASE_PENDING", self.source)
        self.assertIn("LEASE_COMMITTED", self.source)
        self.assertIn("LEASE_ROLLBACK", self.source)
        self.assertRegex(self.source, r'mv\s+"`\$LEASE_PENDING"\s+"`\$LEASE_COMMITTED"')
        self.assertIn("expire)", self.source)
        self.assertIn("nohup", self.source)
        self.assertIn("rollbackCommand", self.source)
        deploy_body = self.source[self.source.index("deploy() {") :]
        self.assertLess(
            deploy_body.index("start_verification_lease"),
            deploy_body.index('podman rm -f "`$CONTAINER_NAME"'),
        )

    def test_deployment_records_are_unique_and_current_switch_is_atomic(self) -> None:
        self.assertIn("DEPLOYMENT_ID", self.source)
        self.assertRegex(
            self.source,
            r'RECORD="`\$DEPLOYMENTS/`\$BACKEND_COMMIT-`\$FRONTEND_COMMIT-`\$DEPLOYMENT_ID\.json"',
        )
        self.assertIn("CURRENT_LINK_TEMP", self.source)
        self.assertRegex(self.source, r'mv\s+-T\s+"`\$CURRENT_LINK_TEMP"\s+"`\$DEPLOYMENTS/current\.json"')
        self.assertIn('fsync_parent "`$DEPLOYMENTS/current.json"', self.source)
        self.assertIn('fsync_parent "`$STATE_FILE"', self.source)

    def test_existing_network_subnet_and_gateway_are_exactly_validated(self) -> None:
        self.assertIn("podman network inspect", self.source)
        self.assertIn("NETWORK_SUBNET", self.source)
        self.assertIn("NETWORK_GATEWAY", self.source)
        self.assertIn("unexpected subnet or gateway", self.source)
        self.assertIn('document[0].get("subnets")', self.source)

    def test_ui_switch_is_atomic_and_active_tree_is_never_deleted(self) -> None:
        self.assertNotRegex(
            self.source,
            re.compile(r"find\s+['\"]?`?\$UI_PATH.*-exec\s+rm\s+-rf", re.IGNORECASE),
        )
        self.assertIn("mv -T", self.source)
        self.assertIn("ln -s", self.source)

    def test_candidate_is_verified_before_success_is_recorded(self) -> None:
        health = self.source.index("/health")
        issuer = self.source.index("ExpectedIssuer")
        record = self.source.index("deployment-success")
        self.assertLess(health, record)
        self.assertLess(issuer, record)

    def test_rendered_remote_transaction_is_valid_bash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rendered = render_fixture(root)
            self.assertNotIn(
                b"\r",
                rendered.read_bytes(),
                "remote Linux shell scripts must be emitted as UTF-8 with LF line endings",
            )
            syntax = subprocess.run(
                [git_bash(), "-n", str(rendered)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
                check=False,
            )

        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_frontend_sibling_discovery_skips_wrong_default_and_selects_unique_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "NazoAuth"
            backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
            init_repo(
                root / "NazoAuthWeb",
                {".gitignore": "dist/\n"},
                branch="wrong-branch",
            )
            frontend = root / "NazoAuthWeb-modular-workspace-architecture"
            frontend_commit = init_repo(
                frontend,
                {".gitignore": "dist/\n"},
                remote_url="git@github.com:nazozero/NazoAuthWeb.git",
            )
            ui = frontend / "dist"
            ui.mkdir()
            (ui / "index.html").write_text("ok", encoding="utf-8")
            completed = run_render_only(
                root, backend, backend_commit, frontend_commit,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_frontend_sibling_discovery_fails_closed_on_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "NazoAuth"
            backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
            frontend = root / "NazoAuthWeb-one"
            frontend_commit = init_repo(frontend, {".gitignore": "dist/\n"})
            ui = frontend / "dist"
            ui.mkdir()
            (ui / "index.html").write_text("ok", encoding="utf-8")
            duplicate = root / "NazoAuthWeb-two"
            shutil.copytree(frontend, duplicate)
            completed = run_render_only(
                root, backend, backend_commit, frontend_commit, ui=ui,
            )

        self.assertNotEqual(completed.returncode, 0)
        output = completed.stdout + completed.stderr
        self.assertIn("Frontend worktree discovery is ambiguous", output)
        self.assertIn(str(frontend), output)
        self.assertIn(str(duplicate), output)

    def test_frontend_sibling_discovery_reports_rejected_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "NazoAuth"
            backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
            frontend = root / "NazoAuthWeb"
            frontend_commit = init_repo(
                frontend,
                {".gitignore": "dist/\n"},
                branch="wrong-branch",
            )
            completed = run_render_only(
                root, backend, backend_commit, frontend_commit,
            )

        self.assertNotEqual(completed.returncode, 0)
        output = completed.stdout + completed.stderr
        self.assertIn("Unable to discover a unique synchronized sibling", output)
        self.assertIn("Rejected candidates", output)
        self.assertIn("wrong-branch", output)

    def test_explicit_frontend_path_rejects_invalid_repository_state(self) -> None:
        cases = ("dirty", "remote", "branch", "upstream")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                backend = root / "NazoAuth"
                backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
                frontend = root / "NazoAuthWeb-explicit"
                frontend_commit = init_repo(frontend, {"tracked.txt": "clean\n", ".gitignore": "dist/\n"})
                ui = frontend / "dist"
                ui.mkdir()
                (ui / "index.html").write_text("ok", encoding="utf-8")
                if case == "dirty":
                    (frontend / "untracked.txt").write_text("dirty\n", encoding="utf-8")
                    expected = "worktree must be clean"
                elif case == "remote":
                    subprocess.run(
                        ["git", "remote", "set-url", "origin", "https://github.com/other/NazoAuthWeb"],
                        cwd=frontend, check=True, capture_output=True,
                    )
                    expected = "does not identify expected repository"
                elif case == "branch":
                    subprocess.run(
                        ["git", "branch", "-M", "wrong-branch"],
                        cwd=frontend, check=True, capture_output=True,
                    )
                    expected = "does not match expected branch"
                else:
                    (frontend / "tracked.txt").write_text("ahead\n", encoding="utf-8")
                    for command in (
                        ["git", "add", "tracked.txt"],
                        ["git", "commit", "-qm", "ahead"],
                    ):
                        subprocess.run(command, cwd=frontend, check=True, capture_output=True)
                    frontend_commit = subprocess.run(
                        ["git", "rev-parse", "HEAD"], cwd=frontend, check=True,
                        capture_output=True, text=True,
                    ).stdout.strip()
                    expected = "is not synchronized"
                completed = run_render_only(
                    root, backend, backend_commit, frontend_commit,
                    frontend=frontend, ui=ui,
                )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(expected, completed.stdout + completed.stderr)

    def test_rendered_network_validation_rejects_additional_fake_subnets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment = root / "remote-deployment"
            keys = deployment / "runtime" / "keys"
            avatars = deployment / "runtime" / "avatars"
            keys.mkdir(parents=True)
            avatars.mkdir(parents=True)
            config = deployment / ".env.yaml"
            config.write_text("server: {}\n", encoding="utf-8")
            remote_temp = root / "remote-temp"
            remote_temp.mkdir()
            rendered = render_fixture(
                root,
                [
                    "-RenderRemoteTempDir", bash_path(remote_temp),
                    "-RemoteDeploymentRoot", bash_path(deployment),
                    "-RemoteConfigPath", bash_path(config),
                    "-RemoteKeysPath", bash_path(keys),
                    "-RemoteAvatarsPath", bash_path(avatars),
                    "-RemoteUiPath", bash_path(deployment / "ui"),
                ],
            )
            shell = r'''
podman() {
  if [ "$1 $2" = "network exists" ]; then return 0; fi
  if [ "$1 $2" = "network inspect" ]; then printf '%s\n' "$FAKE_NETWORK_JSON"; return 0; fi
  if [ "$1" = "run" ]; then return 0; fi
  if [ "$1" = "exec" ]; then printf 'PONG\n'; return 0; fi
  return 0
}
flock() { return 0; }
export -f podman flock
bash "$1" deploy
'''
            def execute(layout: dict) -> subprocess.CompletedProcess[str]:
                environment = os.environ.copy()
                environment["FAKE_NETWORK_JSON"] = json.dumps([layout])
                return subprocess.run(
                    [git_bash(), "-c", shell, "_", bash_path(rendered)],
                    capture_output=True, text=True, errors="replace", timeout=10,
                    check=False, env=environment,
                )

            exact = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24", "gateway": "10.101.0.1"},
                ]}
            )
            completed = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24", "gateway": "10.101.0.1"},
                    {"subnet": "fd00::/64", "gateway": "fd00::1"},
                ]}
            )
            missing_gateway = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24"},
                ]}
            )
            extra_ipv4 = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24", "gateway": "10.101.0.1"},
                    {"subnet": "10.102.0.0/24", "gateway": "10.102.0.1"},
                ]}
            )

        self.assertNotEqual(exact.returncode, 0)
        self.assertNotIn("unexpected subnet or gateway", exact.stdout + exact.stderr)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected subnet or gateway", completed.stdout + completed.stderr)
        self.assertNotEqual(missing_gateway.returncode, 0)
        self.assertIn("unexpected subnet or gateway", missing_gateway.stdout + missing_gateway.stderr)
        self.assertNotEqual(extra_ipv4.returncode, 0)
        self.assertIn("unexpected subnet or gateway", extra_ipv4.stdout + extra_ipv4.stderr)
        self.assertFalse((deployment / "deployments" / "active-deployment").exists())

    def test_fake_lifecycle_immediate_rollback_restores_first_directory_ui_and_migrates_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), skip_migrate=False)
            ui = lifecycle.ui_path
            ui.mkdir()
            (ui / "index.html").write_text("old-ui", encoding="utf-8")
            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            mode = subprocess.run(
                [git_bash(), "-lc", 'stat -c %a "$1"', "_", bash_path(lifecycle.state)],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            if os.name != "nt":
                self.assertEqual(mode, "600")
            self.assertIn("umask 077", self.source)
            self.assertIn('chmod 0600 "`$state_temp"', self.source)
            rolled_back = lifecycle.run("rollback")
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertEqual((ui / "index.html").read_text(encoding="utf-8"), "old-ui")
            self.assertEqual((lifecycle.fake_state / "container-image").read_text().strip(), lifecycle.OLD_IMAGE)
            self.assertEqual((lifecycle.fake_state / "migrations").read_text().strip(), "1")
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertFalse(lifecycle.state.exists())
            self.assertFalse(lifecycle.script.exists())

    def test_fake_lifecycle_installs_and_rolls_back_oidf_ca_in_same_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
            self.assertIsNotNone(lifecycle.oidf_ca_target)
            self.assertIsNotNone(lifecycle.previous_oidf_ca)
            target = lifecycle.oidf_ca_target
            previous = lifecycle.previous_oidf_ca

            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            self.assertNotEqual(target.read_bytes(), previous)
            self.assertIn(
                b"BEGIN CERTIFICATE",
                target.read_bytes(),
            )

            rolled_back = lifecycle.run("rollback")
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertEqual(target.read_bytes(), previous)
            systemctl_log = (lifecycle.fake_state / "systemctl.log").read_text(
                encoding="utf-8"
            )
            self.assertGreaterEqual(systemctl_log.count("reload nginx.service"), 2)

    def test_fake_lifecycle_rejects_tampered_oidf_ca_rollback_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            lifecycle.oidf_ca_backup.write_bytes(b"tampered backup\n")

            rolled_back = lifecycle.run("rollback")
            self.assertNotEqual(rolled_back.returncode, 0)
            self.assertEqual(lifecycle.record_status(), "rollback-failed")
            self.assertTrue(lifecycle.state.exists())

    def test_fake_lifecycle_rejects_proxy_fingerprint_success_override(self) -> None:
        unsafe_fragments = {
            "plain": "~*^legacy-fingerprint$ SUCCESS;\n",
            "quoted": '~*^legacy-fingerprint$ "SUCCESS";\n',
            "spaced-semicolon": "~*^legacy-fingerprint$ SUCCESS ;\n",
            "commented-safe-active-unsafe": (
                "# proxy_set_header X-SSL-Client-Verify $ssl_client_verify;\n"
                "proxy_set_header X-SSL-Client-Verify $http_x_ssl_client_verify;\n"
            ),
            "duplicate-safe-unsafe": (
                "proxy_set_header X-SSL-Client-Verify $http_x_ssl_client_verify;\n"
            ),
            "lowercase-dangerous": (
                "proxy_set_header x-ssl-client-verify $http_x_ssl_client_verify;\n"
                "proxy_set_header x-ssl-client-cert $http_x_ssl_client_cert;\n"
            ),
            "quoted-lowercase-dangerous": (
                'proxy_set_header "x-ssl-client-verify" $http_x_ssl_client_verify;\n'
                'proxy_set_header "x-ssl-client-cert" $http_x_ssl_client_cert;\n'
            ),
            "decoy-dump-boundary": (
                "# configuration file /tmp/decoy.conf:\n"
                "proxy_set_header X-SSL-Client-Verify $http_x_ssl_client_verify;\n"
                "proxy_set_header X-SSL-Client-Cert $http_x_ssl_client_cert;\n"
            ),
            "same-line-dangerous": (
                "proxy_set_header X-SSL-Client-Verify $ssl_client_verify; "
                "proxy_set_header x-ssl-client-verify $http_x_ssl_client_verify;\n"
                "proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert; "
                "proxy_set_header x-ssl-client-cert $http_x_ssl_client_cert;\n"
            ),
            "same-line-include": "server { include /tmp/unsafe.conf; }\n",
        }
        for name, fragment in unsafe_fragments.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
                lifecycle.angie_oidf_config.write_text(
                    lifecycle.angie_oidf_config.read_text(encoding="utf-8") + fragment,
                    encoding="utf-8",
                )

                deployed = lifecycle.run("deploy")
                self.assertNotEqual(deployed.returncode, 0)
                self.assertEqual(
                    lifecycle.oidf_ca_target.read_bytes(),
                    lifecycle.previous_oidf_ca,
                )

    def test_fake_lifecycle_accepts_safe_lowercase_proxy_header_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
            config = lifecycle.angie_oidf_config.read_text(encoding="utf-8")
            lifecycle.angie_oidf_config.write_text(
                config.replace("X-SSL-Client-Verify", "x-ssl-client-verify").replace(
                    "X-SSL-Client-Cert", "x-ssl-client-cert"
                ),
                encoding="utf-8",
            )

            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)

    def test_fake_lifecycle_fails_closed_when_sha256sum_partially_fails(self) -> None:
        for name in (
            "oidf-mtls-ca-bundle.pem",
            "oidf-public-plan-configs.manifest.json",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)

                deployed = lifecycle.run("deploy", FAKE_SHA256_FAILURE_PATTERN=name)
                self.assertNotEqual(deployed.returncode, 0)
                self.assertEqual(
                    lifecycle.oidf_ca_target.read_bytes(),
                    lifecycle.previous_oidf_ca,
                )

    def test_fake_lifecycle_rejects_same_line_different_ca_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
            lifecycle.angie_oidf_config.write_text(
                lifecycle.angie_oidf_config.read_text(encoding="utf-8")
                + (
                    f"ssl_client_certificate {lifecycle.oidf_ca_target.as_posix()}; "
                    "ssl_client_certificate /tmp/different-ca.pem;\n"
                ),
                encoding="utf-8",
            )

            deployed = lifecycle.run("deploy")
            self.assertNotEqual(deployed.returncode, 0)
            self.assertEqual(
                lifecycle.oidf_ca_target.read_bytes(),
                lifecycle.previous_oidf_ca,
            )

    def test_fake_lifecycle_sha256_multiline_garbage_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)

            deployed = lifecycle.run(
                "deploy",
                FAKE_SHA256_GARBAGE_PATTERN="oidf-mtls-ca-bundle.pem",
            )
            self.assertNotEqual(deployed.returncode, 0)
            self.assertEqual(
                lifecycle.oidf_ca_target.read_bytes(),
                lifecycle.previous_oidf_ca,
            )

    def test_fake_lifecycle_detects_config_replacement_before_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)

            deployed = lifecycle.run("deploy", MUTATE_ANGIE_CONFIG_ON_TEST="1")
            self.assertNotEqual(deployed.returncode, 0)
            self.assertIn("Angie OIDF configuration changed", deployed.stderr)
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertEqual(
                lifecycle.oidf_ca_target.read_bytes(),
                lifecycle.previous_oidf_ca,
            )

    def test_fake_lifecycle_restores_safe_config_after_reload_race(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
            safe_config = lifecycle.angie_oidf_config.read_bytes()

            deployed = lifecycle.run("deploy", MUTATE_ANGIE_CONFIG_ON_RELOAD="1")
            self.assertNotEqual(deployed.returncode, 0)
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertEqual(lifecycle.oidf_ca_target.read_bytes(), lifecycle.previous_oidf_ca)
            self.assertEqual(lifecycle.angie_oidf_config.read_bytes(), safe_config)
            self.assertEqual(
                (lifecycle.fake_state / "active-angie-config").read_bytes(),
                safe_config,
            )

    def test_fake_lifecycle_requires_a_new_worker_after_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)

            deployed = lifecycle.run(
                "deploy",
                RELOAD_DROPS_OLD_ONLY="1",
                ANGIE_RELOAD_WAIT_SECONDS="1",
            )
            self.assertNotEqual(deployed.returncode, 0)
            self.assertIn("Angie workers did not rotate", deployed.stderr)
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertEqual(lifecycle.oidf_ca_target.read_bytes(), lifecycle.previous_oidf_ca)

    def test_fake_lifecycle_requires_old_worker_generation_to_drain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)

            deployed = lifecycle.run(
                "deploy",
                RELOAD_RETAINS_OLD_WITH_NEW="1",
                ANGIE_RELOAD_WAIT_SECONDS="1",
            )
            self.assertNotEqual(deployed.returncode, 0)
            self.assertIn("Angie workers did not rotate", deployed.stderr)
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertEqual(lifecycle.oidf_ca_target.read_bytes(), lifecycle.previous_oidf_ca)

    def test_fake_lifecycle_rollback_sha256_checks_fail_closed(self) -> None:
        for target in ("backup", "restored"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                lifecycle = FakeLifecycle(Path(directory), enable_oidf_ca=True)
                deployed = lifecycle.run("deploy")
                self.assertEqual(deployed.returncode, 0, deployed.stderr)
                pattern = (
                    lifecycle.oidf_ca_backup.name
                    if target == "backup"
                    else lifecycle.oidf_ca_target.name
                )

                rolled_back = lifecycle.run(
                    "rollback",
                    FAKE_SHA256_FAILURE_PATTERN=pattern,
                )
                self.assertNotEqual(rolled_back.returncode, 0)
                self.assertEqual(lifecycle.record_status(), "rollback-failed")

    def test_fake_lifecycle_old_image_run_failure_is_nonzero_and_preserves_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory))
            ui = lifecycle.ui_path
            ui.mkdir()
            (ui / "index.html").write_text("old-ui", encoding="utf-8")
            deployments = lifecycle.deployment / "deployments"
            deployments.mkdir()
            previous_record = deployments / "previous-record"
            previous_record.write_text("previous\n", encoding="utf-8")
            current = deployments / "current.json"
            subprocess.run(
                [
                    git_bash(), "-lc", 'ln -s "$1" "$2"', "_",
                    bash_path(previous_record), bash_path(current),
                ],
                check=True, capture_output=True, env=lifecycle.env,
            )
            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            candidate_record = lifecycle.deployment_record()
            subprocess.run(
                [
                    git_bash(), "-lc", 'rm -f "$1"; ln -s "$2" "$1"', "_",
                    bash_path(current), bash_path(candidate_record),
                ],
                check=True, capture_output=True, env=lifecycle.env,
            )
            failed = lifecycle.run("rollback", FAIL_OLD_IMAGE_RUN="1")
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(lifecycle.record_status(), "rollback-failed")
            self.assertEqual((ui / "index.html").read_text(encoding="utf-8"), "old-ui")
            restored_current = subprocess.run(
                [git_bash(), "-lc", 'readlink "$1"', "_", bash_path(current)],
                check=True, capture_output=True, text=True, env=lifecycle.env,
            ).stdout.strip()
            self.assertEqual(restored_current, bash_path(previous_record))
            self.assertTrue(lifecycle.state.exists())
            self.assertTrue(lifecycle.script.exists())
            self.assertTrue((lifecycle.deployment / "deployments" / "active-deployment").exists())
            self.assertTrue(Path(str(lifecycle.state) + ".lease-rollback").exists())

    def test_fake_lifecycle_ui_release_is_worker_readable_and_served_at_ui_auth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory))
            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            release = lifecycle.ui_releases / re.search(
                r"^FRONTEND_COMMIT='([^']+)'",
                lifecycle.script.read_text(encoding="utf-8"),
                re.M,
            ).group(1)
            self.assertEqual((release / "index.html").read_text(encoding="utf-8"), "candidate")
            linked_release = subprocess.run(
                [git_bash(), "-lc", 'readlink "$1"', "_", bash_path(lifecycle.ui_path)],
                check=True, capture_output=True, text=True, env=lifecycle.env,
            ).stdout.strip()
            self.assertEqual(linked_release, bash_path(release))

            runuser_log = (lifecycle.fake_state / "runuser.log").read_text(encoding="utf-8")
            self.assertIn("-u www -- test -r", runuser_log)
            self.assertIn("auth-releases", runuser_log)
            self.assertIn("/auth/ui/index.html", runuser_log)
            if os.name != "nt":
                for directory_path in (lifecycle.public_root, lifecycle.ui_releases, release):
                    self.assertEqual(
                        stat.S_IMODE(directory_path.stat().st_mode) & 0o005,
                        0o005,
                        f"Angie worker cannot traverse {directory_path}",
                    )
                self.assertNotEqual(
                    stat.S_IMODE((release / "index.html").stat().st_mode) & 0o004,
                    0,
                )

            if os.name != "nt":
                handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(
                    *args, directory=str(lifecycle.web_root), **kwargs
                )
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{server.server_port}/ui/index.html",
                        timeout=5,
                    ) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), b"candidate")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_fake_lifecycle_corrupt_or_partial_state_fails_closed_and_preserves_evidence(self) -> None:
        for payload in ("{", '{"schema":1}'):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                lifecycle = FakeLifecycle(Path(directory))
                deployed = lifecycle.run("deploy")
                self.assertEqual(deployed.returncode, 0, deployed.stderr)
                lifecycle.state.write_text(payload, encoding="utf-8")
                failed = lifecycle.run("rollback")
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(lifecycle.record_status(), "rollback-failed")
                self.assertTrue(lifecycle.state.exists())
                self.assertTrue(lifecycle.script.exists())

    def test_fake_lifecycle_failed_restored_health_is_rollback_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory))
            self.assertEqual(lifecycle.run("deploy").returncode, 0)
            failed = lifecycle.run("rollback", FAIL_ROLLBACK_HEALTH="1")
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(lifecycle.record_status(), "rollback-failed")
            self.assertTrue(lifecycle.state.exists())

    def test_fake_lifecycle_timeout_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), lease_seconds=3)
            deployed = lifecycle.run("deploy")
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            for _ in range(30):
                if not lifecycle.state.exists():
                    break
                subprocess.run([git_bash(), "-lc", "sleep 0.1"], check=True)
            self.assertFalse(lifecycle.state.exists(), "watchdog did not finish rollback")
            self.assertEqual(lifecycle.record_status(), "rolled-back")
            self.assertEqual((lifecycle.fake_state / "container-image").read_text().strip(), lifecycle.OLD_IMAGE)

    def test_fake_lifecycle_commit_and_expiry_race_has_one_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = FakeLifecycle(Path(directory), lease_seconds=30)
            self.assertEqual(lifecycle.run("deploy").returncode, 0)
            commands = [
                [git_bash(), "-lc", 'export PATH="$1:$PATH"; exec bash "$2" commit', "_", bash_path(lifecycle.fake_bin), bash_path(lifecycle.script)],
                [git_bash(), "-lc", 'export PATH="$1:$PATH"; exec bash "$2" expire', "_", bash_path(lifecycle.fake_bin), bash_path(lifecycle.script)],
            ]
            processes = [
                subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=lifecycle.env)
                for command in commands
            ]
            results = [process.communicate(timeout=10) + (process.returncode,) for process in processes]
            self.assertIn(lifecycle.record_status(), {"deployment-success", "rolled-back"}, results)
            self.assertFalse(lifecycle.state.exists())
            self.assertFalse((lifecycle.deployment / "deployments" / "active-deployment").exists())


if __name__ == "__main__":
    unittest.main()
