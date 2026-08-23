#!/usr/bin/env bash
set -euo pipefail

IGNORE_REGEX='(^|/)(tests?|benches|examples|migrations)(/|\.rs$)|(^|/)cargo/registry/src/|(^|/)(?:crates/authorization-server/src/)?(schema|db|lib)\.rs$|(^|/)crates/authorization-server/src/domain/(rows|mod|state|keyset)\.rs$|(^|/)domain/(rows|mod|state|keyset)\.rs$|(^|/)crates/authorization-server/src/bootstrap/(routes|observability|mod)\.rs$|(^|/)bootstrap/(routes|observability|mod)\.rs$|(^|/)support/(valkey|mod)\.rs$|(^|/)crates/authorization-server/src/support/(valkey|mod)\.rs$|(^|/)crates/authorization-server/src/http/(mod|admin|profile|token)\.rs$|(^|/)http/(mod|admin|profile|token)\.rs$|(^|/)http/admin/clients/mod\.rs$|(^|/)crates/authorization-server/src/http/admin/clients/mod\.rs$|(^|/)http/auth/mod\.rs$|(^|/)crates/authorization-server/src/http/auth/mod\.rs$|(^|/)http/authorization/mod\.rs$|(^|/)crates/authorization-server/src/http/authorization/mod\.rs$|(^|/)main\.rs$|(^|/)crates/authorization-server/src/main\.rs$|(^|/)bin/nazo_oauth_(keyctl|migrate)\.rs$|(^|/)crates/authorization-server/src/bin/nazo_oauth_(keyctl|migrate)\.rs$'

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEFAULT_CARGO_TARGET_DIR="$SCRIPT_ROOT/target/codecov-coverage"
REQUESTED_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$DEFAULT_CARGO_TARGET_DIR}"
if ! command -v realpath >/dev/null 2>&1; then
  echo "realpath is required to validate CARGO_TARGET_DIR" >&2
  exit 2
fi
if ! CARGO_TARGET_DIR="$(realpath -m -- "$REQUESTED_CARGO_TARGET_DIR")"; then
  echo "unable to resolve CARGO_TARGET_DIR" >&2
  exit 2
fi
if [[ "$CARGO_TARGET_DIR" != "$DEFAULT_CARGO_TARGET_DIR" ]]; then
  echo "refusing CARGO_TARGET_DIR outside the repository-owned codecov target: $CARGO_TARGET_DIR" >&2
  exit 2
fi
export CARGO_TARGET_DIR
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

COVERAGE_DIR="${CARGO_TARGET_DIR%/}/llvm-cov-target"
BIN_DIR="${CARGO_TARGET_DIR%/}/debug"
RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
case "$RUST_HOST" in
  *-windows-*) EXECUTABLE_SUFFIX=".exe" ;;
  *) EXECUTABLE_SUFFIX="" ;;
esac
SERVER_BIN="$BIN_DIR/nazoauth$EXECUTABLE_SUFFIX"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    PYTHON_BIN="python"
  fi
fi
SERVER_PID=""
SIGNED_SERVER_PID=""
CODECOV_OWNER_LABEL="nazoauth-codecov-lcov"
DEFAULT_POSTGRES_CONTAINER="nazo-oauth-codecov-postgres"
DEFAULT_VALKEY_CONTAINER="nazo-oauth-codecov-valkey"
POSTGRES_CONTAINER="${CODECOV_POSTGRES_CONTAINER:-$DEFAULT_POSTGRES_CONTAINER}"
VALKEY_CONTAINER="${CODECOV_VALKEY_CONTAINER:-$DEFAULT_VALKEY_CONTAINER}"
if [[ "$POSTGRES_CONTAINER" != "$DEFAULT_POSTGRES_CONTAINER" ]]; then
  echo "refusing CODECOV_POSTGRES_CONTAINER override; only $DEFAULT_POSTGRES_CONTAINER is script-owned" >&2
  exit 2
fi
if [[ "$VALKEY_CONTAINER" != "$DEFAULT_VALKEY_CONTAINER" ]]; then
  echo "refusing CODECOV_VALKEY_CONTAINER override; only $DEFAULT_VALKEY_CONTAINER is script-owned" >&2
  exit 2
fi

remove_owned_container() {
  local container_name="$1"
  if ! docker inspect "$container_name" >/dev/null 2>&1; then
    return 0
  fi
  local owner
  owner="$(docker inspect --format '{{ index .Config.Labels "io.nazoauth.owner" }}' "$container_name" 2>/dev/null || true)"
  if [[ "$owner" != "$CODECOV_OWNER_LABEL" ]]; then
    echo "refusing to remove unowned Docker container $container_name" >&2
    return 1
  fi
  docker rm -f "$container_name"
}

POSTGRES_HOST="${CODECOV_POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${CODECOV_POSTGRES_PORT:-15432}"
VALKEY_HOST="${CODECOV_VALKEY_HOST:-127.0.0.1}"
VALKEY_PORT="${CODECOV_VALKEY_PORT:-16383}"
PRIMARY_SERVER_PORT="${CODECOV_PRIMARY_SERVER_PORT:-18000}"
SIGNED_SERVER_PORT="${CODECOV_SIGNED_SERVER_PORT:-18001}"
if [[ -n "${CODECOV_DOCKER_NETWORK:-}" ]]; then
  echo "refusing CODECOV_DOCKER_NETWORK override; coverage owns its loopback ports" >&2
  exit 2
fi
case "$POSTGRES_HOST" in
  127.0.0.1) ;;
  *) echo "refusing CODECOV_POSTGRES_HOST outside the script-owned fixture" >&2; exit 2 ;;
esac
case "$POSTGRES_PORT" in
  15432) ;;
  *) echo "refusing CODECOV_POSTGRES_PORT outside the script-owned fixture" >&2; exit 2 ;;
esac
case "$VALKEY_HOST" in
  127.0.0.1) ;;
  *) echo "refusing CODECOV_VALKEY_HOST outside the script-owned fixture" >&2; exit 2 ;;
esac
case "$VALKEY_PORT" in
  16383) ;;
  *) echo "refusing CODECOV_VALKEY_PORT outside the script-owned fixture" >&2; exit 2 ;;
esac

validate_server_port() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]{3,4}$ ]]; then
    echo "$name must be an unprivileged TCP port between 1024 and 65535" >&2
    exit 2
  fi
  local numeric_value=$((10#$value))
  if (( numeric_value < 1024 || numeric_value > 65535 )); then
    echo "$name must be an unprivileged TCP port between 1024 and 65535" >&2
    exit 2
  fi
}
validate_server_port CODECOV_PRIMARY_SERVER_PORT "$PRIMARY_SERVER_PORT"
validate_server_port CODECOV_SIGNED_SERVER_PORT "$SIGNED_SERVER_PORT"
if [[ "$PRIMARY_SERVER_PORT" == "$SIGNED_SERVER_PORT"
  || "$PRIMARY_SERVER_PORT" == "$POSTGRES_PORT"
  || "$PRIMARY_SERVER_PORT" == "$VALKEY_PORT"
  || "$SIGNED_SERVER_PORT" == "$POSTGRES_PORT"
  || "$SIGNED_SERVER_PORT" == "$VALKEY_PORT" ]]
then
  echo "coverage server and fixture ports must be distinct" >&2
  exit 2
fi
"$PYTHON_BIN" - "$PRIMARY_SERVER_PORT" "$SIGNED_SERVER_PORT" <<'PY'
import socket
import sys

sockets = []
try:
    for raw_port in sys.argv[1:]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(("127.0.0.1", int(raw_port)))
        sockets.append(listener)
except OSError as error:
    raise SystemExit(f"coverage server port is unavailable: {error}") from error
finally:
    for listener in sockets:
        listener.close()
PY
PRIMARY_SERVER_URL="http://127.0.0.1:${PRIMARY_SERVER_PORT}"
SIGNED_SERVER_URL="http://127.0.0.1:${SIGNED_SERVER_PORT}"

cleanup() {
  if [[ -n "$SIGNED_SERVER_PID" ]]; then
    kill -INT "$SIGNED_SERVER_PID" 2>/dev/null || true
    wait "$SIGNED_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]]; then
    kill -INT "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  remove_owned_container "$POSTGRES_CONTAINER" || true
  remove_owned_container "$VALKEY_CONTAINER" || true
}
trap cleanup EXIT

profile_path() {
  case "$COVERAGE_DIR" in
    /*) printf '%s/%s' "$COVERAGE_DIR" "$1" ;;
    *) printf '%s/%s/%s' "$PWD" "$COVERAGE_DIR" "$1" ;;
  esac
}

cargo llvm-cov clean --workspace
eval "$(cargo llvm-cov show-env --sh)"
if [[ "${CARGO_TARGET_DIR:-}" != "$DEFAULT_CARGO_TARGET_DIR" ]]; then
  echo "cargo llvm-cov changed CARGO_TARGET_DIR outside the repository-owned codecov target" >&2
  exit 2
fi
if [[ "${CODECOV_FORCE_CARGO_CLEAN:-0}" == "1" ]]; then
  cargo clean
fi

remove_owned_container "$POSTGRES_CONTAINER"
remove_owned_container "$VALKEY_CONTAINER"
postgres_port_args=(-p "${POSTGRES_PORT}:5432")
valkey_port_args=(-p "${VALKEY_PORT}:6379")
docker run -d --name "$POSTGRES_CONTAINER" \
  --label "io.nazoauth.owner=$CODECOV_OWNER_LABEL" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=oauth \
  "${postgres_port_args[@]}" \
  postgres:18-alpine
docker run -d --name "$VALKEY_CONTAINER" \
  --label "io.nazoauth.owner=$CODECOV_OWNER_LABEL" \
  "${valkey_port_args[@]}" \
  valkey/valkey:8-alpine

services_ready=false
for attempt in $(seq 1 60); do
  if docker exec "$POSTGRES_CONTAINER" sh -lc \
      'pg_isready -U postgres -d oauth >/dev/null && psql -U postgres -d oauth -c "select 1" >/dev/null' \
    && docker exec "$VALKEY_CONTAINER" valkey-cli ping >/dev/null 2>&1
  then
    services_ready=true
    break
  fi
  sleep 2
done
if [[ "$services_ready" != "true" ]]; then
  docker exec "$POSTGRES_CONTAINER" pg_isready -U postgres -d oauth || true
  docker exec "$VALKEY_CONTAINER" valkey-cli ping || true
  echo "Coverage dependencies did not become ready." >&2
  exit 1
fi
docker exec "$POSTGRES_CONTAINER" pg_isready -U postgres -d oauth
docker exec "$VALKEY_CONTAINER" valkey-cli ping
docker exec "$POSTGRES_CONTAINER" \
  psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE DATABASE nazo_audit_test'
docker exec "$POSTGRES_CONTAINER" \
  psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE DATABASE nazo_workspace_test'

export DATABASE_URL="postgresql://postgres:postgres@${POSTGRES_HOST}:${POSTGRES_PORT}/oauth"
export NAZO_AUDIT_TEST_DATABASE_URL="postgresql://postgres:postgres@${POSTGRES_HOST}:${POSTGRES_PORT}/nazo_audit_test"
export VALKEY_URL="redis://${VALKEY_HOST}:${VALKEY_PORT}/0"
WORKSPACE_DATABASE_URL="postgresql://postgres:postgres@${POSTGRES_HOST}:${POSTGRES_PORT}/nazo_workspace_test"
WORKSPACE_VALKEY_URL="redis://${VALKEY_HOST}:${VALKEY_PORT}/1"
export VALKEY_COMMAND_TIMEOUT_MS='1000'
export BIND="127.0.0.1:${PRIMARY_SERVER_PORT}"
export ISSUER="$PRIMARY_SERVER_URL"
export MTLS_ENDPOINT_BASE_URL="$PRIMARY_SERVER_URL"
export FRONTEND_BASE_URL='http://127.0.0.1:3000'
export CORS_ALLOWED_ORIGINS='http://127.0.0.1:3000'
export COOKIE_SECURE='false'
export SESSION_COOKIE_NAME='nazo_oauth_session'
export CSRF_COOKIE_NAME='nazo_oauth_csrf'
export EMAIL_DELIVERY='smtp'
export EMAIL_SMTP_HOST='127.0.0.1'
export EMAIL_SMTP_PORT='1025'
export EMAIL_SMTP_TLS='none'
export EMAIL_SMTP_USERNAME=''
export EMAIL_SMTP_PASSWORD=''
export EMAIL_FROM='Nazo OAuth <no-reply@example.com>'
export EMAIL_CODE_SEND_COOLDOWN_SECONDS='1'
export EMAIL_CODE_PEER_COOLDOWN_SECONDS='1'
export EMAIL_CODE_DEV_RESPONSE_ENABLED='false'
export AVATAR_STORAGE_DIR='runtime/codecov/avatars'
export JWK_KEYS_DIR='runtime/codecov/keys'
export REQUIRE_PUSHED_AUTHORIZATION_REQUESTS='false'
# Coverage owns and migrates an ephemeral database with its bootstrap
# superuser.  Keep production's strict least-privilege default intact while
# explicitly selecting the documented non-strict repository preflight for
# this disposable functional-test fixture.
export SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE='false'
# Exercise the real encrypted TOTP persistence boundary with a fresh key that
# exists only for this coverage run.  Both server processes inherit the same
# value so they can read each other's envelopes without weakening the
# production fail-closed requirement.
export MFA_TOTP_ENCRYPTION_KEY_ID='codecov-ephemeral-v1'
export MFA_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export ENABLE_AUTHORIZATION_DETAILS='true'
export RUNTIME_INSTANCE_ID='codecov-primary'
PRIMARY_INSTANCE_IDENTITY_DIR="$SCRIPT_ROOT/runtime/codecov/instance-primary"
SIGNED_INSTANCE_IDENTITY_DIR="$SCRIPT_ROOT/runtime/codecov/instance-signed"
export INSTANCE_IDENTITY_DIR="$PRIMARY_INSTANCE_IDENTITY_DIR"
# 覆盖率 E2E 使用与服务端相同的 provider registry，不再维护单 provider 配置入口。
export FEDERATION_PROVIDER_CONFIGS="[{\"provider_id\":\"codecov-oidc\",\"enabled\":true,\"display_name\":\"Codecov OIDC\",\"adapter_type\":\"oidc\",\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/authorize\",\"token_endpoint\":\"https://issuer.example/token\",\"jwks_url\":\"https://issuer.example/jwks\",\"client_id\":\"codecov-oidc-client\",\"client_secret\":\"codecov-oidc-secret\",\"redirect_uri\":\"${PRIMARY_SERVER_URL}/auth/federation/codecov-oidc/callback\",\"scopes\":\"openid email profile\"}]"
export E2E_OIDC_PROVIDER_ID='codecov-oidc'
export E2E_OIDC_REDIRECT_URI="${PRIMARY_SERVER_URL}/auth/federation/codecov-oidc/callback"
export FEDERATION_SAML_GATEWAY_ENABLED='true'
export FEDERATION_SAML_GATEWAY_ISSUER='codecov-saml-gateway'
export FEDERATION_SAML_GATEWAY_AUDIENCE='nazo-oauth-codecov'
export FEDERATION_SAML_GATEWAY_SECRET='codecov-saml-gateway-secret-000000'
export RUST_LOG="${RUST_LOG:-warn}"

mkdir -p runtime/codecov/avatars runtime/codecov/keys \
  "$PRIMARY_INSTANCE_IDENTITY_DIR" "$SIGNED_INSTANCE_IDENTITY_DIR" "$COVERAGE_DIR"
"$PYTHON_BIN" - <<'PY'
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

key_dir = Path(os.environ["JWK_KEYS_DIR"])
key_dir.mkdir(parents=True, exist_ok=True)
keyset_path = key_dir / "keyset.json"
if keyset_path.is_file():
    keyset = json.loads(keyset_path.read_text(encoding="utf-8"))
else:
    keyset = {"active_kid": "", "keys": []}

keys = keyset.setdefault("keys", [])
if not isinstance(keys, list):
    raise RuntimeError(f"keyset keys must be an array: {keyset_path}")

now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_key_path(entry):
    if (
        isinstance(entry, dict)
        and entry.get("backend", "local-pem") == "local-pem"
        and isinstance(entry.get("file"), str)
    ):
        return key_dir / entry["file"]
    return None


def is_server_rsa_pem(path: Path) -> bool:
    if not path.is_file():
        return False
    first_line = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return bool(first_line and first_line[0].strip() == "-----BEGIN RSA PRIVATE KEY-----")


def usable_key_entry(entry) -> bool:
    if not isinstance(entry, dict):
        return True
    if entry.get("backend", "local-pem") != "local-pem":
        return True
    if entry.get("alg") not in {"RS256", "PS256"}:
        return True
    path = local_key_path(entry)
    return path is not None and is_server_rsa_pem(path)


keys[:] = [entry for entry in keys if usable_key_entry(entry)]
if keyset.get("active_kid") and not any(
    isinstance(entry, dict) and entry.get("kid") == keyset.get("active_kid")
    for entry in keys
):
    keyset["active_kid"] = ""


def live_local_key(alg: str):
    for entry in keys:
        if (
            isinstance(entry, dict)
            and entry.get("alg") == alg
            and entry.get("retire_at") is None
            and entry.get("backend", "local-pem") == "local-pem"
            and isinstance(entry.get("file"), str)
            and (key_dir / entry["file"]).is_file()
        ):
            return entry
    return None


def create_local_rsa_key(alg: str):
    kid = f"{alg.lower()}-codecov-{uuid.uuid4().hex}"
    file_name = f"{kid}.pem"
    target = key_dir / file_name
    subprocess.run(
        [
            "openssl",
            "genrsa",
            "-traditional",
            "-out",
            str(target),
            "2048",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    target.chmod(0o600)
    entry = {
        "kid": kid,
        "alg": alg,
        "file": file_name,
        "created_at": now,
        "retire_at": None,
    }
    keys.append(entry)
    return entry


rs256 = live_local_key("RS256") or create_local_rsa_key("RS256")
live_local_key("PS256") or create_local_rsa_key("PS256")
if not keyset.get("active_kid"):
    keyset["active_kid"] = rs256["kid"]
keyset_path.write_text(json.dumps(keyset, indent=2) + "\n", encoding="utf-8")
os.chmod(keyset_path, 0o600)
PY
export LLVM_PROFILE_FILE="$(profile_path 'cargo-%p-%m.profraw')"
cargo test --locked -p nazo-postgres --test migrations \
  pending_migrations_create_all_runtime_module_state_tables
cargo build --locked --workspace --all-features --bin nazoauth

INSTANCE_IDENTITY_DIR="$PRIMARY_INSTANCE_IDENTITY_DIR" \
LLVM_PROFILE_FILE="$(profile_path 'server-%p.profraw')" "$SERVER_BIN" server &
SERVER_PID=$!
ENABLE_FAPI_HTTP_SIGNATURES='true' \
  RUNTIME_INSTANCE_ID='codecov-signed' \
  INSTANCE_IDENTITY_DIR="$SIGNED_INSTANCE_IDENTITY_DIR" \
  BIND="127.0.0.1:${SIGNED_SERVER_PORT}" \
  LLVM_PROFILE_FILE="$(profile_path 'signed-server-%p.profraw')" \
  "$SERVER_BIN" server &
SIGNED_SERVER_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "$PRIMARY_SERVER_URL/health" >/dev/null \
    && curl -fsS "$SIGNED_SERVER_URL/health" >/dev/null
  then
    break
  fi
  sleep 2
done
curl -fsS "$PRIMARY_SERVER_URL/health" >/dev/null
curl -fsS "$SIGNED_SERVER_URL/health" >/dev/null

kill -INT "$SIGNED_SERVER_PID"
wait "$SIGNED_SERVER_PID" || true
SIGNED_SERVER_PID=""
kill -INT "$SERVER_PID"
wait "$SERVER_PID" || true
SERVER_PID=""

# The E2E seed intentionally leaves durable identity and protocol state behind.
# Workspace integration tests include process-wide migration and key-rotation
# invariants, so they must start from their own migrated database and Valkey DB
# rather than inheriting another test phase's credentials or key versions.
export DATABASE_URL="$WORKSPACE_DATABASE_URL"
export NAZO_TEST_DATABASE_URL="$WORKSPACE_DATABASE_URL"
export VALKEY_URL="$WORKSPACE_VALKEY_URL"
cargo test --locked -p nazo-postgres --test migrations \
  pending_migrations_create_all_runtime_module_state_tables

TEST_OBJECT_MANIFEST="$COVERAGE_DIR/test-objects.jsonl"
cargo test --locked --workspace --all-features --lib --bins --tests \
  --no-run --message-format=json > "$TEST_OBJECT_MANIFEST"
cargo test --locked --workspace --all-features --lib --bins --tests

# These integration-heavy protocol tests are intentionally excluded from the
# default workspace run because they require live PostgreSQL and Valkey. This
# coverage phase owns both services, so execute the explicit allowlist here.
# Keep the allowlist narrow: future ignored tests may depend on external state.
COVERAGE_LIVE_TESTS=(
  live_immediate_offer_pre_authorized_credential_replay_and_notification
  live_deferred_credential_claim_response_replay_and_notification
  live_access_enforces_dpop_binding_and_validates_presented_proof
  live_offer_enforces_subject_dataset_lifetime_and_transaction_code_policy
  par_fapi2_rejects_shared_secret_client_auth_after_authentication
)
for test_name in "${COVERAGE_LIVE_TESTS[@]}"; do
  cargo test --locked -p nazo-oauth-server --lib "$test_name" -- --ignored
done

# Export exactly the test executables recorded by Cargo's JSON artifact stream.
# This is the authoritative workspace object graph on every host, including
# Windows where inferring a binary path without Cargo's `.exe` suffix fails.
LLVM_TOOLS_DIR="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin"
mapfile -t SERVER_PROFRAWS < <(
  find "$COVERAGE_DIR" -type f \
    \( -name 'server-*.profraw' -o -name 'signed-server-*.profraw' \)
)
mapfile -t TEST_PROFRAWS < <(
  find "$COVERAGE_DIR" -type f \
    -name 'cargo-*.profraw'
)
if [[ "${#SERVER_PROFRAWS[@]}" -eq 0 || "${#TEST_PROFRAWS[@]}" -eq 0 ]]; then
  echo "Both server and test llvm-cov profile files are required." >&2
  exit 1
fi
"$LLVM_TOOLS_DIR/llvm-profdata" merge -sparse "${SERVER_PROFRAWS[@]}" \
  -o "$COVERAGE_DIR/server.profdata"
"$LLVM_TOOLS_DIR/llvm-profdata" merge -sparse "${TEST_PROFRAWS[@]}" \
  -o "$COVERAGE_DIR/tests.profdata"

test_objects=()
while IFS= read -r object; do
  test_objects+=("$object")
done < <(
  "$PYTHON_BIN" - "$TEST_OBJECT_MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
executables = set()
for line in manifest.read_text(encoding="utf-8").splitlines():
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    if message.get("reason") != "compiler-artifact":
        continue
    executable = message.get("executable")
    if executable and message.get("profile", {}).get("test") is True:
        executables.add(executable)

payload = "\n".join(sorted(executables))
if payload:
    sys.stdout.buffer.write(payload.encode("utf-8") + b"\n")
PY
)

if [[ ! -x "$SERVER_BIN" ]]; then
  echo "Instrumented server binary was not found at $SERVER_BIN." >&2
  exit 1
fi
if [[ "${#test_objects[@]}" -eq 0 ]]; then
  echo "No instrumented test objects were found." >&2
  exit 1
fi

"$LLVM_TOOLS_DIR/llvm-cov" export --format=lcov \
  --instr-profile "$COVERAGE_DIR/server.profdata" \
  --ignore-filename-regex "$IGNORE_REGEX" \
  "$SERVER_BIN" > lcov-e2e.info

# Some integration tests deliberately execute the production binary as a child
# process. Those profiles belong to the test run, not the long-lived E2E server
# run, so export the same binary against tests.profdata as a distinct report.
# The deterministic merger keeps the maximum counter for duplicate records.
"$LLVM_TOOLS_DIR/llvm-cov" export --format=lcov \
  --instr-profile "$COVERAGE_DIR/tests.profdata" \
  --ignore-filename-regex "$IGNORE_REGEX" \
  "$SERVER_BIN" > lcov-process-tests.info

test_reports=()
test_report_index=0
for object in "${test_objects[@]}"; do
  test_report="$COVERAGE_DIR/test-object-${test_report_index}.lcov"
  "$LLVM_TOOLS_DIR/llvm-cov" export --format=lcov \
    --instr-profile "$COVERAGE_DIR/tests.profdata" \
    --ignore-filename-regex "$IGNORE_REGEX" \
    "$object" > "$test_report"
  test_reports+=("$test_report")
  test_report_index=$((test_report_index + 1))
done
"$PYTHON_BIN" scripts/merge_lcov.py \
  --source-root "$PWD" \
  --output lcov.info \
  lcov-e2e.info lcov-process-tests.info "${test_reports[@]}"
