#!/usr/bin/env bash
set -euo pipefail

IGNORE_REGEX='(^|/)(tests?|benches|examples|migrations)(/|\.rs$)|(^|/)cargo/registry/src/|(^|/)(?:crates/authorization-server/src/)?(schema|db|lib)\.rs$|(^|/)crates/authorization-server/src/domain/(rows|mod|state|keyset)\.rs$|(^|/)domain/(rows|mod|state|keyset)\.rs$|(^|/)crates/authorization-server/src/bootstrap/(routes|observability|mod)\.rs$|(^|/)bootstrap/(routes|observability|mod)\.rs$|(^|/)support/(valkey|mod)\.rs$|(^|/)crates/authorization-server/src/support/(valkey|mod)\.rs$|(^|/)crates/authorization-server/src/http/(mod|admin|profile|token)\.rs$|(^|/)http/(mod|admin|profile|token)\.rs$|(^|/)http/admin/clients/mod\.rs$|(^|/)crates/authorization-server/src/http/admin/clients/mod\.rs$|(^|/)http/auth/mod\.rs$|(^|/)crates/authorization-server/src/http/auth/mod\.rs$|(^|/)http/authorization/mod\.rs$|(^|/)crates/authorization-server/src/http/authorization/mod\.rs$|(^|/)crates/authorization-server/src/oidf_seed/|(^|/)oidf_seed/|(^|/)main\.rs$|(^|/)crates/authorization-server/src/main\.rs$|(^|/)bin/nazo_oauth_(keyctl|migrate|seed_oidf)\.rs$|(^|/)crates/authorization-server/src/bin/nazo_oauth_(keyctl|migrate|seed_oidf)\.rs$'

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/codecov-coverage}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

COVERAGE_DIR="${CARGO_TARGET_DIR%/}/llvm-cov-target"
BIN_DIR="${CARGO_TARGET_DIR%/}/debug"
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
POSTGRES_CONTAINER="${CODECOV_POSTGRES_CONTAINER:-nazo-oauth-codecov-postgres}"
VALKEY_CONTAINER="${CODECOV_VALKEY_CONTAINER:-nazo-oauth-codecov-valkey}"
POSTGRES_HOST="${CODECOV_POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${CODECOV_POSTGRES_PORT:-15432}"
VALKEY_HOST="${CODECOV_VALKEY_HOST:-127.0.0.1}"
VALKEY_PORT="${CODECOV_VALKEY_PORT:-16383}"
DOCKER_NETWORK="${CODECOV_DOCKER_NETWORK:-}"
if [[ -n "$DOCKER_NETWORK" ]]; then
  POSTGRES_HOST="${CODECOV_POSTGRES_HOST:-$POSTGRES_CONTAINER}"
  POSTGRES_PORT="${CODECOV_POSTGRES_PORT:-5432}"
  VALKEY_HOST="${CODECOV_VALKEY_HOST:-$VALKEY_CONTAINER}"
  VALKEY_PORT="${CODECOV_VALKEY_PORT:-6379}"
fi

cleanup() {
  if [[ -n "$SIGNED_SERVER_PID" ]]; then
    kill -INT "$SIGNED_SERVER_PID" 2>/dev/null || true
    wait "$SIGNED_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]]; then
    kill -INT "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker rm -f "$POSTGRES_CONTAINER" "$VALKEY_CONTAINER" 2>/dev/null || true
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
if [[ "${CODECOV_FORCE_CARGO_CLEAN:-0}" == "1" ]]; then
  cargo clean
fi

docker rm -f "$POSTGRES_CONTAINER" "$VALKEY_CONTAINER" 2>/dev/null || true
docker_args=()
if [[ -n "$DOCKER_NETWORK" ]]; then
  docker_args+=(--network "$DOCKER_NETWORK")
fi
postgres_port_args=(-p "${POSTGRES_PORT}:5432")
valkey_port_args=(-p "${VALKEY_PORT}:6379")
if [[ -n "$DOCKER_NETWORK" ]]; then
  postgres_port_args=()
  valkey_port_args=()
fi
docker run -d --name "$POSTGRES_CONTAINER" \
  "${docker_args[@]}" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=oauth \
  "${postgres_port_args[@]}" \
  postgres:18-alpine
docker run -d --name "$VALKEY_CONTAINER" \
  "${docker_args[@]}" \
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

export DATABASE_URL="postgresql://postgres:postgres@${POSTGRES_HOST}:${POSTGRES_PORT}/oauth"
export VALKEY_URL="redis://${VALKEY_HOST}:${VALKEY_PORT}/0"
export VALKEY_COMMAND_TIMEOUT_MS='1000'
export BIND='127.0.0.1:18000'
export ISSUER='http://127.0.0.1:18000'
export MTLS_ENDPOINT_BASE_URL='http://127.0.0.1:18000'
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
export AUTH_RATE_LIMIT_MAX_REQUESTS='100000'
export TOKEN_RATE_LIMIT_MAX_REQUESTS='100000'
export TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS='100000'
export REQUIRE_PUSHED_AUTHORIZATION_REQUESTS='false'
export ENABLE_REQUEST_OBJECT='true'
export ENABLE_REQUEST_URI_PARAMETER='true'
export ENABLE_PAR_REQUEST_OBJECT='true'
export ENABLE_AUTHORIZATION_DETAILS='true'
export ENABLE_LEGACY_AUDIENCE_PARAM='true'
export NAZO_RUNTIME_INSTANCE_ID='codecov-primary'
export SCIM_BEARER_TOKEN='codecov-scim-secret'
# 覆盖率 E2E 使用与服务端相同的 provider registry，不再维护单 provider 配置入口。
export FEDERATION_PROVIDER_CONFIGS='[{"provider_id":"codecov-oidc","enabled":true,"display_name":"Codecov OIDC","adapter_type":"oidc","issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_url":"https://issuer.example/jwks","client_id":"codecov-oidc-client","client_secret":"codecov-oidc-secret","redirect_uri":"http://127.0.0.1:18000/auth/federation/codecov-oidc/callback","scopes":"openid email profile"}]'
export E2E_OIDC_PROVIDER_ID='codecov-oidc'
export E2E_OIDC_REDIRECT_URI='http://127.0.0.1:18000/auth/federation/codecov-oidc/callback'
export FEDERATION_SAML_GATEWAY_ENABLED='true'
export FEDERATION_SAML_GATEWAY_ISSUER='codecov-saml-gateway'
export FEDERATION_SAML_GATEWAY_AUDIENCE='nazo-oauth-codecov'
export FEDERATION_SAML_GATEWAY_SECRET='codecov-saml-gateway-secret-000000'
export RUST_LOG="${RUST_LOG:-warn}"

mkdir -p runtime/codecov/avatars runtime/codecov/keys "$COVERAGE_DIR"
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
cargo build --locked --workspace --all-features --bins

LLVM_PROFILE_FILE="$(profile_path 'migrate-%p.profraw')" "$BIN_DIR/nazo-oauth-migrate"
LLVM_PROFILE_FILE="$(profile_path 'server-%p.profraw')" "$BIN_DIR/nazo-oauth-server" &
SERVER_PID=$!
ENABLE_FAPI_HTTP_SIGNATURES='true' \
  NAZO_RUNTIME_INSTANCE_ID='codecov-signed' \
  BIND='127.0.0.1:18001' \
  LLVM_PROFILE_FILE="$(profile_path 'signed-server-%p.profraw')" \
  "$BIN_DIR/nazo-oauth-server" &
SIGNED_SERVER_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:18000/health >/dev/null \
    && curl -fsS http://127.0.0.1:18001/health >/dev/null
  then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:18000/health >/dev/null
curl -fsS http://127.0.0.1:18001/health >/dev/null

E2E_BASE_URL='http://127.0.0.1:18000' \
E2E_SIGNED_BASE_URL='http://127.0.0.1:18001' \
E2E_ISSUER_URL='http://127.0.0.1:18000' \
E2E_DATABASE_URL="$DATABASE_URL" \
E2E_VALKEY_URL="$VALKEY_URL" \
E2E_CORS_ORIGIN='http://127.0.0.1:3000' \
E2E_SAML_GATEWAY_ISSUER="$FEDERATION_SAML_GATEWAY_ISSUER" \
E2E_SAML_GATEWAY_AUDIENCE="$FEDERATION_SAML_GATEWAY_AUDIENCE" \
E2E_SAML_GATEWAY_SECRET="$FEDERATION_SAML_GATEWAY_SECRET" \
E2E_ALLOW_CODEX_COVERAGE_LOOPBACK='1' \
E2E_SMTP_BIND_HOST='127.0.0.1' \
  "$PYTHON_BIN" scripts/full_real_request_e2e.py

kill -INT "$SIGNED_SERVER_PID"
wait "$SIGNED_SERVER_PID" || true
SIGNED_SERVER_PID=""
kill -INT "$SERVER_PID"
wait "$SERVER_PID" || true
SERVER_PID=""

cargo test --locked --workspace --all-features --lib

RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
LLVM_TOOLS_DIR="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin"
mapfile -t PROFRAWS < <(find "$COVERAGE_DIR" -name '*.profraw' -type f)
if [[ "${#PROFRAWS[@]}" -eq 0 ]]; then
  echo "No llvm-cov profile files were generated." >&2
  exit 1
fi
"$LLVM_TOOLS_DIR/llvm-profdata" merge -sparse "${PROFRAWS[@]}" -o "$COVERAGE_DIR/codecov.profdata"

objects=("$BIN_DIR/nazo-oauth-server")
while IFS= read -r object; do
  objects+=("$object")
done < <(find "$BIN_DIR/deps" -maxdepth 1 -type f \( \
  -name 'nazo_oauth_server-*' \
\) ! -name '*.d' ! -name '*.rlib' ! -name '*.rmeta')

if [[ ! -x "${objects[0]}" ]]; then
  echo "Instrumented server binary was not found at ${objects[0]}." >&2
  exit 1
fi

cov_args=(export --format=lcov --instr-profile "$COVERAGE_DIR/codecov.profdata" --ignore-filename-regex "$IGNORE_REGEX" "${objects[0]}")
for object in "${objects[@]:1}"; do
  cov_args+=(--object "$object")
done
"$LLVM_TOOLS_DIR/llvm-cov" "${cov_args[@]}" > lcov.info
