#!/bin/sh
set -eu

# Keep the reviewed release revision as the safe default, while allowing an
# operator to bind this deployment to an explicitly fetched GitLab baseline.
# The value is always checked against the clean checkout before any image is
# reused or built.
expected_revision=${OIDF_SUITE_UPSTREAM_REVISION:-321bc5bc53601b9690b54c023c0cbfac0f0230f2}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NAZOAUTH_SOURCE_DIR=${NAZOAUTH_SOURCE_DIR:-$(CDPATH= cd -- "$script_dir/../.." && pwd)}
export NAZOAUTH_SOURCE_DIR
: "${OIDF_SUITE_SOURCE_DIR:?set OIDF_SUITE_SOURCE_DIR}"
: "${OIDF_SUITE_BASE_URL:?set OIDF_SUITE_BASE_URL}"
: "${OIDF_SUITE_TOKEN_FILE:?set OIDF_SUITE_TOKEN_FILE}"
: "${OIDF_SUITE_TOKEN_METADATA_FILE:=${OIDF_SUITE_TOKEN_ID_FILE:-${OIDF_SUITE_TOKEN_FILE}.metadata}}"
: "${OIDF_OPERATOR_ISSUER:?set OIDF_OPERATOR_ISSUER}"
: "${OIDF_TARGET_HOSTNAME:?set OIDF_TARGET_HOSTNAME}"

# Keep the historical variable name as an alias while storing id + expiry as
# JSON.  A bare id cannot distinguish an expired token after an interrupted
# run, whereas the upstream expiry gives SIGKILL a bounded 24-hour lifetime.
OIDF_SUITE_TOKEN_ID_FILE=$OIDF_SUITE_TOKEN_METADATA_FILE
export OIDF_SUITE_TOKEN_METADATA_FILE OIDF_SUITE_TOKEN_ID_FILE

container_runtime=${OIDF_CONTAINER_RUNTIME:-podman}
case "$container_runtime" in
  podman|docker) ;;
  *)
    echo "OIDF_CONTAINER_RUNTIME must be podman or docker" >&2
    exit 1
    ;;
esac

actual_revision=$(git -C "$OIDF_SUITE_SOURCE_DIR" rev-parse HEAD)
test "$actual_revision" = "$expected_revision" || {
  echo "OIDF suite checkout is $actual_revision, expected $expected_revision" >&2
  exit 1
}
test -z "$(git -C "$OIDF_SUITE_SOURCE_DIR" status --porcelain)" || {
  echo "OIDF suite checkout is not clean" >&2
  exit 1
}
test -f "$OIDF_SUITE_SOURCE_DIR/pom.xml" || {
  echo "official suite pom.xml is absent" >&2
  exit 1
}
source_revision=$(git -C "$NAZOAUTH_SOURCE_DIR" rev-parse HEAD)
test -z "$(git -C "$NAZOAUTH_SOURCE_DIR" status --porcelain)" || {
  echo "NazoAuth source checkout is not clean" >&2
  exit 1
}
suite_image_tag=${OIDF_SUITE_IMAGE_TAG:-$(printf '%.12s' "$expected_revision")}
export OIDF_SUITE_IMAGE_TAG=$suite_image_tag
suite_image="nazoauth-oidf-suite:$suite_image_tag"
nginx_image="nazoauth-oidf-suite-nginx:$suite_image_tag"
pki_init_image="nazoauth-oidf-proxy-pki-init:$suite_image_tag"

image_label() {
  image=$1
  label=$2
  "$container_runtime" image inspect "$image" \
    --format "{{ index .Config.Labels \"$label\" }}" 2>/dev/null || true
}

require_image_label() {
  actual=$(image_label "$1" "$2")
  test "$actual" = "$3" || {
    echo "image $1 has $2=$actual, expected $3" >&2
    exit 1
  }
}

if test "$(image_label "$suite_image" org.opencontainers.image.revision)" != "$expected_revision" || \
   test "$(image_label "$suite_image" run.nazoauth.source.revision)" != "$source_revision"; then
  "$container_runtime" build \
    --build-context "oidf_suite=$OIDF_SUITE_SOURCE_DIR" \
    --build-arg "OIDF_SUITE_UPSTREAM_REVISION=$expected_revision" \
    --label "run.nazoauth.source.revision=$source_revision" \
    --file "$script_dir/Containerfile" \
    --tag "$suite_image" \
    "$NAZOAUTH_SOURCE_DIR"
else
  echo "Reusing exact OIDF Suite image $suite_image"
fi
require_image_label "$suite_image" org.opencontainers.image.revision "$expected_revision"
require_image_label "$suite_image" run.nazoauth.source.revision "$source_revision"

if test "$(image_label "$nginx_image" org.opencontainers.image.revision)" != "$expected_revision" || \
   test "$(image_label "$nginx_image" run.nazoauth.source.revision)" != "$source_revision"; then
  "$container_runtime" build \
    --label "org.opencontainers.image.revision=$expected_revision" \
    --label "run.nazoauth.source.revision=$source_revision" \
    --file "$OIDF_SUITE_SOURCE_DIR/nginx/Dockerfile" \
    --tag "$nginx_image" \
    "$OIDF_SUITE_SOURCE_DIR/nginx"
else
  echo "Reusing exact OIDF Suite TLS ingress image $nginx_image"
fi
require_image_label "$nginx_image" org.opencontainers.image.revision "$expected_revision"
require_image_label "$nginx_image" run.nazoauth.source.revision "$source_revision"

if test "$(image_label "$pki_init_image" run.nazoauth.source.revision)" != "$source_revision"; then
  "$container_runtime" build \
    --target pki-init \
    --label "run.nazoauth.source.revision=$source_revision" \
    --file "$NAZOAUTH_SOURCE_DIR/deploy/oidf-proxy/Containerfile" \
    --tag "$pki_init_image" \
    "$NAZOAUTH_SOURCE_DIR"
else
  echo "Reusing exact OIDF proxy PKI initializer image $pki_init_image"
fi
require_image_label "$pki_init_image" run.nazoauth.source.revision "$source_revision"

if ! "$container_runtime" volume inspect nazoauth-oidf-proxy-pki >/dev/null 2>&1; then
  "$container_runtime" volume create nazoauth-oidf-proxy-pki >/dev/null
fi
"$container_runtime" run --rm \
  --env "OIDF_TARGET_HOSTNAME=$OIDF_TARGET_HOSTNAME" \
  --volume nazoauth-oidf-proxy-pki:/pki \
  "$pki_init_image"

token_parent=$(dirname -- "$OIDF_SUITE_TOKEN_FILE")
metadata_parent=$(dirname -- "$OIDF_SUITE_TOKEN_METADATA_FILE")
install -d -m 0700 "$token_parent"
test "$metadata_parent" = "$token_parent" || install -d -m 0700 "$metadata_parent"
compose() {
  "$container_runtime" compose -f "$script_dir/compose.yml" "$@"
}
bootstrap_container=nazoauth-oidf-suite-bootstrap

OIDF_SUITE_BASE_URL="$OIDF_SUITE_BASE_URL" \
OIDF_SUITE_TOKEN_FILE="$OIDF_SUITE_TOKEN_FILE" \
OIDF_SUITE_TOKEN_METADATA_FILE="$OIDF_SUITE_TOKEN_METADATA_FILE" \
  sh "$script_dir/revoke-api-token.sh"

# This is deliberately a one-shot container on the private suite network.  It
# can coexist with an already-running main suite and never binds the nginx
# port; each invocation therefore gets a newly issued non-permanent token.
cleanup_bootstrap() {
  "$container_runtime" rm -f "$bootstrap_container" >/dev/null 2>&1 || true
}
trap cleanup_bootstrap EXIT HUP INT TERM

compose up -d --no-build mongodb
cleanup_bootstrap
"$container_runtime" run -d \
  --name "$bootstrap_container" \
  --network nazoauth-oidf-suite-default \
  --publish 127.0.0.1:18443:8080 \
  --env "BASE_URL=$OIDF_SUITE_BASE_URL" \
  --env "BASE_MTLS_URL=$OIDF_SUITE_BASE_URL" \
  --env MONGODB_HOST=mongodb \
  --env OIDC_GOOGLE_CLIENTID=google-client \
  --env OIDC_GOOGLE_SECRET=google-secret \
  --env OIDC_GITLAB_CLIENTID=gitlab-client \
  --env OIDC_GITLAB_SECRET=gitlab-secret \
  --env "JAVA_EXTRA_ARGS=-Dfintechlabs.devmode=true -Dfintechlabs.makeDummyUserAdminInDevMode=false -Doidc.google.iss=$OIDF_OPERATOR_ISSUER -Doidc.gitlab.iss=$OIDF_OPERATOR_ISSUER -Doidc.admin.issuer=$OIDF_OPERATOR_ISSUER" \
  "$suite_image" >/dev/null

python3 - "$OIDF_SUITE_TOKEN_FILE" "$OIDF_SUITE_TOKEN_METADATA_FILE" <<'PY'
import json
import os
import pathlib
import stat
import sys
import time
import urllib.error
import urllib.request

endpoint = "http://127.0.0.1:18443/api/token"
request = urllib.request.Request(
    endpoint,
    data=b'{"permanent":false}',
    method="POST",
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Forwarded-Proto": "https",
    },
)
last_error = None
for _ in range(120):
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.load(response)
            if response.status != 201:
                raise RuntimeError(f"token endpoint returned HTTP {response.status}")
        break
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        last_error = error
        time.sleep(1)
else:
    raise SystemExit(f"OIDF bootstrap endpoint did not become ready: {last_error}")

token = payload.get("token") if isinstance(payload, dict) else None
token_id = payload.get("_id") if isinstance(payload, dict) else None
expires = payload.get("expires") if isinstance(payload, dict) else None
now_ms = int(time.time() * 1000)
if not isinstance(token, str) or not token or any(character.isspace() for character in token):
    raise SystemExit("OIDF token endpoint returned no valid token")
if not isinstance(token_id, str) or not token_id.isalnum() or len(token_id) > 128:
    raise SystemExit("OIDF token endpoint returned no valid token id")
if (
    isinstance(expires, bool)
    or not isinstance(expires, int)
    or expires <= now_ms
    or expires > now_ms + 24 * 60 * 60 * 1000 + 5 * 60 * 1000
):
    raise SystemExit("OIDF token endpoint returned no valid temporary expiry")


def write_protected(path: pathlib.Path, value: str, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise SystemExit(f"{label} cannot be created safely") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"{label} security properties are unsafe")


token_path = pathlib.Path(sys.argv[1])
metadata_path = pathlib.Path(sys.argv[2])
if os.path.abspath(token_path) == os.path.abspath(metadata_path):
    raise SystemExit("suite token and token metadata files must be different paths")
created: list[pathlib.Path] = []
try:
    write_protected(token_path, token, "suite token file")
    created.append(token_path)
    write_protected(
        metadata_path,
        json.dumps({"id": token_id, "expires": expires}, separators=(",", ":"), sort_keys=True),
        "suite token metadata file",
    )
    created.append(metadata_path)
except BaseException:
    for path in reversed(created):
        try:
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                path.unlink()
        except OSError:
            pass
    raise
PY

cleanup_bootstrap
trap - EXIT HUP INT TERM

compose up -d --no-build

python3 - "$OIDF_SUITE_BASE_URL" "$OIDF_SUITE_TOKEN_FILE" <<'PY'
import os
import pathlib
import stat
import sys
import time
import urllib.error
import urllib.request

base_url = sys.argv[1].rstrip("/")
token_path = pathlib.Path(sys.argv[2])
metadata = token_path.lstat()
if (
    stat.S_ISLNK(metadata.st_mode)
    or not stat.S_ISREG(metadata.st_mode)
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_nlink != 1
):
    raise SystemExit("suite token file is not a protected regular file")
flags = os.O_RDONLY
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
try:
    descriptor = os.open(token_path, flags)
except OSError as error:
    raise SystemExit("suite token file cannot be opened safely") from error
try:
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or stat.S_ISLNK(opened.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
    ):
        raise SystemExit("suite token file changed security properties while opening")
    token = os.read(descriptor, 64 * 1024 + 1).decode("utf-8").strip()
finally:
    os.close(descriptor)
if not token or any(character.isspace() for character in token):
    raise SystemExit("suite token file is empty or malformed")

def status(authenticated):
    headers = {"Accept": "application/json"}
    if authenticated:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{base_url}/api/server", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read(1024 * 1024 + 1)
            return response.status
    except urllib.error.HTTPError as error:
        with error:
            error.read(1024 * 1024 + 1)
            return error.code

last = None
for _ in range(120):
    try:
        last = (status(False), status(True))
        if last == (401, 200):
            print("OIDF suite API boundary verified: unauthenticated=401 authenticated=200")
            break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(1)
else:
    raise SystemExit(f"OIDF suite API boundary was not ready; last statuses={last}")
PY
