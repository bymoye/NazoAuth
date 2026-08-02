#!/bin/sh
set -eu

expected_revision=946451d1ce29965c9ab7aee05f5003552233160e
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NAZOAUTH_SOURCE_DIR=$(CDPATH= cd -- "$script_dir/../.." && pwd)
export NAZOAUTH_SOURCE_DIR
: "${OIDF_SUITE_SOURCE_DIR:?set OIDF_SUITE_SOURCE_DIR}"
: "${OIDF_SUITE_BASE_URL:?set OIDF_SUITE_BASE_URL}"
: "${OIDF_SUITE_TOKEN_FILE:?set OIDF_SUITE_TOKEN_FILE}"

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
test ! -e "$OIDF_SUITE_TOKEN_FILE" || {
  echo "suite token file already exists; refusing to overwrite it" >&2
  exit 1
}

token_parent=$(dirname -- "$OIDF_SUITE_TOKEN_FILE")
install -d -m 0700 "$token_parent"
compose="docker compose --project-directory $script_dir -f $script_dir/compose.yml"

cleanup_bootstrap() {
  $compose --profile bootstrap stop server-bootstrap >/dev/null 2>&1 || true
  $compose --profile bootstrap rm -f server-bootstrap >/dev/null 2>&1 || true
}
trap cleanup_bootstrap EXIT HUP INT TERM

$compose --profile bootstrap up -d --build mongodb server-bootstrap

python3 - "$OIDF_SUITE_TOKEN_FILE" <<'PY'
import json
import os
import pathlib
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
if not isinstance(token, str) or not token:
    raise SystemExit("OIDF token endpoint returned no token")
path = pathlib.Path(sys.argv[1])
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    stream.write(token)
    stream.write("\n")
PY

cleanup_bootstrap
trap - EXIT HUP INT TERM
$compose up -d server

python3 - "$OIDF_SUITE_BASE_URL" "$OIDF_SUITE_TOKEN_FILE" <<'PY'
import pathlib
import sys
import time
import urllib.error
import urllib.request

base_url = sys.argv[1].rstrip("/")
token = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()

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
