#!/bin/sh
set -eu

: "${OIDF_SUITE_BASE_URL:?set OIDF_SUITE_BASE_URL}"
: "${OIDF_SUITE_TOKEN_FILE:?set OIDF_SUITE_TOKEN_FILE}"
: "${OIDF_SUITE_TOKEN_METADATA_FILE:=${OIDF_SUITE_TOKEN_ID_FILE:-${OIDF_SUITE_TOKEN_FILE}.metadata}}"
OIDF_SUITE_TOKEN_ID_FILE=$OIDF_SUITE_TOKEN_METADATA_FILE
export OIDF_SUITE_TOKEN_METADATA_FILE OIDF_SUITE_TOKEN_ID_FILE

# Keep token handling in one small, no-follow Python boundary.  The suite's
# DELETE endpoint is authenticated by the token itself and returns 200 when
# the id was removed or 404 when it was already absent.
python3 - "$OIDF_SUITE_BASE_URL" "$OIDF_SUITE_TOKEN_FILE" "$OIDF_SUITE_TOKEN_METADATA_FILE" <<'PY'
from __future__ import annotations

import os
import pathlib
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class TokenFileError(RuntimeError):
    pass


TOKEN_TTL_MS = 24 * 60 * 60 * 1000
CLOCK_SKEW_MS = 60 * 1000


def _owner_is_safe(metadata: os.stat_result) -> bool:
    if not hasattr(os, "getuid"):
        return True
    return metadata.st_uid in {0, os.getuid()}


def _open_regular_secret(path: pathlib.Path, label: str) -> tuple[int, os.stat_result]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        raise TokenFileError(f"{label} cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TokenFileError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise TokenFileError(f"{label} permissions must be exactly 0600")
    if metadata.st_nlink != 1 or not _owner_is_safe(metadata):
        raise TokenFileError(f"{label} has unsafe ownership or hard-link count")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TokenFileError(f"{label} cannot be opened safely") from error
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or stat.S_IMODE(opened.st_mode) != 0o600
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not _owner_is_safe(opened)
    ):
        os.close(descriptor)
        raise TokenFileError(f"{label} security properties changed while opening")
    return descriptor, opened


def _read_secret(path: pathlib.Path, label: str) -> str | None:
    try:
        descriptor, _ = _open_regular_secret(path, label)
    except FileNotFoundError:
        return None
    try:
        payload = os.read(descriptor, 64 * 1024 + 1)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > 64 * 1024:
        raise TokenFileError(f"{label} is empty or too large")
    try:
        value = payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise TokenFileError(f"{label} is not UTF-8") from error
    if not value or any(character.isspace() or character == "\x00" for character in value):
        raise TokenFileError(f"{label} must contain one non-empty line")
    return value


def _unlink_secret(path: pathlib.Path, label: str) -> None:
    try:
        _descriptor, _ = _open_regular_secret(path, label)
    except FileNotFoundError:
        return
    else:
        os.close(_descriptor)
    # unlink() removes the named leaf and never follows a symlink.  Repeating
    # the no-follow metadata check above makes a replacement race fail closed.
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TokenFileError(f"{label} changed to an unsafe file before deletion")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or not _owner_is_safe(metadata):
        raise TokenFileError(f"{label} changed security properties before deletion")
    try:
        path.unlink()
    except OSError as error:
        raise TokenFileError(f"{label} could not be deleted") from error


def _read_metadata(path: pathlib.Path) -> dict[str, int | str] | None:
    raw = _read_secret(path, "suite token metadata file")
    if raw is None:
        return None
    try:
        import json

        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise TokenFileError("suite token metadata file is not strict JSON") from error
    if not isinstance(value, dict) or set(value) != {"id", "expires"}:
        raise TokenFileError("suite token metadata must contain exactly id and expires")
    token_id = value.get("id")
    expires = value.get("expires")
    if (
        not isinstance(token_id, str)
        or not token_id
        or not token_id.isalnum()
        or len(token_id) > 128
        or isinstance(expires, bool)
        or not isinstance(expires, int)
        or expires <= 0
    ):
        raise TokenFileError("suite token metadata has invalid id or expiry")
    return {"id": token_id, "expires": expires}


def _is_expired(expires_ms: int) -> bool:
    return int(time.time() * 1000) >= expires_ms + CLOCK_SKEW_MS


def _legacy_token_is_expired(path: pathlib.Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TokenFileError("legacy suite token file cannot be inspected") from error
    return int(metadata.st_mtime * 1000) + TOKEN_TTL_MS + CLOCK_SKEW_MS <= int(time.time() * 1000)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, *_args, **_kwargs):
        raise urllib.error.HTTPError(
            request.full_url,
            310,
            "redirects are not permitted for token revocation",
            hdrs=None,
            fp=None,
        )


def _delete_token(base_url: str, token_id: str, token: str) -> int | None:
    # TokenApi IDs are generated as short alphanumeric values.  Restricting
    # the path component prevents an id file from changing the API target.
    if not token_id or not token_id.isalnum() or len(token_id) > 128:
        raise TokenFileError("suite token id has an invalid format")
    endpoint = base_url.rstrip("/") + "/api/token/" + urllib.parse.quote(token_id, safe="")
    request = urllib.request.Request(
        endpoint,
        method="DELETE",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Forwarded-Proto": "https",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=30) as response:
            response.read(1024 * 1024 + 1)
            return response.status
    except urllib.error.HTTPError as error:
        with error:
            error.read(1024 * 1024 + 1)
            return error.code
    except (OSError, urllib.error.URLError):
        return None


base_url, token_file_name, token_metadata_file_name = sys.argv[1:]
token_file = pathlib.Path(token_file_name)
token_metadata_file = pathlib.Path(token_metadata_file_name)
if os.path.abspath(token_file) == os.path.abspath(token_metadata_file):
    raise SystemExit("suite token and token metadata files must be different paths")

token = _read_secret(token_file, "suite token file")
metadata = _read_metadata(token_metadata_file)

if token is None and metadata is None:
    raise SystemExit(0)
if token is None or metadata is None:
    if token is not None and metadata is None:
        # Files created before token ids were persisted cannot be revoked by
        # id.  Once its mtime proves the upstream 24-hour TTL elapsed, remove
        # the local secret.  Before that, retain it and fail closed.
        if _legacy_token_is_expired(token_file):
            print(
                "legacy suite token file has naturally expired; removing local secret",
                file=sys.stderr,
            )
            _unlink_secret(token_file, "suite token file")
            raise SystemExit(0)
        raise SystemExit(
            "legacy suite token file has no metadata; it remains within the 24-hour TTL"
        )
    raise SystemExit("suite token metadata file exists without a token file")

token_id = metadata["id"]
expires = metadata["expires"]
assert isinstance(token_id, str)
assert isinstance(expires, int)

status = _delete_token(base_url, token_id, token)
if status not in {200, 404}:
    if not _is_expired(expires):
        reason = "request failed" if status is None else f"returned HTTP {status}"
        raise SystemExit(
            f"suite token revocation {reason}; retaining protected token files"
        )
    print(
        "suite API token reached its recorded expiry; removing local files",
        file=sys.stderr,
    )
else:
    print(
        f"suite API token {('revoked' if status == 200 else 'already absent')}; local files removed"
    )

_unlink_secret(token_file, "suite token file")
_unlink_secret(token_metadata_file, "suite token metadata file")
PY
