"""Bounded secret input helpers for OIDF operator tooling.

Secret values are accepted only from standard input, an inherited descriptor,
or a regular mode-0600 file.  Environment variables and command-line values
are deliberately not supported.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Collection


MAX_SECRET_DOCUMENT_BYTES = 64 * 1024
MAX_PRIVATE_CONFIG_BYTES = 8 * 1024 * 1024
INHERITED_CHILD_ENV_NAMES = frozenset(
    {
        "PATH",
        "LANG",
        "TZ",
        # Required for ordinary process creation and executable lookup on Windows.
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    }
)


class SecretInputError(RuntimeError):
    pass


def closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise SecretInputError("secret document contains a duplicate field")
        value[key] = child
    return value


def add_secret_source_arguments(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--secrets-stdin",
        action="store_true",
        help="read the strict secret JSON document from non-interactive stdin",
    )
    source.add_argument(
        "--secret-fd",
        type=int,
        help="read the strict secret JSON document from an already-open descriptor >= 3",
    )
    source.add_argument(
        "--secret-file",
        type=Path,
        help="read the strict secret JSON document from a POSIX non-symlink mode-0600 file",
    )


def _read_bounded_descriptor(descriptor: int) -> bytes:
    if descriptor < 0:
        raise SecretInputError("secret descriptor must be non-negative")
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_SECRET_DOCUMENT_BYTES:
        chunk = os.read(
            descriptor,
            min(4096, MAX_SECRET_DOCUMENT_BYTES + 1 - total),
        )
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    payload = b"".join(chunks)
    if not payload or len(payload) > MAX_SECRET_DOCUMENT_BYTES:
        raise SecretInputError(
            f"secret document must contain 1 through {MAX_SECRET_DOCUMENT_BYTES} bytes"
        )
    return payload


def _secure_file_descriptor(path: Path) -> int:
    if os.name == "nt":
        raise SecretInputError(
            "--secret-file requires POSIX ownership and mode enforcement; "
            "use standard input or an inherited descriptor on Windows"
        )
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SecretInputError("secret file is not readable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SecretInputError("secret file must be a regular non-symlink file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SecretInputError("secret file permissions must be exactly 0600")
    if metadata.st_nlink != 1:
        raise SecretInputError("secret file must have exactly one hard link")
    if hasattr(os, "getuid") and metadata.st_uid not in {0, os.getuid()}:
        raise SecretInputError("secret file must be owned by the current user or root")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SecretInputError("secret file is not readable") from error
    opened = os.fstat(descriptor)
    owner_valid = not hasattr(os, "getuid") or opened.st_uid in {0, os.getuid()}
    permissions_valid = os.name == "nt" or stat.S_IMODE(opened.st_mode) == 0o600
    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or not stat.S_ISREG(opened.st_mode)
        or not permissions_valid
        or opened.st_nlink != 1
        or not owner_valid
    ):
        os.close(descriptor)
        raise SecretInputError("secret file security properties changed while it was opened")
    return descriptor


def read_secret_document(
    args: argparse.Namespace,
    *,
    required_fields: Collection[str],
) -> dict[str, str]:
    if getattr(args, "secrets_stdin", False):
        if sys.stdin.isatty():
            raise SecretInputError("--secrets-stdin refuses an interactive terminal")
        payload = sys.stdin.buffer.read(MAX_SECRET_DOCUMENT_BYTES + 1)
        if not payload or len(payload) > MAX_SECRET_DOCUMENT_BYTES:
            raise SecretInputError(
                f"secret document must contain 1 through {MAX_SECRET_DOCUMENT_BYTES} bytes"
            )
    elif getattr(args, "secret_fd", None) is not None:
        descriptor = args.secret_fd
        if not isinstance(descriptor, int) or descriptor < 3:
            raise SecretInputError("--secret-fd must be an already-open descriptor >= 3")
        payload = _read_bounded_descriptor(descriptor)
    else:
        path = getattr(args, "secret_file", None)
        if not isinstance(path, Path):
            raise SecretInputError("one secret source is required")
        descriptor = _secure_file_descriptor(path)
        try:
            payload = _read_bounded_descriptor(descriptor)
        finally:
            os.close(descriptor)

    try:
        value = json.loads(payload, object_pairs_hook=closed_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SecretInputError("secret document must be strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SecretInputError("secret document must be a JSON object")
    required = set(required_fields)
    if set(value) != required:
        raise SecretInputError("secret document fields do not match the closed schema")
    if any(not isinstance(value[field], str) or not value[field] for field in required):
        raise SecretInputError("every secret document field must be a non-empty string")
    return {field: value[field] for field in required}


def read_secret_value(*, descriptor: int | None = None, path: Path | None = None) -> str:
    if (descriptor is None) == (path is None):
        raise SecretInputError("select exactly one secret value source")
    if descriptor is not None:
        if descriptor < 3:
            raise SecretInputError("secret descriptor must be an already-open descriptor >= 3")
        payload = _read_bounded_descriptor(descriptor)
    else:
        assert path is not None
        opened = _secure_file_descriptor(path)
        try:
            payload = _read_bounded_descriptor(opened)
        finally:
            os.close(opened)
    try:
        value = payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise SecretInputError("secret value must be UTF-8") from error
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise SecretInputError("secret value must be one non-empty line")
    return value


def read_private_text(
    path: Path,
    *,
    max_bytes: int = MAX_PRIVATE_CONFIG_BYTES,
) -> str:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    descriptor = _secure_file_descriptor(path)
    try:
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload or len(payload) > max_bytes:
        raise SecretInputError(
            f"private input must contain 1 through {max_bytes} bytes"
        )
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SecretInputError("private input must be UTF-8") from error


def sanitized_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a closed child environment, never a filtered parent copy.

    Only process-launch/locale settings cross the parent boundary implicitly.
    Callers must add each required, non-secret application setting explicitly.
    """

    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in INHERITED_CHILD_ENV_NAMES or name.upper().startswith("LC_")
    }
    if extra:
        environment.update(extra)
    return environment
