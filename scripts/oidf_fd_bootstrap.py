"""Launch the pristine OIDF runner with one non-exportable token lookup."""

from __future__ import annotations

import collections.abc
import os
import runpy
import sys
import sysconfig
from typing import Iterator


TOKEN_NAME = "CONFORMANCE_TOKEN"
MAX_TOKEN_BYTES = 64 * 1024


class OneShotSecretEnvironment(collections.abc.MutableMapping[str, str]):
    """Delegate the real process environment without exporting the token.

    The token is absent from iteration, copy, the C process environment, and
    descendant processes.  The one official-suite lookup consumes and clears
    it immediately.
    """

    def __init__(self, delegate: collections.abc.MutableMapping[str, str], token: bytearray):
        self._delegate = delegate
        self._token: bytearray | None = token

    def __getitem__(self, key: str) -> str:
        if key != TOKEN_NAME:
            return self._delegate[key]
        token = self._token
        if token is None:
            raise KeyError(key)
        try:
            return token.decode("utf-8")
        finally:
            token[:] = b"\x00" * len(token)
            self._token = None

    def __setitem__(self, key: str, value: str) -> None:
        if key == TOKEN_NAME:
            raise RuntimeError("OIDF token environment mutation is forbidden")
        self._delegate[key] = value

    def __delitem__(self, key: str) -> None:
        if key == TOKEN_NAME:
            token = self._token
            if token is None:
                raise KeyError(key)
            token[:] = b"\x00" * len(token)
            self._token = None
            return
        del self._delegate[key]

    def __iter__(self) -> Iterator[str]:
        return (key for key in self._delegate if key != TOKEN_NAME)

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key: object) -> bool:
        if key == TOKEN_NAME:
            return False
        return key in self._delegate

    def copy(self) -> dict[str, str]:
        return {key: self._delegate[key] for key in self}


def read_token(descriptor: int) -> bytearray:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_TOKEN_BYTES:
        chunk = os.read(descriptor, min(4096, MAX_TOKEN_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    os.close(descriptor)
    token = bytearray(b"".join(chunks))
    if not token or len(token) > MAX_TOKEN_BYTES or b"\x00" in token:
        token[:] = b"\x00" * len(token)
        raise RuntimeError("OIDF token descriptor contains an invalid value")
    return token


def main() -> None:
    if len(sys.argv) < 4:
        raise RuntimeError("OIDF FD bootstrap requires suite path, runner path, and token FD")
    suite_scripts = sys.argv.pop(1)
    runner = sys.argv.pop(1)
    token_fd = sys.argv.pop(1)
    paths = sysconfig.get_paths()
    sys.path.extend(dict.fromkeys([paths["purelib"], paths["platlib"]]))
    sys.path.insert(0, suite_scripts)
    sys.argv[0] = runner
    if token_fd == "-":
        runpy.run_path(runner, run_name="__main__")
        return
    original_environment = os.environ
    os.environ = OneShotSecretEnvironment(original_environment, read_token(int(token_fd)))
    try:
        runpy.run_path(runner, run_name="__main__")
    finally:
        os.environ = original_environment


if __name__ == "__main__":
    main()
