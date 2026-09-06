#!/usr/bin/env sh

install_capacity_dependencies() {
  missing=""
  for command_name in git jq python3; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      missing="${missing} ${command_name}"
    fi
  done

  if [ -z "${missing}" ]; then
    return 0
  fi

  echo "installing missing capacity dependencies:${missing}"
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache coreutils git jq python3 >/dev/null
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends coreutils git jq python3 >/dev/null
    return 0
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y coreutils git jq python3 >/dev/null
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y coreutils git jq python3 >/dev/null
    return 0
  fi

  echo "missing required commands and no supported package manager was found:${missing}" >&2
  return 1
}
