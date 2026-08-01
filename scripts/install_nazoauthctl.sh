#!/bin/sh
set -eu

repository="nazozero/NazoAuth"
version=""
install_path="/usr/local/sbin/nazoauthctl"
engine=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository) repository="${2:?--repository requires OWNER/NAME}"; shift 2 ;;
    --version) version="${2:?--version requires vMAJOR.MINOR.PATCH}"; shift 2 ;;
    --install-path) install_path="${2:?--install-path requires an absolute path}"; shift 2 ;;
    --engine) engine="${2:?--engine requires podman or docker}"; shift 2 ;;
    *) printf '%s\n' "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$repository" in
  *[!A-Za-z0-9._/-]*|*/*/*|/*|*/|'')
    printf '%s\n' 'repository must be one safe OWNER/NAME pair' >&2
    exit 2
    ;;
esac
case "$install_path" in
  /|*/|*//*|*/./*|*/../*|*[!A-Za-z0-9._/-]*)
    printf '%s\n' 'unsafe install path' >&2
    exit 2
    ;;
  /*) ;;
  *) printf '%s\n' 'install path must be absolute' >&2; exit 2 ;;
esac
case "$engine" in
  ''|podman|docker) ;;
  *) printf '%s\n' 'engine must be podman or docker' >&2; exit 2 ;;
esac

if [ -z "$version" ]; then
  version="$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$repository/releases/latest" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
fi
semantic=${version#v}
major=${semantic%%.*}
remainder=${semantic#*.}
minor=${remainder%%.*}
patch=${remainder#*.}
if [ "$semantic" = "$version" ] || [ "$remainder" = "$semantic" ] || [ "$patch" = "$remainder" ]; then
  printf '%s\n' 'version must be an immutable vMAJOR.MINOR.PATCH tag' >&2
  exit 2
fi
for component in "$major" "$minor" "$patch"; do
  case "$component" in
    ''|*[!0-9]*|0[0-9]*)
      printf '%s\n' 'version must be an immutable vMAJOR.MINOR.PATCH tag' >&2
      exit 2
      ;;
  esac
done

temporary="$(mktemp -d "${TMPDIR:-/tmp}/nazoauthctl-bootstrap.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
base="https://github.com/$repository/releases/download/$version"
for name in nazoauthctl nazoauthctl.bundle; do
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$temporary/$name" "$base/$name"
done

identity="https://github.com/$repository/.github/workflows/release-security.yml@refs/tags/$version"
if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob --bundle "$temporary/nazoauthctl.bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$temporary/nazoauthctl"
else
  if [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then engine=podman
    elif command -v docker >/dev/null 2>&1; then engine=docker
    else printf '%s\n' 'cosign, Podman, or Docker is required' >&2; exit 1
    fi
  fi
  "$engine" run --rm -v "$temporary:/work:ro" \
    ghcr.io/sigstore/cosign/cosign@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00 \
    verify-blob --bundle /work/nazoauthctl.bundle \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    /work/nazoauthctl
fi

install -o root -g root -m 0755 "$temporary/nazoauthctl" "$install_path"
"$install_path" --help >/dev/null
printf 'installed verified nazoauthctl %s at %s\n' "$version" "$install_path"
