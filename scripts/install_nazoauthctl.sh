#!/bin/sh
set -eu

repository="nazozero/NazoAuth"
version=""
install_path="/usr/local/sbin/nazoauthctl"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository) repository="${2:?--repository requires OWNER/NAME}"; shift 2 ;;
    --version) version="${2:?--version requires vMAJOR.MINOR.PATCH}"; shift 2 ;;
    --install-path) install_path="${2:?--install-path requires an absolute path}"; shift 2 ;;
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
if ! command -v gh >/dev/null 2>&1; then
  printf '%s\n' 'GitHub CLI (gh) is required for attested bootstrap' >&2
  exit 1
fi

if [ -z "$version" ]; then
  version="$(gh release view --repo "$repository" --json tagName --jq .tagName)"
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
case "$(uname -s)" in
  Linux) ;;
  *) printf '%s\n' 'managed bootstrap currently requires Linux' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) architecture=x86_64 ;;
  aarch64|arm64) architecture=aarch64 ;;
  *) printf '%s\n' 'unsupported Linux architecture' >&2; exit 1 ;;
esac
if command -v getconf >/dev/null 2>&1 && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
  libc=gnu
else
  libc=musl
fi
target="$architecture-unknown-linux-$libc"
artifact="nazoauthctl-$target"
gh release download "$version" --repo "$repository" --pattern "$artifact" --dir "$temporary"
gh attestation verify "$temporary/$artifact" \
  --repo "$repository" \
  --predicate-type 'https://nazo.run/attestations/release-manifest/v1' \
  --signer-workflow "$repository/.github/workflows/release-security.yml" \
  --source-ref "refs/tags/$version" \
  --deny-self-hosted-runners

install -o root -g root -m 0755 "$temporary/$artifact" "$install_path"
"$install_path" --help >/dev/null
printf 'installed verified nazoauthctl %s at %s\n' "$version" "$install_path"
