#!/bin/sh
set -eu

umask 077
secret_dir=/run/nazoauth-secrets
mkdir -p "$secret_dir"
chmod 0700 "$secret_dir"

generate_hex_secret() {
    target=$1
    if [ -e "$target" ]; then
        test -s "$target" || {
            echo "refusing to replace empty persisted secret: $target" >&2
            exit 1
        }
        return
    fi
    temporary="${target}.tmp"
    test ! -e "$temporary" || {
        echo "stale secret temporary file requires operator review: $temporary" >&2
        exit 1
    }
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$temporary"
    test "$(wc -c <"$temporary" | tr -d ' ')" -eq 64
    mv "$temporary" "$target"
}

generate_hex_secret "$secret_dir/postgres-password"
generate_hex_secret "$secret_dir/valkey-password"
generate_hex_secret "$secret_dir/revision"

if [ "${NAZOAUTH_GENERATE_CONFORMANCE_SECRETS:-0}" = 1 ]; then
    generate_hex_secret "$secret_dir/dynamic-registration-token"
    generate_hex_secret "$secret_dir/ciba-decision-token"
    generate_hex_secret "$secret_dir/openid4vci-management-token"
    generate_hex_secret "$secret_dir/openid4vp-management-token"
    if [ ! -e "$secret_dir/openid4vc-data-encryption-key" ]; then
        temporary="$secret_dir/openid4vc-data-encryption-key.tmp"
        test ! -e "$temporary" || {
            echo "stale secret temporary file requires operator review: $temporary" >&2
            exit 1
        }
        od -An -N32 -tx1 /dev/urandom \
            | tr -d ' \n' \
            | xxd -r -p \
            | base64 \
            | tr '+/' '-_' \
            | tr -d '=\n' >"$temporary"
        test "$(wc -c <"$temporary" | tr -d ' ')" -eq 43
        mv "$temporary" "$secret_dir/openid4vc-data-encryption-key"
    fi
fi

postgres_password=$(cat "$secret_dir/postgres-password")
valkey_password=$(cat "$secret_dir/valkey-password")
expected_database_url="postgresql://nazoauth:${postgres_password}@postgres:5432/oauth"
expected_valkey_url="redis://default:${valkey_password}@valkey:6379/0"
expected_valkey_acl="user default on >${valkey_password} ~* &* +@all"

if [ ! -e "$secret_dir/database-url" ]; then
    printf '%s' "$expected_database_url" >"$secret_dir/database-url"
elif [ "$(cat "$secret_dir/database-url")" != "$expected_database_url" ]; then
    echo "persisted database URL does not match the persisted PostgreSQL password" >&2
    exit 1
fi
if [ ! -e "$secret_dir/valkey-url" ]; then
    printf '%s' "$expected_valkey_url" >"$secret_dir/valkey-url"
elif [ "$(cat "$secret_dir/valkey-url")" != "$expected_valkey_url" ]; then
    echo "persisted Valkey URL does not match the persisted Valkey password" >&2
    exit 1
fi
if [ ! -e "$secret_dir/valkey.acl" ]; then
    printf '%s\n' "$expected_valkey_acl" >"$secret_dir/valkey.acl"
elif [ "$(cat "$secret_dir/valkey.acl")" != "$expected_valkey_acl" ]; then
    echo "persisted Valkey ACL does not match the persisted Valkey password" >&2
    exit 1
fi

for required in database-url postgres-password revision valkey-url valkey-password valkey.acl; do
    test -s "$secret_dir/$required" || {
        echo "persisted secret is missing or empty: $secret_dir/$required" >&2
        exit 1
    }
done

if [ "${NAZOAUTH_GENERATE_CONFORMANCE_SECRETS:-0}" = 1 ]; then
    for required in dynamic-registration-token ciba-decision-token \
        openid4vci-management-token openid4vp-management-token \
        openid4vc-data-encryption-key; do
        test -s "$secret_dir/$required" || {
            echo "persisted conformance secret is missing or empty: $secret_dir/$required" >&2
            exit 1
        }
    done
fi

# The official images use different unprivileged runtime UIDs. The named
# volume is mounted only into the selected services and is not published to
# the host, so make its immutable outputs readable without depending on a
# shared numeric group.
chmod 0444 "$secret_dir"/database-url \
    "$secret_dir"/postgres-password \
    "$secret_dir"/revision \
    "$secret_dir"/valkey-url \
    "$secret_dir"/valkey-password \
    "$secret_dir"/valkey.acl
if [ "${NAZOAUTH_GENERATE_CONFORMANCE_SECRETS:-0}" = 1 ]; then
    chmod 0444 "$secret_dir"/dynamic-registration-token \
        "$secret_dir"/ciba-decision-token \
        "$secret_dir"/openid4vci-management-token \
        "$secret_dir"/openid4vp-management-token \
        "$secret_dir"/openid4vc-data-encryption-key
fi
chmod 0555 "$secret_dir"
