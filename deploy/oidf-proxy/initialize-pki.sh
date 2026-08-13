#!/bin/sh
set -eu

: "${OIDF_TARGET_HOSTNAME:?set OIDF_TARGET_HOSTNAME}"
pki_dir=/pki
umask 077
mkdir -p "$pki_dir"

required="server-ca.crt server.crt server.key client-ca.pem"
existing=0
for name in $required; do
    if [ -e "$pki_dir/$name" ]; then
        existing=$((existing + 1))
    fi
done
if [ "$existing" -ne 0 ]; then
    test "$existing" -eq 4 || {
        echo "incomplete persisted OIDF proxy PKI requires operator review" >&2
        exit 1
    }
    for name in $required; do
        test -s "$pki_dir/$name"
    done
    exit 0
fi

work=$(mktemp -d "$pki_dir/.initialize.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -subj "/CN=NazoAuth host-local OIDF proxy CA" \
    -keyout "$work/server-ca.key" -out "$work/server-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=$OIDF_TARGET_HOSTNAME" \
    -addext "subjectAltName=DNS:$OIDF_TARGET_HOSTNAME" \
    -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$OIDF_TARGET_HOSTNAME" \
    >"$work/server.ext"
openssl x509 -req -sha256 -days 30 -in "$work/server.csr" \
    -CA "$work/server-ca.crt" -CAkey "$work/server-ca.key" -CAcreateserial \
    -extfile "$work/server.ext" -out "$work/server.crt" >/dev/null 2>&1
cp "$work/server-ca.crt" "$work/client-ca.pem"
chmod 0400 "$work/server.key"
chmod 0444 "$work/server-ca.crt" "$work/server.crt" "$work/client-ca.pem"
for name in $required; do
    mv "$work/$name" "$pki_dir/$name"
done
trap - EXIT HUP INT TERM
rm -rf "$work"
