#!/bin/sh
set -eu

: "${NAZOAUTH_POSTGRES_PASSWORD:?NAZOAUTH_POSTGRES_PASSWORD is required}"

psql --set ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set runtime_password="$NAZOAUTH_POSTGRES_PASSWORD" <<'SQL'
CREATE ROLE nazoauth
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    PASSWORD :'runtime_password';
SQL
