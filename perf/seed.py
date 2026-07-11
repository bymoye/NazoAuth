#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import redis
from blake3 import blake3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from psycopg.types.json import Jsonb


TENANT_ID = "00000000-0000-0000-0000-000000000001"
REALM_ID = "00000000-0000-0000-0000-000000000002"
ORGANIZATION_ID = "00000000-0000-0000-0000-000000000003"
USER_EMAIL = "perf-user@example.test"
USER_PASSWORD = "PerfUserPassword-2026!"
CLIENT_SECRET = "PerfClientSecret-2026!"
CLIENT_SECRET_PEPPER = os.environ.get(
    "CLIENT_SECRET_PEPPER", "perf-client-secret-pepper-000000000000000001"
)
REFRESH_TOKEN_TTL_SECONDS = int(os.environ.get("REFRESH_TOKEN_TTL_SECONDS", "2592000"))
MTLS_THUMBPRINT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
REDIRECT_URI = "https://client.example/callback"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba"
CIBA_AUTOMATED_DECISION_TOKEN = "perf-ciba-automated-decision-token-2026"
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(size, "big"))


def random_token(byte_count: int = 32) -> str:
    return b64url(secrets.token_bytes(byte_count))


def pkce_pair() -> tuple[str, str]:
    verifier = random_token()
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def rsa_public_jwk(private_key: rsa.RSAPrivateKey, kid: str, alg: str = "RS256") -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }


def ec_public_jwk(private_key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": b64url_uint(numbers.x),
        "y": b64url_uint(numbers.y),
    }


def rsa_private_jwk(private_key: rsa.RSAPrivateKey, kid: str, alg: str = "RS256") -> dict[str, str]:
    public = private_key.public_key().public_numbers()
    private = private_key.private_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": b64url_uint(public.n),
        "e": b64url_uint(public.e),
        "d": b64url_uint(private.d),
        "p": b64url_uint(private.p),
        "q": b64url_uint(private.q),
        "dp": b64url_uint(private.dmp1),
        "dq": b64url_uint(private.dmq1),
        "qi": b64url_uint(private.iqmp),
    }


def ec_private_jwk(private_key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, str]:
    public = private_key.public_key().public_numbers()
    private = private_key.private_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": b64url_uint(public.x),
        "y": b64url_uint(public.y),
        "d": b64url_uint(private.private_value),
    }


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def hash_secret(value: str) -> str:
    return PasswordHasher().hash(value)


def hash_client_secret(value: str) -> str:
    salt = random_token()
    digest = hmac.new(
        CLIENT_SECRET_PEPPER.encode("utf-8"),
        f"{salt}:{value}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"client-secret-v1:{salt}:{b64url(digest)}"


def blake3_hex(value: str) -> str:
    return blake3(value.encode("utf-8")).hexdigest()


def user_credentials(count: int) -> list[dict[str, str]]:
    return [
        {
            "email": USER_EMAIL if index == 0 else f"perf-user-{index + 1}@example.test",
            "password": USER_PASSWORD,
            "username": "perf_user" if index == 0 else f"perf_user_{index + 1}",
            "display_name": "Perf User" if index == 0 else f"Perf User {index + 1}",
        }
        for index in range(count)
    ]


def upsert_users(conn: psycopg.Connection[Any], users: list[dict[str, str]]) -> None:
    password_hash = hash_secret(USER_PASSWORD)
    for user in users:
        email = user["email"]
        username = user["username"]
        display_name = user["display_name"]
        normalized_email = email.lower()
        conn.execute(
            """
            DELETE FROM users
            WHERE tenant_id = %s::uuid
              AND (email = %s OR lower(email) = %s OR username = %s)
            """,
            (TENANT_ID, email, normalized_email, username),
        )
        conn.execute(
            """
            DELETE FROM users
            WHERE tenant_id <> %s::uuid
              AND lower(email) = %s
            """,
            (TENANT_ID, normalized_email),
        )
        conn.execute(
            """
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email, password_hash,
                is_active, email_verified, display_name, role, admin_level
            )
            VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE, %s, 'user', 0)
            """,
            (
                TENANT_ID,
                REALM_ID,
                ORGANIZATION_ID,
                username,
                email,
                password_hash,
                display_name,
            ),
        )


def upsert_client(
    conn: psycopg.Connection[Any],
    *,
    client_id: str,
    name: str,
    auth_method: str,
    grants: list[str],
    scopes: list[str],
    secret_hash: str | None,
    jwks: dict[str, Any] | None,
    require_dpop: bool = False,
    require_mtls: bool = False,
    require_par_request_object: bool = False,
    tls_thumbprint: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, post_logout_redirect_uris,
            scopes, allowed_audiences, grant_types, token_endpoint_auth_method,
            require_dpop_bound_tokens, require_mtls_bound_tokens,
            tls_client_auth_cert_sha256, allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, jwks, is_active
        )
        VALUES (
            %s::uuid, %s::uuid, %s::uuid, %s, %s, 'confidential',
            %s, %s, '[]'::jsonb, %s, %s, %s, %s,
            %s, %s, %s, FALSE, FALSE, %s, FALSE, %s, TRUE
        )
        ON CONFLICT (tenant_id, client_id) DO UPDATE SET
            client_name = EXCLUDED.client_name,
            client_type = EXCLUDED.client_type,
            client_secret_hash = EXCLUDED.client_secret_hash,
            redirect_uris = EXCLUDED.redirect_uris,
            scopes = EXCLUDED.scopes,
            allowed_audiences = EXCLUDED.allowed_audiences,
            grant_types = EXCLUDED.grant_types,
            token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
            require_dpop_bound_tokens = EXCLUDED.require_dpop_bound_tokens,
            require_mtls_bound_tokens = EXCLUDED.require_mtls_bound_tokens,
            tls_client_auth_cert_sha256 = EXCLUDED.tls_client_auth_cert_sha256,
            require_par_request_object = EXCLUDED.require_par_request_object,
            jwks = EXCLUDED.jwks,
            is_active = TRUE,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            TENANT_ID,
            REALM_ID,
            ORGANIZATION_ID,
            client_id,
            name,
            secret_hash,
            Jsonb([REDIRECT_URI]),
            Jsonb(scopes),
            Jsonb(["resource://default"]),
            Jsonb(grants),
            auth_method,
            require_dpop,
            require_mtls,
            tls_thumbprint,
            require_par_request_object,
            Jsonb(jwks) if jwks else None,
        ),
    )


def seed_oidc_refresh_tokens(
    conn: psycopg.Connection[Any],
    users: list[dict[str, str]],
) -> list[str]:
    client_row = conn.execute(
        """
        SELECT id
        FROM oauth_clients
        WHERE tenant_id = %s::uuid
          AND client_id = 'perf-oidc-client'
        """,
        (TENANT_ID,),
    ).fetchone()
    if client_row is None:
        raise RuntimeError("perf OIDC client was not seeded")
    client_db_id = client_row[0]
    conn.execute(
        """
        DELETE FROM oauth_tokens
        WHERE tenant_id = %s::uuid
          AND client_id = %s
        """,
        (TENANT_ID, client_db_id),
    )
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS)
    refresh_tokens: list[str] = []
    for user in users:
        user_row = conn.execute(
            """
            SELECT id
            FROM users
            WHERE tenant_id = %s::uuid
              AND lower(email) = %s
            """,
            (TENANT_ID, user["email"].lower()),
        ).fetchone()
        if user_row is None:
            raise RuntimeError(f"perf user was not seeded: {user['email']}")
        user_db_id = user_row[0]
        raw_refresh_token = random_token(48)
        conn.execute(
            """
            INSERT INTO oauth_tokens (
                tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
                client_id, user_id, scopes, audience, authorization_details,
                issued_at, expires_at, subject, dpop_jkt, mtls_x5t_s256
            )
            VALUES (
                %s::uuid, %s, %s, NULL,
                %s, %s, %s, %s, %s,
                %s, %s, %s, NULL, NULL
            )
            """,
            (
                TENANT_ID,
                blake3_hex(raw_refresh_token),
                uuid.uuid4(),
                client_db_id,
                user_db_id,
                Jsonb(["openid", "profile", "offline_access"]),
                Jsonb(["resource://default"]),
                Jsonb([]),
                now,
                expires_at,
                str(user_db_id),
            ),
        )
        refresh_tokens.append(raw_refresh_token)
    return refresh_tokens


def seed_logged_in_sessions(
    conn: psycopg.Connection[Any],
    users: list[dict[str, str]],
) -> list[dict[str, str]]:
    valkey_url = os.environ["VALKEY_URL"]
    client = redis.Redis.from_url(valkey_url, decode_responses=True)
    now = int(datetime.now(UTC).timestamp())
    sessions: list[dict[str, str]] = []
    for user in users:
        user_row = conn.execute(
            """
            SELECT id
            FROM users
            WHERE tenant_id = %s::uuid
              AND lower(email) = %s
            """,
            (TENANT_ID, user["email"].lower()),
        ).fetchone()
        if user_row is None:
            raise RuntimeError(f"perf user was not seeded: {user['email']}")
        session_id = random_token()
        csrf_token = random_token()
        payload = {
            "user_id": str(user_row[0]),
            "auth_time": now,
            "amr": ["password"],
            "pending_mfa": False,
            "oidc_sid": random_token(),
        }
        client.setex(
            f"oauth:session:{session_id}",
            SESSION_TTL_SECONDS,
            json.dumps(payload, separators=(",", ":")),
        )
        sessions.append(
            {
                "email": user["email"],
                "session_id": session_id,
                "csrf_token": csrf_token,
                "cookie_header": f"nazo_oauth_session={session_id}; nazo_oauth_csrf={csrf_token}",
            }
        )
    return sessions


def prepare_vectors(
    *,
    count: int,
    issuer: str,
    rsa_key: rsa.RSAPrivateKey,
    rsa_kid: str,
    dpop_key: ec.EllipticCurvePrivateKey,
    dpop_jwk: dict[str, str],
    dpop_jkt: str,
    scenario: str,
    rate: int,
) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for index in range(count):
        verifier, challenge = pkce_pair()
        fapi_verifier, fapi_challenge = pkce_pair()
        state = f"perf-state-{index}-{uuid.uuid4()}"
        nonce = f"perf-nonce-{index}-{uuid.uuid4()}"
        fapi_state = f"perf-fapi-state-{index}-{uuid.uuid4()}"
        fapi_nonce = f"perf-fapi-nonce-{index}-{uuid.uuid4()}"
        vectors.append(
            {
                "pkce_verifier": verifier,
                "oidc_code_challenge": challenge,
                "oidc_state": state,
                "oidc_nonce": nonce,
                "fapi_pkce_verifier": fapi_verifier,
                "fapi_code_challenge": fapi_challenge,
                "fapi_state": fapi_state,
                "fapi_nonce": fapi_nonce,
            }
        )
    return vectors


def seed() -> None:
    database_url = os.environ["DATABASE_URL"]
    issuer = os.environ.get("ISSUER_URL", "http://127.0.0.1:8000").rstrip("/")
    vector_count = int(os.environ.get("PERF_VECTOR_COUNT", "1000"))
    user_count = max(1, int(os.environ.get("PERF_USER_COUNT", "64")))
    users = user_credentials(user_count)
    state_dir = Path(os.environ.get("PERF_STATE_DIR", "/perf-state"))
    state_dir.mkdir(parents=True, exist_ok=True)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_kid = "perf-rs256"
    ps256_kid = "perf-ps256"
    rsa_jwk = rsa_public_jwk(rsa_key, rsa_kid)
    ps256_jwk = rsa_public_jwk(rsa_key, ps256_kid, "PS256")
    ec_key = ec.generate_private_key(ec.SECP256R1())
    dpop_jwk = ec_public_jwk(ec_key, "perf-dpop-es256")
    dpop_jkt = jwk_thumbprint(dpop_jwk)
    jwks = {"keys": [rsa_jwk, ps256_jwk]}
    secret_hash = hash_client_secret(CLIENT_SECRET)

    with psycopg.connect(database_url) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        upsert_users(conn, users)
        upsert_client(
            conn,
            client_id="perf-client-credentials",
            name="Perf Client Credentials",
            auth_method="client_secret_post",
            grants=["client_credentials"],
            scopes=["profile"],
            secret_hash=secret_hash,
            jwks=None,
        )
        upsert_client(
            conn,
            client_id="perf-oidc-client",
            name="Perf OIDC Client",
            auth_method="client_secret_post",
            grants=["authorization_code", "refresh_token"],
            scopes=["openid", "profile", "offline_access"],
            secret_hash=secret_hash,
            jwks=jwks,
        )
        upsert_client(
            conn,
            client_id="perf-fapi-private-jwt-dpop-client",
            name="Perf FAPI Private JWT DPoP Client",
            auth_method="private_key_jwt",
            grants=["authorization_code", "refresh_token", "client_credentials"],
            scopes=["openid", "profile", "offline_access"],
            secret_hash=None,
            jwks=jwks,
            require_dpop=True,
            require_par_request_object=True,
        )
        upsert_client(
            conn,
            client_id="perf-mtls-client",
            name="Perf mTLS Client",
            auth_method="tls_client_auth",
            grants=["client_credentials"],
            scopes=["profile"],
            secret_hash=None,
            jwks=None,
            require_mtls=True,
            tls_thumbprint=MTLS_THUMBPRINT,
        )
        upsert_client(
            conn,
            client_id="perf-ciba-private-jwt-dpop-client",
            name="Perf CIBA Private JWT DPoP Client",
            auth_method="private_key_jwt",
            grants=[CIBA_GRANT_TYPE],
            scopes=["openid", "profile"],
            secret_hash=None,
            jwks=jwks,
            require_dpop=True,
            require_par_request_object=True,
        )
        oidc_refresh_tokens = seed_oidc_refresh_tokens(conn, users)
        logged_in_sessions = seed_logged_in_sessions(conn, users)
        conn.commit()

    secrets_doc = {
        "issuer": issuer,
        "redirect_uri": REDIRECT_URI,
        "user": users[0],
        "users": users,
        "logged_in_sessions": logged_in_sessions,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_secret": CLIENT_SECRET,
        "oidc_refresh_tokens": oidc_refresh_tokens,
        "mtls_thumbprint": MTLS_THUMBPRINT,
        "clients": {
            "client_credentials": "perf-client-credentials",
            "oidc": "perf-oidc-client",
            "fapi": "perf-fapi-private-jwt-dpop-client",
            "mtls": "perf-mtls-client",
            "ciba": "perf-ciba-private-jwt-dpop-client",
        },
        "ciba_automated_decision_token": CIBA_AUTOMATED_DECISION_TOKEN,
        "dpop_jkt": dpop_jkt,
        "private_jwk": rsa_private_jwk(rsa_key, rsa_kid),
        "ps256_private_jwk": rsa_private_jwk(rsa_key, ps256_kid, "PS256"),
        "dpop_private_jwk": ec_private_jwk(ec_key, "perf-dpop-es256"),
        "dpop_public_jwk": dpop_jwk,
    }
    (state_dir / "secrets.json").write_text(json.dumps(secrets_doc, indent=2), encoding="utf-8")
    vectors = prepare_vectors(
        count=vector_count,
        issuer=issuer,
        rsa_key=rsa_key,
        rsa_kid=rsa_kid,
        dpop_key=ec_key,
        dpop_jwk=dpop_jwk,
        dpop_jkt=dpop_jkt,
        scenario=os.environ.get("PERF_SCENARIO", "").strip(),
        rate=int(os.environ.get("PERF_RATE", "0") or "0"),
    )
    (state_dir / "vectors.json").write_text(json.dumps(vectors), encoding="utf-8")
    print(
        f"seeded {user_count} perf users, clients, and {vector_count} flow vectors "
        f"(scenario={os.environ.get('PERF_SCENARIO', '').strip() or 'all'}, "
        f"rate={os.environ.get('PERF_RATE', '0') or '0'}/s)"
    )


if __name__ == "__main__":
    seed()
