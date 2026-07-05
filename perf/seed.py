#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

import psycopg
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
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
MTLS_THUMBPRINT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
REDIRECT_URI = "https://client.example/callback"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
VECTOR_STRIDE_FLOOR = 100
VECTOR_OFFSET_MULTIPLIERS = {
    "par_signed_request_object": 0,
    "refresh_token_rotation": 1,
    "introspect_opaque_refresh_token": 2,
    "authorize_par_session": 3,
    "fapi2_par_jar_private_key_jwt_dpop": 4,
    "same_user_refresh_token_rotation": 5,
    "same_user_introspect_opaque_refresh_token": 6,
    "same_user_authorize_par_session": 7,
    "oidc_cold_login_refresh": 8,
    "oidc_logged_in_authorization_code": 9,
    "oidc_refresh_only": 10,
    "fapi2_full_security": 11,
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(size, "big"))


def json_b64(value: dict[str, Any]) -> str:
    return b64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def random_token(byte_count: int = 32) -> str:
    return b64url(secrets.token_bytes(byte_count))


def pkce_pair() -> tuple[str, str]:
    verifier = random_token()
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def rsa_public_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
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


def rsa_private_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    public = private_key.public_key().public_numbers()
    private = private_key.private_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
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


def sign_rs256(private_key: rsa.RSAPrivateKey, header: dict[str, Any], claims: dict[str, Any]) -> str:
    signing_input = f"{json_b64(header)}.{json_b64(claims)}"
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(signature)}"


def sign_es256(private_key: ec.EllipticCurvePrivateKey, header: dict[str, Any], claims: dict[str, Any]) -> str:
    signing_input = f"{json_b64(header)}.{json_b64(claims)}"
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{b64url(signature)}"


def scheduled_now(base_now: int, index: int, scenario: str, rate: int) -> int:
    if rate <= 0 or not scenario:
        return base_now
    vector_stride = max(int(os.environ.get("PERF_ITERATIONS", "50")), VECTOR_STRIDE_FLOOR)
    offset = VECTOR_OFFSET_MULTIPLIERS.get(scenario, 0) * vector_stride
    relative_iteration = max(0, index - offset)
    return base_now + relative_iteration // rate


def client_assertion(
    private_key: rsa.RSAPrivateKey,
    kid: str,
    client_id: str,
    issuer: str,
    jti_suffix: str,
    now: int,
) -> str:
    return sign_rs256(
        private_key,
        {"alg": "RS256", "kid": kid, "typ": "JWT"},
        {
            "iss": client_id,
            "sub": client_id,
            "aud": issuer,
            "iat": now,
            "exp": now + 240,
            "jti": f"{jti_suffix}-{uuid.uuid4()}",
        },
    )


def request_object(
    private_key: rsa.RSAPrivateKey,
    kid: str,
    client_id: str,
    issuer: str,
    *,
    state: str,
    nonce: str,
    code_challenge: str,
    dpop_jkt: str | None,
    now: int,
) -> str:
    claims: dict[str, Any] = {
        "client_id": client_id,
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "iat": now,
        "nbf": now - 5,
        "exp": now + 240,
        "jti": f"jar-{uuid.uuid4()}",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile offline_access",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if dpop_jkt:
        claims["dpop_jkt"] = dpop_jkt
    return sign_rs256(private_key, {"alg": "RS256", "kid": kid, "typ": "JWT"}, claims)


def dpop_proof(
    private_key: ec.EllipticCurvePrivateKey,
    public_jwk: dict[str, str],
    method: str,
    htu: str,
    jti_suffix: str,
    now: int,
) -> str:
    return sign_es256(
        private_key,
        {"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk},
        {
            "htm": method,
            "htu": htu,
            "iat": now,
            "jti": f"{jti_suffix}-{uuid.uuid4()}",
        },
    )


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
    oidc_client = "perf-oidc-client"
    fapi_client = "perf-fapi-private-jwt-dpop-client"
    base_now = int(time.time())
    for index in range(count):
        vector_now = scheduled_now(base_now, index, scenario, rate)
        verifier, challenge = pkce_pair()
        fapi_verifier, fapi_challenge = pkce_pair()
        state = f"perf-state-{index}-{uuid.uuid4()}"
        nonce = f"perf-nonce-{index}-{uuid.uuid4()}"
        fapi_state = f"perf-fapi-state-{index}-{uuid.uuid4()}"
        fapi_nonce = f"perf-fapi-nonce-{index}-{uuid.uuid4()}"
        vectors.append(
            {
                "pkce_verifier": verifier,
                "oidc_request": request_object(
                    rsa_key,
                    rsa_kid,
                    oidc_client,
                    issuer,
                    state=state,
                    nonce=nonce,
                    code_challenge=challenge,
                    dpop_jkt=None,
                    now=vector_now,
                ),
                "oidc_state": state,
                "fapi_pkce_verifier": fapi_verifier,
                "fapi_request": request_object(
                    rsa_key,
                    rsa_kid,
                    fapi_client,
                    issuer,
                    state=fapi_state,
                    nonce=fapi_nonce,
                    code_challenge=fapi_challenge,
                    dpop_jkt=dpop_jkt,
                    now=vector_now,
                ),
                "fapi_state": fapi_state,
                "fapi_par_assertion": client_assertion(
                    rsa_key, rsa_kid, fapi_client, issuer, "fapi-par", vector_now
                ),
                "fapi_token_assertion": client_assertion(
                    rsa_key, rsa_kid, fapi_client, issuer, "fapi-token", vector_now
                ),
                "fapi_refresh_assertion": client_assertion(
                    rsa_key, rsa_kid, fapi_client, issuer, "fapi-refresh", vector_now
                ),
                "fapi_client_credentials_assertion": client_assertion(
                    rsa_key, rsa_kid, fapi_client, issuer, "fapi-client-credentials", vector_now
                ),
                "fapi_introspection_assertion": client_assertion(
                    rsa_key, rsa_kid, fapi_client, issuer, "fapi-introspection", vector_now
                ),
                "dpop_par": dpop_proof(
                    dpop_key, dpop_jwk, "POST", f"{issuer}/par", "dpop-par", vector_now
                ),
                "dpop_token": dpop_proof(
                    dpop_key, dpop_jwk, "POST", f"{issuer}/token", "dpop-token", vector_now
                ),
                "dpop_refresh": dpop_proof(
                    dpop_key, dpop_jwk, "POST", f"{issuer}/token", "dpop-refresh", vector_now
                ),
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
    rsa_jwk = rsa_public_jwk(rsa_key, rsa_kid)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    dpop_jwk = ec_public_jwk(ec_key, "perf-dpop-es256")
    dpop_jkt = jwk_thumbprint(dpop_jwk)
    jwks = {"keys": [rsa_jwk]}
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
        conn.commit()

    secrets_doc = {
        "issuer": issuer,
        "redirect_uri": REDIRECT_URI,
        "user": users[0],
        "users": users,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_secret": CLIENT_SECRET,
        "mtls_thumbprint": MTLS_THUMBPRINT,
        "clients": {
            "client_credentials": "perf-client-credentials",
            "oidc": "perf-oidc-client",
            "fapi": "perf-fapi-private-jwt-dpop-client",
            "mtls": "perf-mtls-client",
        },
        "dpop_jkt": dpop_jkt,
        "private_jwk": rsa_private_jwk(rsa_key, rsa_kid),
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
    print(f"seeded {user_count} perf users, clients, and {vector_count} scheduled signed vectors")


if __name__ == "__main__":
    seed()
