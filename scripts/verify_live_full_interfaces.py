#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
import time
import urllib.parse
import uuid
from pathlib import Path


BASE_URL = "https://auth.nazo.run"
REMOTE_BASE = Path("/opt/nazo-oauth")
SECRETS_PATH = REMOTE_BASE / "secrets.json"
EXPECTED_BACKEND_SHA = ""
DEPLOYMENT_RECORD = REMOTE_BASE / "deployments" / "current.json"
RUN_ID = f"live-full-{int(time.time())}-{secrets.token_hex(3)}"
PASSWORD = f"{RUN_ID}-Passw0rd!"
CSRF_COOKIE = "nazo_oauth_csrf"
DEFAULT_AUDIENCE = "resource://default"
OPENID_SCOPES = "openid profile email address phone offline_access"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exercise the complete deployed NazoAuth HTTPS interface set."
    )
    parser.add_argument("--base-url", default="https://auth.nazo.run")
    parser.add_argument("--secrets-path", default="/opt/nazo-oauth/secrets.json")
    parser.add_argument("--expected-backend-sha", required=True)
    return parser.parse_args(argv)


def load_runtime_dependencies() -> None:
    global Jsonb, MultipartEncoder, PasswordHasher
    global ec, ed25519, jwt, psycopg, redis, requests, rsa

    import jwt as jwt_module
    import psycopg as psycopg_module
    import redis as redis_module
    import requests as requests_module
    from argon2 import PasswordHasher as password_hasher
    from cryptography.hazmat.primitives.asymmetric import ec as ec_module
    from cryptography.hazmat.primitives.asymmetric import ed25519 as ed25519_module
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
    from psycopg.types.json import Jsonb as jsonb
    from requests_toolbelt import MultipartEncoder as multipart_encoder

    jwt = jwt_module
    psycopg = psycopg_module
    redis = redis_module
    requests = requests_module
    PasswordHasher = password_hasher
    ec = ec_module
    ed25519 = ed25519_module
    rsa = rsa_module
    Jsonb = jsonb
    MultipartEncoder = multipart_encoder


def main(argv: list[str] | None = None) -> None:
    global BASE_URL, EXPECTED_BACKEND_SHA, SECRETS_PATH

    args = parse_args(argv)
    BASE_URL = args.base_url.rstrip("/")
    SECRETS_PATH = Path(args.secrets_path)
    EXPECTED_BACKEND_SHA = args.expected_backend_sha
    load_runtime_dependencies()
    run()


def verify_deployed_backend(
    expected_sha: str,
    deployment_record: Path = DEPLOYMENT_RECORD,
    command_runner=subprocess.run,
) -> None:
    if len(expected_sha) != 40 or any(character not in "0123456789abcdef" for character in expected_sha):
        raise AssertionError("expected backend SHA must be a full lowercase Git SHA")
    record = json.loads(deployment_record.read_text(encoding="utf-8"))
    if record.get("status") != "deployment-success":
        raise AssertionError(f"deployment record is not successful: {record.get('status')!r}")
    if record.get("backend_commit") != expected_sha:
        raise AssertionError("deployment record backend SHA does not match the expected candidate")

    inspected = command_runner(
        [
            "podman",
            "inspect",
            "nazo-oauth-server",
            "--format",
            '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if inspected.returncode != 0:
        raise AssertionError(f"cannot inspect deployed server revision: {inspected.stderr.strip()}")
    if inspected.stdout.strip() != expected_sha:
        raise AssertionError("running container revision does not match the expected candidate")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_jwt_unverified(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def int_b64u(value: int) -> str:
    width = max(1, (value.bit_length() + 7) // 8)
    return b64u(value.to_bytes(width, "big"))


def rsa_jwk(key, kid: str, alg: str) -> dict:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": int_b64u(public.n),
        "e": int_b64u(public.e),
        "d": int_b64u(numbers.d),
        "p": int_b64u(numbers.p),
        "q": int_b64u(numbers.q),
        "dp": int_b64u(numbers.dmp1),
        "dq": int_b64u(numbers.dmq1),
        "qi": int_b64u(numbers.iqmp),
    }


def ec_jwk(key, kid: str, alg: str = "ES256") -> dict:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "crv": "P-256",
        "x": b64u(public.x.to_bytes(32, "big")),
        "y": b64u(public.y.to_bytes(32, "big")),
        "d": b64u(numbers.private_value.to_bytes(32, "big")),
    }


def ed25519_jwk(key, kid: str) -> dict:
    public = key.public_key().public_bytes_raw()
    private = key.private_bytes_raw()
    return {
        "kty": "OKP",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "crv": "Ed25519",
        "x": b64u(public),
        "d": b64u(private),
    }


def public_jwk(jwk: dict) -> dict:
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    return {k: v for k, v in jwk.items() if k not in private_fields}


def private_key_from_jwk(jwk: dict):
    def dec_int(value: str) -> int:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    if jwk["kty"] == "RSA":
        public = rsa.RSAPublicNumbers(dec_int(jwk["e"]), dec_int(jwk["n"]))
        private = rsa.RSAPrivateNumbers(
            dec_int(jwk["p"]),
            dec_int(jwk["q"]),
            dec_int(jwk["d"]),
            dec_int(jwk["dp"]),
            dec_int(jwk["dq"]),
            dec_int(jwk["qi"]),
            public,
        )
        return private.private_key()
    if jwk["kty"] == "EC":
        return ec.derive_private_key(dec_int(jwk["d"]), ec.SECP256R1())
    if jwk["kty"] == "OKP":
        padded = jwk["d"] + "=" * ((4 - len(jwk["d"]) % 4) % 4)
        return ed25519.Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
    raise ValueError(f"unsupported jwk kty: {jwk['kty']}")


class Checks:
    def __init__(self):
        self.items = []

    def ok(self, name: str, detail: str = "ok"):
        self.items.append({"name": name, "status": "ok", "detail": detail})

    def fail(self, name: str, detail: str):
        self.items.append({"name": name, "status": "failed", "detail": detail})
        raise AssertionError(f"{name}: {detail}")


checks = Checks()


def request(session, method, path, *, expected, name, **kwargs):
    url = path if path.startswith("http") else f"{BASE_URL}{path}"
    response = session.request(method, url, timeout=20, allow_redirects=False, **kwargs)
    if response.status_code not in expected:
        checks.fail(name, f"{method} {url} -> {response.status_code}: {response.text[:500]}")
    checks.ok(name, f"{method} {path} -> {response.status_code}")
    return response


def csrf_headers(session) -> dict:
    token = session.cookies.get(CSRF_COOKIE)
    if not token:
        raise AssertionError("CSRF cookie is absent")
    return {"x-csrf-token": token}


def db_url(secrets_doc: dict) -> str:
    return f"postgresql://postgres:{secrets_doc['postgres_password']}@10.101.0.10:5432/oauth"


def cleanup_rows(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH test_clients AS (
                SELECT id FROM oauth_clients
                WHERE client_name LIKE 'live-full-%' OR client_id LIKE 'live-full-%'
            ),
            test_users AS (
                SELECT id FROM users
                WHERE email LIKE 'live-full-%@auth.nazo.run'
                   OR email LIKE 'registered-live-full-%@auth.nazo.run'
            )
            DELETE FROM access_token_revocations
            WHERE client_id IN (SELECT id FROM test_clients)
            """
        )
        cur.execute(
            """
            WITH test_clients AS (
                SELECT id FROM oauth_clients
                WHERE client_name LIKE 'live-full-%' OR client_id LIKE 'live-full-%'
            ),
            test_users AS (
                SELECT id FROM users
                WHERE email LIKE 'live-full-%@auth.nazo.run'
                   OR email LIKE 'registered-live-full-%@auth.nazo.run'
            )
            DELETE FROM oauth_tokens
            WHERE client_id IN (SELECT id FROM test_clients)
               OR user_id IN (SELECT id FROM test_users)
            """
        )
        cur.execute(
            """
            WITH test_clients AS (
                SELECT id FROM oauth_clients
                WHERE client_name LIKE 'live-full-%' OR client_id LIKE 'live-full-%'
            ),
            test_users AS (
                SELECT id FROM users
                WHERE email LIKE 'live-full-%@auth.nazo.run'
                   OR email LIKE 'registered-live-full-%@auth.nazo.run'
            )
            DELETE FROM user_client_grants
            WHERE client_id IN (SELECT id FROM test_clients)
               OR user_id IN (SELECT id FROM test_users)
            """
        )
        cur.execute(
            """
            WITH test_clients AS (
                SELECT id FROM oauth_clients
                WHERE client_name LIKE 'live-full-%' OR client_id LIKE 'live-full-%'
            ),
            test_users AS (
                SELECT id FROM users
                WHERE email LIKE 'live-full-%@auth.nazo.run'
                   OR email LIKE 'registered-live-full-%@auth.nazo.run'
            )
            DELETE FROM client_access_requests
            WHERE user_id IN (SELECT id FROM test_users)
               OR approved_client_id IN (SELECT id FROM test_clients)
               OR site_name LIKE 'live-full-%'
            """
        )
        cur.execute(
            """
            DELETE FROM oauth_clients
            WHERE client_name LIKE 'live-full-%' OR client_id LIKE 'live-full-%'
            """
        )
        cur.execute(
            """
            DELETE FROM users
            WHERE email LIKE 'live-full-%@auth.nazo.run'
               OR email LIKE 'registered-live-full-%@auth.nazo.run'
            """
        )


def seed_admin(conn):
    ph = PasswordHasher()
    email = f"{RUN_ID}@auth.nazo.run"
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (
                username, email, password_hash, is_active, mfa_enabled,
                email_verified, display_name, role, admin_level
            )
            VALUES (%s, %s, %s, true, false, true, %s, 'admin', 10)
            RETURNING id
            """,
            (RUN_ID, email, ph.hash(PASSWORD), f"{RUN_ID} Admin"),
        )
        return str(cur.fetchone()[0]), email


def login(email: str, password: str) -> requests.Session:
    session = requests.Session()
    response = request(
        session,
        "POST",
        "/auth/login",
        expected={200},
        name=f"login {email}",
        json={"email": email, "password": password},
    )
    body = response.json()
    assert body["csrf_token"]
    return session


def create_email_code(redis_client, email: str, code: str):
    redis_client.set(f"oauth:email_verify:code:{email}", PasswordHasher().hash(code), ex=300)


def create_client(admin_session, payload: dict, name: str) -> dict:
    response = request(
        admin_session,
        "POST",
        "/admin/clients",
        expected={201},
        name=name,
        json=payload,
        headers=csrf_headers(admin_session),
    )
    return response.json()


def client_payload(client_name: str, client_type: str, method: str, *, jwks=None, grants=None, scopes=None):
    return {
        "client_name": client_name,
        "client_type": client_type,
        "redirect_uris": ["https://client.example/callback"],
        "scopes": scopes or ["openid", "profile", "email", "address", "phone", "offline_access"],
        "allowed_audiences": [DEFAULT_AUDIENCE, f"{BASE_URL}/userinfo"],
        "grant_types": grants or ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": method,
        "jwks": jwks,
    }


def pkce_pair():
    verifier = b64u(secrets.token_bytes(32))
    challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def authorize_to_consent(session, params: dict, name: str, *, method: str = "GET") -> str:
    if method == "POST":
        response = request(session, "POST", "/authorize", expected={302}, name=name, data=params)
    else:
        response = request(
            session,
            "GET",
            "/authorize?" + urllib.parse.urlencode(params),
            expected={302},
            name=name,
        )
    location = response.headers["location"]
    parsed = urllib.parse.urlparse(location)
    query = urllib.parse.parse_qs(parsed.query)
    if "request_id" not in query:
        checks.fail(name, f"authorize did not return consent request: {location}")
    return query["request_id"][0]


def consent(session, request_id: str, decision: str, name: str) -> str:
    response = request(
        session,
        "GET",
        f"/authorize/consent?request_id={urllib.parse.quote(request_id)}",
        expected={200},
        name=f"{name} consent detail",
    )
    csrf = response.json()["csrf_token"]
    response = request(
        session,
        "POST",
        "/authorize/decision",
        expected={302},
        name=f"{name} decision {decision}",
        data={"request_id": request_id, "decision": decision, "csrf_token": csrf},
    )
    return response.headers["location"]


def auth_code_flow(
    session,
    client_id: str,
    redirect_uri: str,
    *,
    name: str,
    request_object=None,
    request_uri=None,
    extra_params: dict | None = None,
    method: str = "GET",
):
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(12)
    expected_state = state
    if request_uri:
        params = {"client_id": client_id, "request_uri": request_uri}
        expected_state = None
    elif request_object:
        params = {"request": request_object}
        expected_state = None
    else:
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": OPENID_SCOPES,
            "state": state,
            "nonce": secrets.token_urlsafe(12),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    if extra_params:
        params.update(extra_params)
    request_id = authorize_to_consent(session, params, f"{name} authorize", method=method)
    location = consent(session, request_id, "approve", name)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    if expected_state is not None and query.get("state", [state])[0] != expected_state:
        checks.fail(name, f"state mismatch in redirect: {location}")
    return query["code"][0], verifier


def token_form_private_client(client_id: str, jwk: dict, endpoint: str, alg: str):
    now = int(time.time())
    assertion = jwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": f"{BASE_URL}{endpoint}",
            "jti": secrets.token_urlsafe(18),
            "iat": now,
            "exp": now + 300,
        },
        private_key_from_jwk(jwk),
        algorithm=alg,
        headers={"kid": jwk["kid"], "typ": "JWT"},
    )
    return {
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }


def dpop_proof(jwk: dict, method: str, endpoint: str, *, access_token=None, nonce=None):
    now = int(time.time())
    claims = {
        "htm": method,
        "htu": f"{BASE_URL}{endpoint}",
        "iat": now,
        "jti": secrets.token_urlsafe(18),
    }
    if access_token:
        claims["ath"] = b64u(hashlib.sha256(access_token.encode("ascii")).digest())
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(
        claims,
        private_key_from_jwk(jwk),
        algorithm=jwk["alg"],
        headers={"typ": "dpop+jwt", "alg": jwk["alg"], "jwk": public_jwk(jwk)},
    )


def token_public(client_id: str, code: str, verifier: str, *, dpop_jwk=None):
    form = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": "https://client.example/callback",
        "code_verifier": verifier,
    }
    headers = {}
    if dpop_jwk:
        first = request(
            requests.Session(),
            "POST",
            "/token",
            expected={400},
            name="DPoP token nonce challenge",
            data=form,
            headers={"DPoP": dpop_proof(dpop_jwk, "POST", "/token")},
        )
        nonce = first.headers.get("dpop-nonce")
        if not nonce:
            checks.fail("DPoP token nonce challenge", "missing dpop-nonce header")
        headers["DPoP"] = dpop_proof(dpop_jwk, "POST", "/token", nonce=nonce)
    response = request(
        requests.Session(),
        "POST",
        "/token",
        expected={200},
        name="token authorization_code public",
        data=form,
        headers=headers,
    )
    return response


def request_object(client_id: str, jwk: dict, alg: str):
    verifier, challenge = pkce_pair()
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "client_id": client_id,
        "aud": f"{BASE_URL}/authorize",
        "exp": now + 300,
        "iat": now,
        "nbf": now - 1,
        "jti": secrets.token_urlsafe(18),
        "response_type": "code",
        "redirect_uri": "https://client.example/callback",
        "scope": OPENID_SCOPES,
        "state": secrets.token_urlsafe(12),
        "nonce": secrets.token_urlsafe(12),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    signed = jwt.encode(
        claims,
        private_key_from_jwk(jwk),
        algorithm=alg,
        headers={"kid": jwk["kid"], "typ": "JWT"},
    )
    return signed, verifier


def run():
    verify_deployed_backend(EXPECTED_BACKEND_SHA)
    secrets_doc = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    redis_client = redis.Redis(host="10.101.0.11", port=6379, db=0, decode_responses=True)
    with psycopg.connect(db_url(secrets_doc), autocommit=True) as conn:
        cleanup_rows(conn)
        admin_id, admin_email = seed_admin(conn)

    public = requests.Session()
    request(public, "GET", "/health", expected={200}, name="health")
    health = public.get(f"{BASE_URL}/health", timeout=20)
    for header in [
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
        "x-content-type-options",
    ]:
        if header not in health.headers:
            checks.fail("security headers", f"missing {header}")
    checks.ok("security headers")
    discovery = request(public, "GET", "/.well-known/openid-configuration", expected={200}, name="openid discovery").json()
    request(public, "GET", "/.well-known/oauth-authorization-server", expected={200}, name="oauth metadata")
    request(public, "GET", "/jwks.json", expected={200}, name="jwks")
    request(public, "GET", "/auth/captcha-config", expected={200}, name="captcha config")
    request(public, "POST", "/auth/send-code", expected={503}, name="send-code disabled", json={"email": f"registered-{RUN_ID}@auth.nazo.run"})

    register_email = f"registered-{RUN_ID}@auth.nazo.run"
    code = "731924"
    create_email_code(redis_client, register_email, code)
    registered = request(
        public,
        "POST",
        "/auth/register",
        expected={201},
        name="register",
        json={"email": register_email, "verification_code": code, "password": PASSWORD},
    ).json()
    user_id = registered["id"]
    user_session = login(register_email, PASSWORD)
    admin_session = login(admin_email, PASSWORD)

    request(user_session, "GET", "/auth/csrf", expected={200}, name="csrf refresh")
    profile = request(user_session, "GET", "/auth/me", expected={200}, name="me").json()
    if profile["email"] != register_email:
        checks.fail("me", "profile email mismatch")
    request(
        user_session,
        "PATCH",
        "/auth/me",
        expected={200},
        name="profile patch",
        json={
            "display_name": f"{RUN_ID} User",
            "address_formatted": "100 Universal City Plaza\nUniversal City, CA 91608\nUS",
            "address_street_address": "100 Universal City Plaza",
            "address_locality": "Universal City",
            "address_region": "CA",
            "address_postal_code": "91608",
            "address_country": "US",
            "phone_number": "+15555550000",
        },
        headers=csrf_headers(user_session),
    )
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")
    multipart = MultipartEncoder(fields={"avatar": ("avatar.png", png, "image/png")})
    request(
        user_session,
        "POST",
        "/auth/me/avatar",
        expected={200},
        name="avatar upload",
        data=multipart,
        headers={**csrf_headers(user_session), "Content-Type": multipart.content_type},
    )
    request(user_session, "GET", "/auth/me/avatar", expected={200}, name="avatar get")
    request(user_session, "DELETE", "/auth/me/avatar", expected={200}, name="avatar delete", headers=csrf_headers(user_session))

    request(admin_session, "GET", "/admin/users?page=1&page_size=5", expected={200}, name="admin users")
    request(
        admin_session,
        "PATCH",
        f"/admin/users/{user_id}",
        expected={200},
        name="admin patch user",
        json={"is_active": True, "role": "user", "admin_level": 0},
        headers=csrf_headers(admin_session),
    )

    public_client = create_client(
        admin_session,
        client_payload(f"{RUN_ID} public", "public", "none"),
        "admin create public client",
    )
    secret_client = create_client(
        admin_session,
        client_payload(
            f"{RUN_ID} secret",
            "confidential",
            "client_secret_post",
            grants=["authorization_code", "refresh_token"],
        ),
        "admin create secret client",
    )
    machine_client = create_client(
        admin_session,
        client_payload(
            f"{RUN_ID} machine",
            "confidential",
            "client_secret_post",
            grants=["client_credentials"],
            scopes=["profile", "email"],
        ),
        "admin create machine client",
    )
    request(admin_session, "GET", "/admin/clients?page=1&page_size=5", expected={200}, name="admin clients")
    request(admin_session, "GET", f"/admin/clients/{public_client['client_id']}", expected={200}, name="admin client detail")
    request(
        admin_session,
        "PATCH",
        f"/admin/clients/{public_client['client_id']}",
        expected={200},
        name="admin patch client",
        json={"client_name": f"{RUN_ID} public patched", "is_active": True},
        headers=csrf_headers(admin_session),
    )

    first_request = request(
        user_session,
        "POST",
        "/auth/me/access-requests",
        expected={201},
        name="create access request approve",
        json={"site_name": f"{RUN_ID} approved", "site_url": "https://client.example", "request_description": "online full interface verification"},
        headers=csrf_headers(user_session),
    ).json()
    request(admin_session, "GET", "/admin/access-requests?page=1&page_size=10", expected={200}, name="admin access requests")
    request(
        admin_session,
        "POST",
        f"/admin/access-requests/{first_request['id']}/approve",
        expected={200},
        name="admin approve access request",
        json=client_payload(f"{RUN_ID} approved delivery", "confidential", "client_secret_post", grants=["authorization_code", "refresh_token"]),
        headers=csrf_headers(admin_session),
    )
    delivery_pattern = f"oauth:client_delivery:{user_id}:*"
    delivery_keys = list(redis_client.scan_iter(delivery_pattern))
    if not delivery_keys:
        checks.fail("access delivery", "delivery key missing")
    delivery_token = delivery_keys[0].split(":")[-1]
    request(user_session, "GET", f"/auth/me/access-delivery?token={urllib.parse.quote(delivery_token)}", expected={200}, name="access delivery")
    second_request = request(
        user_session,
        "POST",
        "/auth/me/access-requests",
        expected={201},
        name="create access request reject",
        json={"site_name": f"{RUN_ID} rejected", "site_url": "https://reject.example", "request_description": "online full interface verification"},
        headers=csrf_headers(user_session),
    ).json()
    request(
        admin_session,
        "POST",
        f"/admin/access-requests/{second_request['id']}/reject",
        expected={200},
        name="admin reject access request",
        json={"admin_note": "policy verification"},
        headers=csrf_headers(admin_session),
    )
    request(user_session, "GET", "/auth/me/access-requests", expected={200}, name="my access requests")

    code, verifier = auth_code_flow(user_session, public_client["client_id"], "https://client.example/callback", name="bearer auth code")
    token_response = token_public(public_client["client_id"], code, verifier)
    bearer_tokens = token_response.json()
    access_token = bearer_tokens["access_token"]
    refresh_token = bearer_tokens["refresh_token"]
    userinfo_bearer = request(
        public,
        "GET",
        "/userinfo",
        expected={200},
        name="userinfo bearer",
        headers={"authorization": f"Bearer {access_token}"},
    ).json()
    if (
        userinfo_bearer.get("address", {}).get("country") != "US"
        or userinfo_bearer.get("address", {}).get("street_address") != "100 Universal City Plaza"
        or userinfo_bearer.get("phone_number") != "+15555550000"
        or userinfo_bearer.get("phone_number_verified") is not False
    ):
        checks.fail("userinfo contact claims", json.dumps(userinfo_bearer, ensure_ascii=False))
    invalid_redirect = user_session.get(
        f"{BASE_URL}/authorize",
        params={
            "client_id": public_client["client_id"],
            "redirect_uri": "https://attacker.example/callback",
            "response_type": "code",
            "scope": "openid",
            "state": secrets.token_urlsafe(12),
            "nonce": secrets.token_urlsafe(12),
            "code_challenge": pkce_pair()[1],
            "code_challenge_method": "S256",
        },
        allow_redirects=False,
        timeout=15,
    )
    if invalid_redirect.status_code != 400:
        checks.fail(
            "authorize invalid redirect_uri error response",
            f"expected 400 got {invalid_redirect.status_code}: {invalid_redirect.text[:200]}",
        )
    if invalid_redirect.headers.get("location"):
        checks.fail("authorize invalid redirect_uri error response", "unexpected redirect")
    if "application/json" not in invalid_redirect.headers.get("content-type", ""):
        checks.fail("authorize invalid redirect_uri content type", invalid_redirect.headers.get("content-type"))
    try:
        invalid_redirect_body = invalid_redirect.json()
    except ValueError:
        checks.fail("authorize invalid redirect_uri error body", invalid_redirect.text[:200])
    else:
        if invalid_redirect_body.get("error") != "invalid_request":
            checks.fail("authorize invalid redirect_uri error body", invalid_redirect.text[:200])
    checks.ok("authorize invalid redirect_uri error response", "GET /authorize invalid redirect_uri -> 400 JSON")

    post_code, post_verifier = auth_code_flow(
        user_session,
        public_client["client_id"],
        "https://client.example/callback",
        name="POST authorize with acr",
        extra_params={"acr_values": "urn:nazo:acr:password urn:nazo:acr:mfa"},
        method="POST",
    )
    post_tokens = token_public(public_client["client_id"], post_code, post_verifier).json()
    post_id_token = decode_jwt_unverified(post_tokens["id_token"])
    if post_id_token.get("acr") != "urn:nazo:acr:password":
        checks.fail("POST authorize with acr", json.dumps(post_id_token, ensure_ascii=False))

    claims_code, claims_verifier = auth_code_flow(
        user_session,
        public_client["client_id"],
        "https://client.example/callback",
        name="authorize claims essential",
        extra_params={
            "scope": "openid",
            "claims": json.dumps({"userinfo": {"name": {"essential": True}}}, separators=(",", ":")),
        },
    )
    claims_tokens = token_public(public_client["client_id"], claims_code, claims_verifier).json()
    claims_userinfo = request(
        public,
        "GET",
        "/userinfo",
        expected={200},
        name="userinfo essential name claim",
        headers={"authorization": f"Bearer {claims_tokens['access_token']}"},
    ).json()
    if claims_userinfo.get("name") != f"{RUN_ID} User":
        checks.fail("userinfo essential name claim", json.dumps(claims_userinfo, ensure_ascii=False))

    replay_code, replay_verifier = auth_code_flow(
        user_session,
        public_client["client_id"],
        "https://client.example/callback",
        name="authorization code replay",
    )
    request(public, "POST", "/token", expected={200}, name="token before authorization code replay", data={
        "grant_type": "authorization_code",
        "client_id": public_client["client_id"],
        "code": replay_code,
        "redirect_uri": "https://client.example/callback",
        "code_verifier": replay_verifier,
    })
    replay_response = request(public, "POST", "/token", expected={400}, name="authorization code replay rejected", data={
        "grant_type": "authorization_code",
        "client_id": public_client["client_id"],
        "code": replay_code,
        "redirect_uri": "https://client.example/callback",
        "code_verifier": replay_verifier,
    }).json()
    if replay_response.get("error") != "invalid_grant":
        checks.fail("authorization code replay rejected", json.dumps(replay_response, ensure_ascii=False))
    if any(ord(ch) > 0x7E or ch == "\\" for ch in replay_response.get("error_description", "")):
        checks.fail("authorization code replay error_description charset", replay_response.get("error_description"))

    introspect_form = {
        "token": access_token,
        "client_id": secret_client["client_id"],
        "client_secret": secret_client["client_secret"],
    }
    active = request(public, "POST", "/introspect", expected={200}, name="introspect active", data=introspect_form).json()
    if active.get("active") is not True:
        checks.fail("introspect active", json.dumps(active, ensure_ascii=False))
    refreshed = request(
        public,
        "POST",
        "/token",
        expected={200},
        name="token refresh",
        data={"grant_type": "refresh_token", "client_id": public_client["client_id"], "refresh_token": refresh_token},
    ).json()
    if "access_token" not in refreshed:
        checks.fail("token refresh", "missing access_token")
    request(public, "POST", "/revoke", expected={200}, name="revoke access token", data={"token": access_token, "client_id": public_client["client_id"]})
    inactive = request(public, "POST", "/introspect", expected={200}, name="introspect revoked", data=introspect_form).json()
    if inactive.get("active") is not False:
        checks.fail("introspect revoked", json.dumps(inactive, ensure_ascii=False))
    request(public, "GET", "/userinfo", expected={401}, name="userinfo after access revoke", headers={"authorization": f"Bearer {access_token}"})

    request(user_session, "GET", "/auth/me/applications", expected={200}, name="my applications")
    request(admin_session, "GET", "/admin/grants?page=1&page_size=10", expected={200}, name="admin grants")
    request(
        admin_session,
        "POST",
        "/admin/grants/revoke",
        expected={200},
        name="admin revoke grant",
        json={"user_id": user_id, "client_id": public_client["client_id"]},
        headers=csrf_headers(admin_session),
    )

    request(
        public,
        "POST",
        "/token",
        expected={200},
        name="client_credentials secret",
            data={
                "grant_type": "client_credentials",
                "client_id": machine_client["client_id"],
                "client_secret": machine_client["client_secret"],
                "scope": "profile",
            },
    )

    alg_keys = {
        "RS256": rsa_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048), f"{RUN_ID}-rs256", "RS256"),
        "PS256": rsa_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048), f"{RUN_ID}-ps256", "PS256"),
        "ES256": ec_jwk(ec.generate_private_key(ec.SECP256R1()), f"{RUN_ID}-es256", "ES256"),
        "EdDSA": ed25519_jwk(ed25519.Ed25519PrivateKey.generate(), f"{RUN_ID}-eddsa"),
    }
    private_clients = {}
    for alg, jwk in alg_keys.items():
        private_clients[alg] = create_client(
            admin_session,
            client_payload(
                f"{RUN_ID} {alg}",
                "confidential",
                "private_key_jwt",
                jwks={"keys": [public_jwk(jwk)]},
                grants=["client_credentials"],
                scopes=["profile", "email"],
            ),
            f"admin create private_key_jwt {alg}",
        )
        response = request(
            public,
            "POST",
            "/token",
            expected={200},
            name=f"client_credentials private_key_jwt {alg}",
            data={
                "grant_type": "client_credentials",
                "scope": "profile",
                **token_form_private_client(private_clients[alg]["client_id"], jwk, "/token", alg),
            },
        )
        if response.json()["token_type"] not in {"Bearer", "DPoP"}:
            checks.fail(f"client_credentials private_key_jwt {alg}", "invalid token_type")

    par_verifier, par_challenge = pkce_pair()
    par_response = request(
        public,
        "POST",
        "/par",
        expected={201},
        name="pushed authorization request",
        data={
            "client_id": public_client["client_id"],
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "scope": OPENID_SCOPES,
            "state": secrets.token_urlsafe(12),
            "nonce": secrets.token_urlsafe(12),
            "code_challenge": par_challenge,
            "code_challenge_method": "S256",
        },
    ).json()
    request_id = authorize_to_consent(
        user_session,
        {"client_id": public_client["client_id"], "request_uri": par_response["request_uri"]},
        "authorize with request_uri",
    )
    par_location = consent(user_session, request_id, "approve", "PAR")
    par_code = urllib.parse.parse_qs(urllib.parse.urlparse(par_location).query)["code"][0]
    request(
        public,
        "POST",
        "/token",
        expected={200},
        name="token after PAR",
        data={
            "grant_type": "authorization_code",
            "client_id": public_client["client_id"],
            "code": par_code,
            "redirect_uri": "https://client.example/callback",
            "code_verifier": par_verifier,
        },
    )

    jar_client = create_client(
        admin_session,
        client_payload(
            f"{RUN_ID} jar ps256",
            "confidential",
            "private_key_jwt",
            jwks={"keys": [public_jwk(alg_keys["PS256"])]},
            grants=["authorization_code", "refresh_token"],
        ),
        "admin create JAR client",
    )
    jar_token, jar_verifier = request_object(jar_client["client_id"], alg_keys["PS256"], "PS256")
    jar_code, _ = auth_code_flow(
        user_session,
        jar_client["client_id"],
        "https://client.example/callback",
        name="JAR",
        request_object=jar_token,
    )
    request(
        public,
        "POST",
        "/token",
        expected={200},
        name="token after JAR",
        data={
            "grant_type": "authorization_code",
            "code": jar_code,
            "redirect_uri": "https://client.example/callback",
            "code_verifier": jar_verifier,
            **token_form_private_client(jar_client["client_id"], alg_keys["PS256"], "/token", "PS256"),
        },
    )

    dpop_key = ec_jwk(ec.generate_private_key(ec.SECP256R1()), f"{RUN_ID}-dpop", "ES256")
    dpop_code, dpop_verifier = auth_code_flow(user_session, public_client["client_id"], "https://client.example/callback", name="DPoP auth code")
    dpop_token_response = token_public(public_client["client_id"], dpop_code, dpop_verifier, dpop_jwk=dpop_key)
    dpop_token = dpop_token_response.json()["access_token"]
    request(public, "GET", "/userinfo", expected={401}, name="DPoP token with Bearer rejected", headers={"authorization": f"Bearer {dpop_token}"})
    first_userinfo = request(
        public,
        "GET",
        "/userinfo",
        expected={401},
        name="DPoP userinfo nonce challenge",
        headers={
            "authorization": f"DPoP {dpop_token}",
            "DPoP": dpop_proof(dpop_key, "GET", "/userinfo", access_token=dpop_token),
        },
    )
    userinfo_nonce = first_userinfo.headers.get("dpop-nonce")
    if not userinfo_nonce:
        checks.fail("DPoP userinfo nonce challenge", "missing dpop-nonce header")
    request(
        public,
        "GET",
        "/userinfo",
        expected={200},
        name="userinfo DPoP",
        headers={
            "authorization": f"DPoP {dpop_token}",
            "DPoP": dpop_proof(dpop_key, "GET", "/userinfo", access_token=dpop_token, nonce=userinfo_nonce),
        },
    )

    deny_code, deny_challenge = pkce_pair()
    deny_request_id = authorize_to_consent(
        user_session,
        {
            "client_id": public_client["client_id"],
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "scope": "openid",
            "state": secrets.token_urlsafe(12),
            "nonce": secrets.token_urlsafe(12),
            "code_challenge": deny_challenge,
            "code_challenge_method": "S256",
        },
        "authorize deny path",
    )
    deny_location = consent(user_session, deny_request_id, "deny", "deny path")
    deny_query = urllib.parse.parse_qs(urllib.parse.urlparse(deny_location).query)
    if deny_query.get("error", [None])[0] != "access_denied":
        checks.fail("deny path", deny_location)
    checks.ok("authorization deny redirect")

    request(user_session, "POST", "/auth/logout", expected={200}, name="user logout")
    request(admin_session, "POST", "/auth/logout", expected={200}, name="admin logout")

    with psycopg.connect(db_url(secrets_doc), autocommit=True) as conn:
        cleanup_rows(conn)
    for key in redis_client.scan_iter("oauth:email_verify:*live-full-*"):
        redis_client.delete(key)

    print(json.dumps({
        "run_id": RUN_ID,
        "issuer": discovery["issuer"],
        "checks": checks.items,
        "total": len(checks.items),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
