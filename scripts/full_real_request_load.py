#!/usr/bin/env python3
"""Real HTTP load gate for nazo-oauth-server.

The script creates a dedicated confidential client through the admin HTTP API,
then measures health, discovery, token, and token-management traffic against a
running isolated E2E deployment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import statistics
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from urllib.parse import urlparse

import psycopg
import requests
from argon2 import PasswordHasher


BASE_URL = os.environ.get("E2E_BASE_URL", "http://nazo-oauth-e2e-server:8000")
DATABASE_URL = os.environ.get(
    "E2E_DATABASE_URL",
    "postgresql://postgres:postgres@nazo-oauth-e2e-postgres:5432/oauth",
)
ADMIN_EMAIL = os.environ.get("LOAD_ADMIN_EMAIL", "admin-load-e2e@example.com")
ADMIN_PASSWORD = os.environ.get("LOAD_ADMIN_PASSWORD", "AdminLoadPassword-2026")
LOAD_REQUESTS = int(os.environ.get("LOAD_REQUESTS", "300"))
LOAD_CONCURRENCY = int(os.environ.get("LOAD_CONCURRENCY", "24"))
DEFAULT_AUDIENCE = "resource://default"
DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_REALM_ID = "00000000-0000-0000-0000-000000000002"
DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000003"


def fail(message: str) -> None:
    raise AssertionError(message)


def assert_e2e_target() -> None:
    database = urlparse(DATABASE_URL)
    base = urlparse(BASE_URL)
    actual = {
        "database_host": database.hostname,
        "database_name": database.path.lstrip("/"),
        "base_host": base.hostname,
    }
    expected = {
        "database_host": "nazo-oauth-e2e-postgres",
        "database_name": "oauth",
        "base_host": "nazo-oauth-e2e-server",
    }
    if actual != expected:
        fail(f"refusing load seed outside Docker E2E targets: {actual}")


def wait_for_service() -> None:
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    fail("service did not become healthy")


def seed_admin() -> None:
    assert_e2e_target()
    password_hash = PasswordHasher().hash(ADMIN_PASSWORD)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM users WHERE tenant_id = %s AND email = %s",
                (DEFAULT_TENANT_ID, ADMIN_EMAIL),
            )
            cur.execute(
                """
                INSERT INTO users (
                    tenant_id, realm_id, organization_id, username, email,
                    password_hash, email_verified, display_name, role, admin_level,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, 'admin', 10, TRUE)
                """,
                (
                    DEFAULT_TENANT_ID,
                    DEFAULT_REALM_ID,
                    DEFAULT_ORGANIZATION_ID,
                    "admin_load_e2e",
                    ADMIN_EMAIL,
                    password_hash,
                    "Admin Load E2E",
                ),
            )
        conn.commit()


def csrf_header(session: requests.Session) -> dict[str, str]:
    token = session.cookies.get("nazo_oauth_csrf")
    if not token:
        fail("missing csrf cookie")
    return {"x-csrf-token": token}


def totp_code(secret_base32: str) -> str:
    normalized = "".join(secret_base32.split()).upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    secret = base64.b32decode(normalized + padding)
    step = int(time.time()) // 30
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def create_load_client() -> tuple[str, str]:
    admin = requests.Session()
    login = admin.post(
        f"{BASE_URL}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    if login.status_code != 200:
        fail(f"admin login failed: {login.status_code} {login.text}")
    begin = admin.post(
        f"{BASE_URL}/auth/me/mfa/totp/begin",
        headers=csrf_header(admin),
        timeout=10,
    )
    if begin.status_code != 200:
        fail(f"admin TOTP enrollment failed: {begin.status_code} {begin.text}")
    confirm = admin.post(
        f"{BASE_URL}/auth/me/mfa/totp/confirm",
        json={"code": totp_code(begin.json()["secret_base32"])},
        headers=csrf_header(admin),
        timeout=10,
    )
    if confirm.status_code != 200 or confirm.json().get("mfa_enabled") is not True:
        fail(f"admin TOTP confirmation failed: {confirm.status_code} {confirm.text}")
    response = admin.post(
        f"{BASE_URL}/admin/clients",
        json={
            "client_name": "Load Test Client",
            "client_type": "confidential",
            "redirect_uris": [],
            "scopes": ["profile"],
            "allowed_audiences": [DEFAULT_AUDIENCE],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "jwks": None,
        },
        headers=csrf_header(admin),
        timeout=10,
    )
    if response.status_code != 201:
        fail(f"load client creation failed: {response.status_code} {response.text}")
    body = response.json()
    return body["client_id"], body["client_secret"]


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, round((len(values) - 1) * pct)))
    return sorted(values)[index]


def run_phase(name: str, requests_count: int, concurrency: int, call: Callable[[], None]) -> dict[str, Any]:
    durations: list[float] = []
    errors: list[str] = []
    started = time.perf_counter()

    def one() -> float:
        t0 = time.perf_counter()
        call()
        return time.perf_counter() - t0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one) for _ in range(requests_count)]
        for future in as_completed(futures):
            try:
                durations.append(future.result())
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

    elapsed = time.perf_counter() - started
    return {
        "name": name,
        "requests": requests_count,
        "concurrency": concurrency,
        "ok": len(durations),
        "errors": len(errors),
        "sample_errors": errors[:5],
        "elapsed_seconds": round(elapsed, 4),
        "rps": round(len(durations) / elapsed, 2) if elapsed > 0 else 0,
        "latency_ms": {
            "min": round(min(durations) * 1000, 2) if durations else 0,
            "mean": round(statistics.fmean(durations) * 1000, 2) if durations else 0,
            "p50": round(percentile(durations, 0.50) * 1000, 2),
            "p95": round(percentile(durations, 0.95) * 1000, 2),
            "p99": round(percentile(durations, 0.99) * 1000, 2),
            "max": round(max(durations) * 1000, 2) if durations else 0,
        },
    }


def main() -> None:
    seed_admin()
    wait_for_service()
    client_id, client_secret = create_load_client()

    def health() -> None:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code != 200:
            fail(f"health failed: {response.status_code}")

    def discovery() -> None:
        response = requests.get(f"{BASE_URL}/.well-known/openid-configuration", timeout=10)
        if response.status_code != 200:
            fail(f"discovery failed: {response.status_code}")

    def token() -> None:
        response = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "profile",
            },
            timeout=10,
        )
        if response.status_code != 200 or not response.json().get("access_token"):
            fail(f"token failed: {response.status_code} {response.text}")

    def token_introspect() -> None:
        token_response = requests.post(
            f"{BASE_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "profile",
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            fail(f"token for introspection failed: {token_response.status_code}")
        access_token = token_response.json()["access_token"]
        introspect = requests.post(
            f"{BASE_URL}/introspect",
            data={
                "token": access_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=10,
        )
        body = introspect.json()
        if introspect.status_code != 200 or body.get("active") is not True:
            fail(f"introspection failed: {introspect.status_code} {introspect.text}")

    per_phase = max(1, LOAD_REQUESTS // 4)
    result = {
        "base_url": BASE_URL,
        "total_configured_requests": per_phase * 4,
        "configured_concurrency": LOAD_CONCURRENCY,
        "phases": [
            run_phase("GET /health", per_phase, LOAD_CONCURRENCY, health),
            run_phase("GET /.well-known/openid-configuration", per_phase, LOAD_CONCURRENCY, discovery),
            run_phase("POST /token client_credentials", per_phase, LOAD_CONCURRENCY, token),
            run_phase("POST /token + POST /introspect", per_phase, LOAD_CONCURRENCY, token_introspect),
        ],
    }
    result["ok"] = all(phase["errors"] == 0 for phase in result["phases"])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
