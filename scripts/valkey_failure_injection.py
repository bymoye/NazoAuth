#!/usr/bin/env python3
"""Validate externally visible behavior while Valkey is unavailable."""

from __future__ import annotations

import json
import os

import requests


BASE_URL = os.environ.get("E2E_BASE_URL", "http://nazo-oauth-e2e-server:8000").rstrip("/")


def fail(name: str, detail: object) -> None:
    print(json.dumps({"check": name, "ok": False, "detail": detail}, ensure_ascii=False))
    raise SystemExit(1)


def ok(name: str, detail: object | None = None) -> None:
    print(json.dumps({"check": name, "ok": True, "detail": detail}, ensure_ascii=False))


def response_json(response: requests.Response) -> dict[str, object]:
    try:
        payload = response.json()
    except ValueError:
        fail("valkey_outage_json_error_body", response.text[:200])
    if not isinstance(payload, dict):
        fail("valkey_outage_json_error_body", payload)
    return payload


def main() -> int:
    health = requests.get(f"{BASE_URL}/health", timeout=5)
    health_payload = response_json(health)
    if health.status_code != 503:
        fail("health_without_valkey", {"status": health.status_code, "body": health.text[:200]})
    if health_payload != {
        "status": "not_ready",
        "checks": {
            "postgresql": {"status": "up"},
            "signing_keys": {"status": "up"},
            "valkey": {"status": "down"},
        },
    }:
        fail("health_without_valkey", health_payload)
    ok("health_without_valkey", {"status": health.status_code, "body": health_payload})

    token = requests.post(
        f"{BASE_URL}/token",
        data={"grant_type": "client_credentials", "client_id": "missing-client"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    payload = response_json(token)
    if token.status_code != 503:
        fail("token_rejects_when_valkey_unavailable", {"status": token.status_code, "body": payload})
    if payload.get("error") != "server_error":
        fail("token_valkey_failure_error_code", payload)
    leaked_fields = sorted({"access_token", "refresh_token", "id_token"} & payload.keys())
    if leaked_fields:
        fail("token_valkey_failure_no_token_material", leaked_fields)
    ok("token_rejects_when_valkey_unavailable", {"status": token.status_code, "error": payload.get("error")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
