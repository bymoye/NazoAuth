#!/usr/bin/env python3
"""Project-owned RFC 9967 / RFC 8936 black-box HTTP conformance matrix."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from full_real_request_source_policy import (
    RuntimeCaseEvidence,
    execute_case_registry,
    validate_case_registry,
)

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "tests" / "contracts" / "rfc9967-scim-set-matrix.json"
BASE_URL = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ISSUER_URL = os.environ.get("E2E_ISSUER_URL", "http://127.0.0.1:8000").rstrip("/")
DATABASE_URL = os.environ.get(
    "E2E_DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:5432/oauth"
)
UNREGISTERED_TOKEN = "rfc9967-unregistered-token"
TENANT_ID = "00000000-0000-0000-0000-000000000001"
POLL_PATH = "/scim/v2/SecurityEvents"
CONFIG_PATH = "/scim/v2/ServiceProviderConfig"
CREATE = "urn:ietf:params:scim:event:prov:create:notice"
PATCH = "urn:ietf:params:scim:event:prov:patch:notice"
PUT = "urn:ietf:params:scim:event:prov:put:notice"
ACTIVATE = "urn:ietf:params:scim:event:prov:activate"
DEACTIVATE = "urn:ietf:params:scim:event:prov:deactivate"
EVENT_URIS = [CREATE, PATCH, PUT, ACTIVATE, DEACTIVATE]
REQUIRED_CASES = frozenset(
    {
        "discovery_exact_event_uris",
        "poll_authorization_boundaries",
        "create_notice_set_claims",
        "receiver_audience_and_ack_isolation",
        "ack_is_terminal_for_receiver",
        "set_error_requires_content_language",
        "patch_notice_and_deactivate_events",
        "put_notice_and_activate_events",
        "poll_pagination_preserves_order",
        "long_poll_wakes_on_new_event",
        "invalid_poll_shapes_fail_closed",
    }
)
ALLOWED_HANDLERS = frozenset(
    {
        "discovery",
        "authorization",
        "create_notice",
        "receiver_isolation",
        "ack_terminal",
        "set_error_language",
        "patch_deactivate",
        "put_activate",
        "pagination",
        "long_poll",
        "invalid_poll",
    }
)


def load_registry() -> tuple[tuple[str, str, dict[str, object]], ...]:
    payload = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or payload.get("standard") != "RFC 9967":
        raise AssertionError("RFC 9967 matrix metadata is invalid")
    return tuple(
        (item["name"], item["handler"], dict(item.get("parameters", {})))
        for item in payload.get("cases", [])
    )


def assert_destructive_targets_are_e2e() -> None:
    """Refuse SCIM seed/cleanup against an unrecognised database or service.

    This runner writes and deletes rows.  A loopback default is convenient for
    HTTP-only checks but is unsafe for a destructive matrix, so only the
    repository-owned Docker E2E target (or an explicitly named disposable
    coverage/same-container fixture) is accepted.
    """

    database = urlparse(DATABASE_URL)
    base = urlparse(BASE_URL)
    actual = {
        "database_scheme": database.scheme,
        "database_host": database.hostname,
        "database_port": database.port,
        "database_name": database.path.lstrip("/"),
        "base_scheme": base.scheme,
        "base_host": base.hostname,
        "base_port": base.port,
    }
    allowed_targets = [
        {
            "database_scheme": "postgresql",
            "database_host": "nazo-oauth-e2e-postgres",
            "database_port": 5432,
            "database_name": "oauth",
            "base_scheme": "http",
            "base_host": "nazo-oauth-e2e-server",
            "base_port": 8000,
        }
    ]
    if os.environ.get("E2E_ALLOW_SAME_CONTAINER_LOOPBACK") == "1":
        allowed_targets.append(
            {
                "database_scheme": "postgresql",
                "database_host": "postgres",
                "database_port": 5432,
                "database_name": "oauth",
                "base_scheme": "http",
                "base_host": "127.0.0.1",
                "base_port": 8000,
            }
        )
    if os.environ.get("E2E_ALLOW_CODEX_COVERAGE_LOOPBACK") == "1":
        allowed_targets.append(
            {
                "database_scheme": "postgresql",
                "database_host": "127.0.0.1",
                "database_port": 15432,
                "database_name": "oauth",
                "base_scheme": "http",
                "base_host": "127.0.0.1",
                "base_port": 18000,
            }
        )
    if actual not in allowed_targets:
        raise AssertionError(
            f"refusing destructive RFC 9967 seed outside Docker E2E targets: {actual}"
        )


def expect_status(response: requests.Response, status: int) -> requests.Response:
    if response.status_code != status:
        raise AssertionError(
            f"{response.request.method} {response.request.url}: expected {status}, "
            f"got {response.status_code}: {response.text[:500]}"
        )
    return response


def expect_json(response: requests.Response) -> dict[str, Any]:
    value = response.json()
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object, got {type(value).__name__}")
    return value


@dataclass
class MatrixContext:
    evidence: RuntimeCaseEvidence
    tokens: dict[str, str] = field(default_factory=dict)
    token_ids: list[uuid.UUID] = field(default_factory=list)
    user_id: str | None = None
    jwks: dict[str, Any] | None = None

    def headers(self, token: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "User-Agent": "nazo-rfc9967-matrix", **extra}

    def observe(self, case: str, condition: bool) -> None:
        self.evidence.observe(case, condition)

    def seed_tokens(self) -> None:
        assert_destructive_targets_are_e2e()
        definitions = {
            "a": (["scim:read", "scim:write", "scim:events"], "https://receiver-a.example/events"),
            "b": (["scim:read", "scim:write", "scim:events"], "https://receiver-b.example/events"),
            "write": (["scim:write"], None),
            "no_audience": (["scim:events"], None),
        }
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                for label, (scopes, audience) in definitions.items():
                    token = f"rfc9967-{label}-{uuid.uuid4()}"
                    token_id = uuid.uuid4()
                    cursor.execute(
                        """
                        INSERT INTO scim_tokens (id, tenant_id, token_hash, label, scopes, event_audience)
                        VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                        """,
                        (
                            token_id,
                            TENANT_ID,
                            blake3.blake3(token.encode()).hexdigest(),
                            f"RFC 9967 matrix {label}",
                            json.dumps(scopes),
                            audience,
                        ),
                    )
                    self.tokens[label] = token
                    self.token_ids.append(token_id)

    def cleanup(self) -> None:
        assert_destructive_targets_are_e2e()
        errors: list[str] = []
        if self.user_id is not None and "a" in self.tokens:
            try:
                response = requests.delete(
                    f"{BASE_URL}/scim/v2/Users/{self.user_id}",
                    headers=self.headers(self.tokens["a"]),
                    timeout=10,
                )
                if response.status_code not in {204, 404}:
                    errors.append(
                        f"SCIM user cleanup returned HTTP {response.status_code}: "
                        f"{response.text[:200]}"
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"SCIM user cleanup failed: {exc}")
        if self.token_ids:
            try:
                with psycopg.connect(DATABASE_URL) as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM scim_audit_events WHERE scim_token_id = ANY(%s)",
                            (self.token_ids,),
                        )
                        cursor.execute(
                            "DELETE FROM scim_tokens WHERE id = ANY(%s)",
                            (self.token_ids,),
                        )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"SCIM token cleanup failed: {exc}")
        if errors:
            raise RuntimeError("RFC 9967 cleanup incomplete: " + "; ".join(errors))
        print("RFC 9967 fixture cleanup complete", flush=True)

    def poll(
        self,
        token_name: str,
        payload: dict[str, Any] | None = None,
        *,
        language: str | None = None,
        timeout: float = 12,
    ) -> requests.Response:
        extra = {"Content-Language": language} if language else {}
        return requests.post(
            f"{BASE_URL}{POLL_PATH}",
            json=payload or {"returnImmediately": True},
            headers=self.headers(self.tokens[token_name], **extra),
            timeout=timeout,
        )

    def poll_sets(self, token_name: str, payload: dict[str, Any] | None = None) -> dict[str, str]:
        document = expect_json(expect_status(self.poll(token_name, payload), 200))
        sets = document.get("sets")
        if not isinstance(sets, dict):
            raise AssertionError("poll response sets is not an object")
        return sets

    def decode_set(self, encoded: str, audience: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.jwks is None:
            self.jwks = expect_json(expect_status(requests.get(f"{BASE_URL}/jwks.json", timeout=10), 200))
        header = jwt.get_unverified_header(encoded)
        candidates = [key for key in self.jwks.get("keys", []) if key.get("kid") == header.get("kid")]
        if len(candidates) != 1:
            raise AssertionError("SET signing key is not uniquely present in JWKS")
        key = jwt.PyJWK.from_dict(candidates[0]).key
        claims = jwt.decode(
            encoded,
            key,
            algorithms=[header["alg"]],
            audience=audience,
            issuer=ISSUER_URL,
            options={"require": ["iss", "iat", "jti", "txn", "aud", "sub_id", "events"]},
        )
        return header, claims

    def create_user(self) -> str:
        email = f"rfc9967-{uuid.uuid4()}@example.com"
        response = requests.post(
            f"{BASE_URL}/scim/v2/Users",
            headers=self.headers(self.tokens["a"]),
            json={
                "userName": email,
                "active": True,
                "name": {"formatted": "RFC 9967 Matrix", "givenName": "RFC", "familyName": "Matrix"},
                "emails": [{"value": email, "primary": True}],
            },
            timeout=10,
        )
        self.user_id = str(expect_json(expect_status(response, 201))["id"])
        return self.user_id

    def patch_user(self, operations: list[dict[str, Any]]) -> None:
        response = requests.patch(
            f"{BASE_URL}/scim/v2/Users/{self.user_id}",
            headers=self.headers(self.tokens["a"]),
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": operations,
            },
            timeout=10,
        )
        expect_status(response, 200)

    def ack(self, token_name: str, event_ids: list[str]) -> dict[str, Any]:
        return expect_json(
            expect_status(
                self.poll(token_name, {"ack": event_ids, "returnImmediately": True}), 200
            )
        )


def handlers(context: MatrixContext) -> dict[str, Any]:
    def discovery(case: str, _: dict[str, object]) -> None:
        config = expect_json(
            expect_status(
                requests.get(
                    f"{BASE_URL}{CONFIG_PATH}", headers=context.headers(context.tokens["a"]), timeout=10
                ),
                200,
            )
        )
        context.observe(
            case,
            config.get("securityEvents")
            == {"eventUris": EVENT_URIS, "asyncRequest": "none"},
        )

    def authorization(case: str, _: dict[str, object]) -> None:
        missing = expect_status(requests.post(f"{BASE_URL}{POLL_PATH}", json={}, timeout=10), 401)
        unregistered = expect_status(
            requests.post(
                f"{BASE_URL}{POLL_PATH}",
                json={},
                headers=context.headers(UNREGISTERED_TOKEN),
                timeout=10,
            ),
            401,
        )
        write = expect_status(context.poll("write"), 403)
        no_audience = expect_status(context.poll("no_audience"), 403)
        context.observe(
            case,
            missing.headers.get("WWW-Authenticate") == "Bearer"
            and unregistered.headers.get("WWW-Authenticate") == "Bearer"
            and missing.status_code == unregistered.status_code == 401
            and write.status_code == no_audience.status_code == 403,
        )

    def create_notice(case: str, _: dict[str, object]) -> None:
        user_id = context.create_user()
        sets = context.poll_sets("a")
        if len(sets) != 1:
            raise AssertionError(f"create must produce one SET, got {len(sets)}")
        event_id, encoded = next(iter(sets.items()))
        header, claims = context.decode_set(encoded, "https://receiver-a.example/events")
        context.observe(
            case,
            header.get("typ") == "secevent+jwt"
            and claims["jti"] == event_id
            and claims["sub_id"] == {"format": "scim", "uri": f"/Users/{user_id}"}
            and set(claims["events"]) == {CREATE}
            and claims["events"][CREATE]["attributes"]
            == ["active", "emails", "id", "name", "userName"]
            and "sub" not in claims
            and "exp" not in claims,
        )

    def receiver_isolation(case: str, _: dict[str, object]) -> None:
        sets_a = context.poll_sets("a")
        sets_b = context.poll_sets("b")
        if set(sets_a) != set(sets_b) or len(sets_a) != 1:
            raise AssertionError("receivers did not independently observe the same stored event")
        event_id = next(iter(sets_a))
        _, claims_a = context.decode_set(sets_a[event_id], "https://receiver-a.example/events")
        _, claims_b = context.decode_set(sets_b[event_id], "https://receiver-b.example/events")
        context.ack("a", [event_id])
        retained_b = context.poll_sets("b")
        context.ack("b", [event_id])
        context.observe(
            case,
            claims_a["aud"] == ["https://receiver-a.example/events"]
            and claims_b["aud"] == ["https://receiver-b.example/events"]
            and sets_a[event_id] != sets_b[event_id]
            and event_id in retained_b,
        )

    def ack_terminal(case: str, _: dict[str, object]) -> None:
        response = expect_json(expect_status(context.poll("a"), 200))
        context.observe(case, response.get("sets") == {} and response.get("moreAvailable") is False)

    def set_error_language(case: str, _: dict[str, object]) -> None:
        context.patch_user([{"op": "replace", "path": "name.familyName", "value": "Rejected"}])
        sets = context.poll_sets("a")
        event_id = next(iter(sets))
        payload = {
            "returnImmediately": True,
            "setErrs": {event_id: {"err": "jwtClaims", "description": "invalid claims"}},
        }
        missing = expect_status(context.poll("a", payload), 400)
        accepted = expect_json(expect_status(context.poll("a", payload, language="en"), 200))
        terminal = context.poll_sets("a")
        context.observe(
            case,
            missing.status_code == 400 and accepted.get("sets") == {} and terminal == {},
        )

    def patch_deactivate(case: str, _: dict[str, object]) -> None:
        context.patch_user([{"op": "replace", "path": "active", "value": False}])
        sets = context.poll_sets("a")
        event_id, encoded = next(iter(sets.items()))
        _, claims = context.decode_set(encoded, "https://receiver-a.example/events")
        context.ack("a", [event_id])
        context.observe(
            case,
            set(claims["events"]) == {PATCH, DEACTIVATE}
            and claims["events"][PATCH]["attributes"] == ["active"],
        )

    def put_activate(case: str, _: dict[str, object]) -> None:
        email = f"rfc9967-put-{uuid.uuid4()}@example.com"
        response = requests.put(
            f"{BASE_URL}/scim/v2/Users/{context.user_id}",
            headers=context.headers(context.tokens["a"]),
            json={
                "userName": email,
                "active": True,
                "name": {"formatted": "RFC PUT", "givenName": "RFC", "familyName": "PUT"},
                "emails": [{"value": email, "primary": True}],
            },
            timeout=10,
        )
        expect_status(response, 200)
        sets = context.poll_sets("a")
        event_id, encoded = next(iter(sets.items()))
        _, claims = context.decode_set(encoded, "https://receiver-a.example/events")
        context.ack("a", [event_id])
        context.observe(
            case,
            set(claims["events"]) == {PUT, ACTIVATE}
            and claims["events"][PUT]["attributes"] == ["active", "emails", "name", "userName"],
        )

    def pagination(case: str, _: dict[str, object]) -> None:
        context.patch_user([{"op": "replace", "path": "name.familyName", "value": "Page One"}])
        context.patch_user([{"op": "replace", "path": "name.familyName", "value": "Page Two"}])
        first = expect_json(
            expect_status(context.poll("a", {"maxEvents": 1, "returnImmediately": True}), 200)
        )
        first_id = next(iter(first["sets"]))
        second = expect_json(
            expect_status(
                context.poll(
                    "a", {"maxEvents": 1, "returnImmediately": True, "ack": [first_id]}
                ),
                200,
            )
        )
        second_id = next(iter(second["sets"]))
        terminal = context.ack("a", [second_id])
        context.observe(
            case,
            first["moreAvailable"] is True
            and first_id != second_id
            and second["moreAvailable"] is False
            and terminal["sets"] == {},
        )

    def long_poll(case: str, _: dict[str, object]) -> None:
        result: dict[str, Any] = {}

        def wait_for_set() -> None:
            started = time.monotonic()
            response = context.poll("a", {"maxEvents": 1, "returnImmediately": False}, timeout=15)
            result["elapsed"] = time.monotonic() - started
            result["document"] = expect_json(expect_status(response, 200))

        thread = threading.Thread(target=wait_for_set, daemon=True)
        thread.start()
        time.sleep(0.75)
        context.patch_user([{"op": "replace", "path": "name.familyName", "value": "Wake"}])
        thread.join(timeout=12)
        if thread.is_alive():
            raise AssertionError("long poll did not wake after a new event")
        sets = result["document"]["sets"]
        event_id = next(iter(sets))
        context.ack("a", [event_id])
        context.observe(case, len(sets) == 1 and 0.5 <= result["elapsed"] < 8.0)

    def invalid_poll(case: str, _: dict[str, object]) -> None:
        excessive = expect_status(
            context.poll("a", {"maxEvents": 101, "returnImmediately": True}), 400
        )
        event_id = str(uuid.uuid4())
        duplicate = expect_status(
            context.poll("a", {"ack": [event_id, event_id], "returnImmediately": True}), 400
        )
        unknown = expect_status(
            context.poll("a", {"returnImmediately": True, "unexpected": True}), 400
        )
        context.observe(
            case,
            excessive.status_code == duplicate.status_code == unknown.status_code == 400,
        )

    return {
        "discovery": discovery,
        "authorization": authorization,
        "create_notice": create_notice,
        "receiver_isolation": receiver_isolation,
        "ack_terminal": ack_terminal,
        "set_error_language": set_error_language,
        "patch_deactivate": patch_deactivate,
        "put_activate": put_activate,
        "pagination": pagination,
        "long_poll": long_poll,
        "invalid_poll": invalid_poll,
    }


def source_policy_check() -> None:
    registry = load_registry()
    validate_case_registry(
        registry, required=REQUIRED_CASES, allowed_handlers=ALLOWED_HANDLERS
    )
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = ("scim_security_" + "events", "scim_security_event_" + "receipts")
    if any(name in source for name in forbidden):
        raise AssertionError("black-box runner must not inspect event persistence tables")
    print(f"RFC 9967 source policy passed ({len(registry)} exact cases)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-policy-check", action="store_true")
    args = parser.parse_args()
    if args.source_policy_check:
        source_policy_check()
        return

    assert_destructive_targets_are_e2e()
    global blake3, jwt, psycopg, requests
    import blake3
    import jwt
    import psycopg
    import requests

    registry = load_registry()
    evidence = RuntimeCaseEvidence(REQUIRED_CASES)
    context = MatrixContext(evidence)
    try:
        context.seed_tokens()
        executed = execute_case_registry(
            registry,
            handlers(context),
            required=REQUIRED_CASES,
            allowed_handlers=ALLOWED_HANDLERS,
            evidence=evidence,
        )
        print(f"RFC 9967 black-box matrix passed ({len(executed)} cases)")
    finally:
        context.cleanup()


if __name__ == "__main__":
    main()
