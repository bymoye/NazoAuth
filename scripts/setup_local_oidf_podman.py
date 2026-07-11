#!/usr/bin/env python3
"""Prepare gitignored local files for Podman OIDF conformance runs."""

from __future__ import annotations

import json
import os
import subprocess
import copy
import base64
import hashlib
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = ROOT.parent / "NazoAuthWeb"
RUNTIME = ROOT / "runtime" / "oidf"
ISSUER = "https://auth.nazo.run"
MTLS_ISSUER = "https://auth.nazo.run"
SUITE_BASE_URL = os.environ.get("OIDF_LOCAL_SUITE_BASE_URL", "https://nginx:8443").rstrip("/")
BASIC_ALIAS = os.environ.get("OIDF_LOCAL_BASIC_ALIAS", "local-nazo-oauth-oidf")
USER_EMAIL = os.environ.get("OIDF_LOCAL_USER_EMAIL", "oidf-local@example.test")
USER_PASSWORD = os.environ.get("OIDF_LOCAL_USER_PASSWORD", "oidf-local-password")
CLIENT_SECRET = os.environ.get("OIDF_LOCAL_CLIENT_SECRET", "oidf-local-client-secret")
CLIENT_SECRET_PEPPER = os.environ.get(
    "OIDF_LOCAL_CLIENT_SECRET_PEPPER",
    "oidf-local-client-secret-pepper-000000000001",
)
DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN = os.environ.get(
    "OIDF_LOCAL_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
    "oidf-local-dynamic-registration-token",
)
OIDF_CIBA_AUTOMATED_DECISION_TOKEN = os.environ.get(
    "OIDF_LOCAL_CIBA_AUTOMATED_DECISION_TOKEN",
    "oidf-local-ciba-automated-decision-token",
)
FAPI_CLIENT_PREFIX = os.environ.get("OIDF_LOCAL_FAPI_CLIENT_PREFIX", "local-oidf-fapi")
TRUSTED_PROXY_CIDRS = os.environ.get("OIDF_LOCAL_TRUSTED_PROXY_CIDRS", "10.89.0.0/16")
WRITE_ENV_YAML = os.environ.get("OIDF_LOCAL_WRITE_ENV_YAML", "1") != "0"
SKIP_UI_BUILD = os.environ.get("OIDF_LOCAL_SKIP_UI_BUILD", "0") == "1"
OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES = (
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)
OIDCC_LOCAL_AUTHORIZATION_ERROR_MODULES = (
    "oidcc-ensure-registered-redirect-uri",
    "oidcc-ensure-redirect-uri-in-authorization-request",
    "oidcc-redirect-uri-query-mismatch",
    "oidcc-redirect-uri-query-added",
)
FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH = (
    "fapi2-security-profile-id2-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-final-user-rejects-authentication"
)
FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION = (
    "fapi2-security-profile-id2-user-rejects-authentication"
)
PLAN_CONFIG_FILES = (
    "oidf-oidcc-basic-plan-config.json",
    "oidf-oidcc-dynamic-plan-config.json",
    "oidf-oidcc-dynamic-crypto-plan-config.json",
    "oidf-oidcc-config-plan-config.json",
    "oidf-oidcc-frontchannel-logout-plan-config.json",
    "oidf-oidcc-session-management-plan-config.json",
    "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json",
    "oidf-fapi-security-final-plan-config.json",
    "oidf-fapi-message-final-plan-config.json",
    "oidf-fapi-security-id2-plan-config.json",
    "oidf-fapi-message-id1-plan-config.json",
)
FAPI_MATRIX_CLIENT_AUTHS = ("private_key_jwt", "mtls")
FAPI_MATRIX_SENDER_CONSTRAINS = ("dpop", "mtls")
FAPI_MATRIX_OPENID_MODES = ("plain_oauth", "openid_connect")
NAZO_LOGIN_EMAIL_ID = "nazo-login-email"
NAZO_LOGIN_PASSWORD_ID = "nazo-login-password"
NAZO_LOGIN_SUBMIT_ID = "nazo-login-submit"
NAZO_LOGIN_SUBMIT_READY_SELECTOR = f"#{NAZO_LOGIN_SUBMIT_ID}:not([disabled])"
NAZO_CONSENT_APPROVE_ID = "nazo-consent-approve"
NAZO_CONSENT_DENY_ID = "nazo-consent-deny"
NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN = (
    r'("error"\s*:\s*"(invalid_request|invalid_request_object|access_denied|login_required|server_error)"'
    r"|invalid_request|invalid_request_object|access_denied|login_required|server_error)"
)


def login_commands(*, capture_placeholder: bool = False) -> list[list[object]]:
    commands: list[list[object]] = [
        ["wait-element-visible", "id", NAZO_LOGIN_EMAIL_ID, 30],
        ["wait-element-visible", "id", NAZO_LOGIN_PASSWORD_ID, 30],
        ["text", "id", NAZO_LOGIN_EMAIL_ID, USER_EMAIL],
        ["text", "id", NAZO_LOGIN_PASSWORD_ID, USER_PASSWORD],
        ["wait-element-visible", "id", NAZO_LOGIN_SUBMIT_ID, 30],
        ["wait-element-visible", "css", NAZO_LOGIN_SUBMIT_READY_SELECTOR, 30],
        ["click", "id", NAZO_LOGIN_SUBMIT_ID],
        ["wait", "contains", "/ui/consent", 30],
    ]
    if capture_placeholder:
        commands.insert(
            0,
            ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*", "update-image-placeholder-optional"],
        )
    return commands


def consent_approve_commands() -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_APPROVE_ID, 30],
        ["click", "id", NAZO_CONSENT_APPROVE_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", 10],
    ]


def consent_deny_commands() -> list[list[object]]:
    return [
        ["wait-element-visible", "id", NAZO_CONSENT_DENY_ID, 30],
        ["click", "id", NAZO_CONSENT_DENY_ID],
        ["wait", "contains", "/test/", 30],
        ["wait", "id", "submission_complete", 10],
    ]


def write_text(path: Path, body: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def server_rsa_private_key_is_usable(path: Path) -> bool:
    return (
        subprocess.run(
            ["openssl", "rsa", "-in", str(path), "-check", "-noout"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def live_server_key(
    keys: list[object],
    key_dir: Path,
    alg: str,
    now: str,
) -> dict[str, object] | None:
    live_key = None
    for key in keys:
        if not (
            isinstance(key, dict)
            and key.get("alg") == alg
            and isinstance(key.get("kid"), str)
            and isinstance(key.get("file"), str)
            and key_dir.joinpath(str(key["file"])).is_file()
            and key.get("retire_at") is None
        ):
            continue
        if server_rsa_private_key_is_usable(key_dir / str(key["file"])):
            live_key = key
            break
        key["retire_at"] = now
    return live_key


def create_server_key(
    keys: list[object],
    key_dir: Path,
    alg: str,
    kid_prefix: str,
    now: str,
) -> dict[str, object]:
    kid = kid_prefix
    file_name = f"{kid}.pem"
    existing_kids = {
        key.get("kid")
        for key in keys
        if isinstance(key, dict) and isinstance(key.get("kid"), str)
    }
    suffix = 2
    while kid in existing_kids:
        kid = f"{kid_prefix}-{suffix}"
        file_name = f"{kid}.pem"
        suffix += 1
    pem = key_dir / file_name
    subprocess.run(
        [
            "openssl",
            "genrsa",
            "-traditional",
            "-out",
            str(pem),
            "2048",
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pem.chmod(0o600)
    key = {
        "kid": kid,
        "alg": alg,
        "file": file_name,
        "created_at": now,
        "retire_at": None,
    }
    keys.append(key)
    return key


def ensure_server_oidf_keyset() -> None:
    key_dir = RUNTIME / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    keyset_path = key_dir / "keyset.json"
    keyset: dict[str, object] = {"active_kid": "", "keys": []}
    if keyset_path.is_file():
        loaded = json.loads(keyset_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise RuntimeError(f"server keyset must be a JSON object: {keyset_path}")
        keyset = loaded

    keys = keyset.setdefault("keys", [])
    if not isinstance(keys, list):
        raise RuntimeError(f"server keyset keys must be an array: {keyset_path}")

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    live_ps256 = live_server_key(keys, key_dir, "PS256", now)
    if live_ps256 is None:
        live_ps256 = create_server_key(
            keys, key_dir, "PS256", "ps256-local-oidf-server", now
        )
    live_rs256 = live_server_key(keys, key_dir, "RS256", now)
    if live_rs256 is None:
        live_rs256 = create_server_key(
            keys, key_dir, "RS256", "rs256-local-oidf-server", now
        )

    normalize_server_rsa_private_key(key_dir / str(live_ps256["file"]))
    normalize_server_rsa_private_key(key_dir / str(live_rs256["file"]))
    keyset["active_kid"] = live_ps256["kid"]
    write_text(keyset_path, json.dumps(keyset, indent=2) + "\n", 0o600)


def normalize_server_rsa_private_key(path: Path) -> None:
    tmp_path = path.with_name(f".{path.name}.traditional.tmp")
    subprocess.run(
        [
            "openssl",
            "rsa",
            "-in",
            str(path),
            "-traditional",
            "-out",
            str(tmp_path),
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
    path.chmod(0o600)


def ensure_cert() -> None:
    cert_dir = RUNTIME / "certs"
    cert = cert_dir / "oidf.crt"
    key = cert_dir / "oidf.key"
    if cert.is_file() and key.is_file():
        return
    cert_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=auth.nazo.run",
            "-addext",
            "subjectAltName=DNS:auth.nazo.run",
        ],
        check=True,
        cwd=ROOT,
    )
    key.chmod(0o600)


def ensure_mtls_ca() -> None:
    cert_dir = RUNTIME / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "mtls-ca.key"
    ca_cert = cert_dir / "mtls-ca.crt"
    if not ca_key.is_file() or not ca_cert.is_file():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-subj",
                "/CN=Nazo OAuth Local OIDF mTLS CA",
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ca_key.chmod(0o600)


def ensure_mtls_certs() -> None:
    ensure_mtls_ca()
    for name in ("mtls-client-1", "mtls-client-2"):
        ensure_mtls_client_cert(name)


def ensure_mtls_client_cert(name: str) -> None:
    ensure_mtls_ca()
    cert_dir = RUNTIME / "certs"
    ca_key = cert_dir / "mtls-ca.key"
    ca_cert = cert_dir / "mtls-ca.crt"
    key = cert_dir / f"{name}.key"
    csr = cert_dir / f"{name}.csr"
    cert = cert_dir / f"{name}.crt"
    if key.is_file() and cert.is_file():
        return
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={name}",
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "3650",
            "-out",
            str(cert),
        ],
        check=True,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    csr.unlink(missing_ok=True)


def mtls_config(index: int) -> dict[str, str]:
    return mtls_named_config(f"mtls-client-{index}")


def mtls_client_cert_name(client_id: str) -> str:
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:24]
    return f"mtls-{digest}"


def mtls_named_config(name: str) -> dict[str, str]:
    ensure_mtls_client_cert(name)
    cert_dir = RUNTIME / "certs"
    return {
        "cert": (cert_dir / f"{name}.crt").read_text(encoding="utf-8"),
        "key": (cert_dir / f"{name}.key").read_text(encoding="utf-8"),
        "ca": (cert_dir / "mtls-ca.crt").read_text(encoding="utf-8"),
    }


def write_env_yaml() -> None:
    write_text(
        ROOT / ".env.yaml",
        f"""BIND: "0.0.0.0:8000"
DATABASE_URL: "postgresql://postgres:postgres@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
ISSUER: "{ISSUER}"
CLIENT_SECRET_PEPPER: "{CLIENT_SECRET_PEPPER}"
ENABLE_REQUEST_OBJECT: true
ENABLE_PAR_REQUEST_OBJECT: true
ENABLE_DYNAMIC_CLIENT_REGISTRATION: true
ENABLE_CIBA: true
ENABLE_FRONTCHANNEL_LOGOUT: true
ENABLE_SESSION_MANAGEMENT: true
ENABLE_NATIVE_SSO: true
CIBA_AUTOMATED_DECISION_TOKEN: "{OIDF_CIBA_AUTOMATED_DECISION_TOKEN}"
DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN: "{DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN}"
MTLS_ENDPOINT_BASE_URL: "{MTLS_ISSUER}"
FRONTEND_BASE_URL: "{ISSUER}/ui"
CORS_ALLOWED_ORIGINS:
  - "{ISSUER}"
COOKIE_SECURE: true
DEFAULT_AUDIENCE: "resource://default"
EMAIL_DELIVERY: "disabled"
AVATAR_STORAGE_DIR: "/var/lib/nazo_oauth/avatars"
JWK_KEYS_DIR: "/var/lib/nazo_oauth/keys"
TRUSTED_PROXY_CIDRS: "{TRUSTED_PROXY_CIDRS}"
RATE_LIMIT_WINDOW_SECONDS: 60
AUTH_RATE_LIMIT_MAX_REQUESTS: 10000
TOKEN_RATE_LIMIT_MAX_REQUESTS: 10000
TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS: 10000
RUST_LOG: "info"
""",
        0o600,
    )


def write_nginx() -> None:
    write_text(
        RUNTIME / "nginx.conf",
        """events {}

http {
  server {
    listen 443 ssl;
    listen 9443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/certs/oidf.crt;
    ssl_certificate_key /etc/nginx/certs/oidf.key;
    ssl_client_certificate /etc/nginx/certs/mtls-ca.crt;
    ssl_verify_client optional;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    location /ui/ {
      root /usr/share/nginx/html;
      try_files $uri $uri/ /ui/index.html;
    }

    location / {
      proxy_pass http://nazo_oauth_server:8000;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port $server_port;
      proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
      proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
    }
  }

  server {
    listen 9444 ssl;
    server_name _;

    ssl_certificate /etc/nginx/certs/oidf.crt;
    ssl_certificate_key /etc/nginx/certs/oidf.key;
    ssl_client_certificate /etc/nginx/certs/mtls-ca.crt;
    ssl_verify_client optional;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    location / {
      proxy_pass http://nazo_oauth_server:8000;
      proxy_set_header Host auth.nazo.run;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host auth.nazo.run;
      proxy_set_header X-Forwarded-Port 9444;
      proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
      proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
    }
  }
}
""",
    )


def write_ui() -> None:
    if SKIP_UI_BUILD:
        target = RUNTIME / "ui"
        target.mkdir(parents=True, exist_ok=True)
        index = target / "index.html"
        if not index.exists():
            write_text(index, "<!doctype html><html><body>OIDF UI build skipped.</body></html>\n")
        return

    package_json = FRONTEND_ROOT / "package.json"
    if not package_json.is_file():
        raise RuntimeError(f"frontend project not found: {FRONTEND_ROOT}")

    env = os.environ.copy()
    env.update(
        {
            "VITE_BASE_PATH": "/ui/",
        }
    )
    subprocess.run(["npm", "run", "build"], cwd=FRONTEND_ROOT, env=env, check=True)

    dist = FRONTEND_ROOT / "dist"
    if not (dist / "index.html").is_file():
        raise RuntimeError(f"frontend build did not produce {dist / 'index.html'}")

    target = RUNTIME / "ui"
    target.mkdir(parents=True, exist_ok=True)
    for item in target.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    shutil.copytree(dist, target, dirs_exist_ok=True)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def openssl_hex_field(text: str, label: str) -> bytes:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{label}:":
            hex_lines: list[str] = []
            for candidate in lines[index + 1 :]:
                stripped = candidate.strip()
                if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2})*:?", stripped):
                    break
                hex_lines.append(stripped)
            if not hex_lines:
                break
            raw = bytes.fromhex("".join(line.replace(":", "") for line in hex_lines))
            return raw[1:] if len(raw) > 1 and raw[0] == 0 else raw
    else:
        raise RuntimeError(f"openssl rsa output is missing {label}")
    raise RuntimeError(f"openssl rsa output is missing {label}")


def openssl_public_exponent(text: str) -> bytes:
    match = re.search(r"publicExponent:\s+(\d+)", text)
    if match is None:
        raise RuntimeError("openssl rsa output is missing publicExponent")
    return int(match.group(1)).to_bytes(3, "big")


def generate_rsa_jwk(kid: str) -> dict[str, str]:
    key_dir = RUNTIME / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    pem = key_dir / f"{kid}.pem"
    if not pem.is_file():
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(pem),
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pem.chmod(0o600)
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(pem), "-text", "-noout"],
        check=True,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    text = result.stdout
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "PS256",
        "n": b64url(openssl_hex_field(text, "modulus")),
        "e": b64url(openssl_public_exponent(text)),
        "d": b64url(openssl_hex_field(text, "privateExponent")),
        "p": b64url(openssl_hex_field(text, "prime1")),
        "q": b64url(openssl_hex_field(text, "prime2")),
        "dp": b64url(openssl_hex_field(text, "exponent1")),
        "dq": b64url(openssl_hex_field(text, "exponent2")),
        "qi": b64url(openssl_hex_field(text, "coefficient")),
    }


def client_private_jwks(client_id: str) -> dict[str, object]:
    path = RUNTIME / "keys" / f"{client_id}-jwks.json"
    jwks = {"keys": [generate_rsa_jwk(f"{client_id}-ps256")]}
    write_text(path, json.dumps(jwks, indent=2) + "\n", 0o600)
    return jwks


def public_jwks(private_jwks: dict[str, object]) -> dict[str, object]:
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    keys = []
    for key in private_jwks.get("keys", []):
        if isinstance(key, dict):
            keys.append({name: value for name, value in key.items() if name not in private_fields})
    return {"keys": keys}


def callback_for(alias: str) -> str:
    return test_endpoint_for(alias, "callback")


def test_endpoint_for(alias: str, endpoint: str) -> str:
    return f"{SUITE_BASE_URL}/test/a/{alias}/{endpoint.lstrip('/')}"


def mark_login_page_wait_as_placeholder_update(task: object) -> None:
    if not isinstance(task, dict):
        return
    if task.get("match") == f"{ISSUER}/ui/auth*":
        task["commands"] = login_commands(capture_placeholder=True)
        return

    commands = task.get("commands")
    if not isinstance(commands, list):
        return

    for command in commands:
        if not isinstance(command, list) or len(command) < 5:
            continue
        if command[:5] != ["wait", "id", NAZO_LOGIN_EMAIL_ID, 30, ".*"]:
            continue
        if len(command) == 5:
            command.append("update-image-placeholder-optional")
        elif command[5] in {None, ""}:
            command[5] = "update-image-placeholder-optional"


def browser_automation_with_second_login_placeholder(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
            automation.append(copy.deepcopy(entry))
            continue

        first_authorization = copy.deepcopy(entry)
        first_authorization["match-limit"] = 1
        automation.append(first_authorization)

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        tasks = second_authorization.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                mark_login_page_wait_as_placeholder_update(task)
        automation.append(second_authorization)

    return automation


def first_login_observation_automation(browser: list[object]) -> list[object]:
    automation: list[object] = []
    for entry in browser:
        if not isinstance(entry, dict):
            automation.append(copy.deepcopy(entry))
            continue

        match = entry.get("match")
        if not (isinstance(match, str) and match == f"{ISSUER}/authorize*"):
            automation.append(copy.deepcopy(entry))
            continue

        automation.append(
            {
                "comment": (
                    "This module requires the first authorization endpoint visit to stop "
                    "at the login page without authenticating."
                ),
                "match": match,
                "match-limit": 1,
                "tasks": [
                    {
                        "task": "Observe first login page without authentication",
                        "match": f"{ISSUER}/ui/auth*",
                        "commands": [
                            [
                                "wait",
                                "id",
                                NAZO_LOGIN_EMAIL_ID,
                                30,
                                ".*",
                                "update-image-placeholder-optional",
                            ]
                        ],
                    }
                ],
            }
        )

        second_authorization = copy.deepcopy(entry)
        second_authorization.pop("match-limit", None)
        automation.append(second_authorization)

    return automation


def user_reject_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": (
                "Local Podman Nazo OAuth signs in after an explicit browser click, "
                "then lets this negative module deny consent before auto-approval."
            ),
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": login_commands(),
                },
                {
                    "task": "Deny consent page",
                    "match": f"{ISSUER}/ui/consent*",
                    "commands": consent_deny_commands(),
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [["wait", "id", "submission_complete", 10]],
                },
            ],
        }
    ]


def browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "Local Podman Nazo OAuth conformance browser automation.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error response",
                    "optional": True,
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "css",
                            "body",
                            10,
                            NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN,
                            "update-image-placeholder-optional",
                        ]
                    ],
                },
                {
                    "task": "Complete login page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/auth*",
                    "commands": login_commands(),
                },
                {
                    "task": "Complete consent page",
                    "optional": True,
                    "match": f"{ISSUER}/ui/consent*",
                    "commands": consent_approve_commands(),
                },
                {
                    "task": "Verify callback completion",
                    "match": "*/test/*/callback*",
                    "commands": [["wait", "id", "submission_complete", 10]],
                },
            ],
        },
        {
            "comment": "Local Podman Nazo OAuth post-logout redirect browser automation.",
            "match": f"{ISSUER}/logout*",
            "tasks": [
                {
                    "task": "Reach post-logout redirect page",
                    "match": "*/test/*/post_logout_redirect*",
                    "commands": [["wait", "contains", "/post_logout_redirect?state=", 10]],
                },
            ],
        },
        {
            "comment": "Local Podman OIDC Session Management first verification automation.",
            "match": "*/test/*/session_verify*",
            "tasks": [
                {
                    "task": "Wait for unchanged session management result",
                    "match": "*/test/*/session_verify*",
                    "commands": [["wait", "contains", "/session_result?state=unchanged", 30]],
                },
            ],
        },
        {
            "comment": "Local Podman OIDC Session Management second verification automation.",
            "match": "*/test/*/second_session_verify*",
            "tasks": [
                {
                    "task": "Wait for changed session management result",
                    "match": "*/test/*/second_session_verify*",
                    "commands": [["wait", "contains", "/second_session_result?state=changed", 30]],
                },
            ],
        },
    ]


def redirect_error_browser_automation() -> list[dict[str, object]]:
    return [
        {
            "comment": "Capture the local authorization error response for redirect_uri rejection.",
            "match": f"{ISSUER}/authorize*",
            "tasks": [
                {
                    "task": "Capture authorization error response",
                    "match": f"{ISSUER}/authorize*",
                    "commands": [
                        [
                            "wait",
                            "css",
                            "body",
                            10,
                            NAZO_AUTHORIZATION_ERROR_RESPONSE_PATTERN,
                            "update-image-placeholder-optional",
                        ]
                    ],
                }
            ],
        }
    ]


def fapi_overrides(browser: list[object], include_id2: bool) -> dict[str, object]:
    override: dict[str, object] = {
        module_name: {
            "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
        }
        for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
    }
    override[FAPI_SECURITY_FINAL_PAR_REUSE_BEFORE_AUTH] = {
        "browser": first_login_observation_automation(browser)
    }
    override[FAPI_SECURITY_FINAL_USER_REJECTS_AUTHENTICATION] = {
        "browser": user_reject_browser_automation()
    }
    if include_id2:
        override[FAPI_SECURITY_ID2_PAR_REUSE_BEFORE_AUTH] = {
            "browser": first_login_observation_automation(browser)
        }
        override[FAPI_SECURITY_ID2_USER_REJECTS_AUTHENTICATION] = {
            "browser": user_reject_browser_automation()
        }
    return override


def write_plan_config(name: str, config: dict[str, object]) -> None:
    write_text(RUNTIME / name, json.dumps(config, indent=2) + "\n", 0o600)


def oidf_server_config() -> dict[str, object]:
    return {
        "discoveryUrl": f"{ISSUER}/.well-known/openid-configuration",
        "allow_unexpected_metadata_fields": ["native_sso_supported"],
    }


def nazo_login_metadata() -> dict[str, str]:
    return {
        "oidf_user_email": USER_EMAIL,
        "oidf_user_password": USER_PASSWORD,
    }


def write_basic_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": BASIC_ALIAS,
        "description": "OIDC Basic OP: discovery and authorization-code interoperability.",
        "server": oidf_server_config(),
        "client": {
            "client_id": "local-oidf-basic-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client2": {
            "client_id": "local-oidf-basic-client-2",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "client_secret_post": {
            "client_id": "local-oidf-post-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email address phone offline_access",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
        "override": {
            module_name: {
                "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
            }
            for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
        },
    }
    for module_name in OIDCC_LOCAL_AUTHORIZATION_ERROR_MODULES:
        config["override"][module_name] = {
            "browser": redirect_error_browser_automation()
        }
    write_plan_config("oidf-oidcc-basic-plan-config.json", config)
    return config


def dynamic_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-dynamic",
        "description": "OIDC Basic OP: RFC 7591 dynamic client registration.",
        "server": oidf_server_config(),
        "client": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "client2": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "client_secret_post": {
            "initial_access_token": DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN,
            "scope": "openid profile email address phone offline_access",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
        "override": {
            module_name: {
                "browser": copy.deepcopy(browser_automation_with_second_login_placeholder(browser))
            }
            for module_name in OIDCC_SECOND_LOGIN_SCREENSHOT_MODULES
        },
    }
    for module_name in OIDCC_LOCAL_AUTHORIZATION_ERROR_MODULES:
        config["override"][module_name] = {
            "browser": redirect_error_browser_automation()
        }
    return config


def write_dynamic_plan_config() -> dict[str, object]:
    config = dynamic_plan_config()
    write_plan_config("oidf-oidcc-dynamic-plan-config.json", config)
    return config


def write_dynamic_crypto_plan_config() -> dict[str, object]:
    config = copy.deepcopy(dynamic_plan_config())
    config["alias"] = f"{BASIC_ALIAS}-dynamic-crypto"
    config["description"] = (
        "OIDC dynamic-registration signed UserInfo interoperability coverage."
    )
    write_plan_config("oidf-oidcc-dynamic-crypto-plan-config.json", config)
    return config


def fapi_client_config(client_id: str, private_jwks: dict[str, object], scope: str) -> dict[str, object]:
    return {
        "client_id": client_id,
        "jwks": private_jwks,
        "scope": scope,
        "dpop_signing_alg": "ES256",
    }


def fapi_scope(openid: str, fapi_profile: str) -> str:
    if fapi_profile == "fapi_client_credentials_grant":
        return "accounts"
    if openid == "openid_connect":
        return "openid profile email offline_access"
    return "accounts offline_access"


def display_value(value: str) -> str:
    return {
        "dpop": "DPoP",
        "fapi_client_credentials_grant": "client credentials",
        "jarm": "JARM",
        "message-final": "FAPI2 Message Signing Final",
        "mtls": "mTLS",
        "openid_connect": "OpenID Connect",
        "plain_fapi": "authorization code",
        "plain_oauth": "plain OAuth",
        "plain_response": "plain response",
        "private_key_jwt": "private_key_jwt",
        "security-final": "FAPI2 Security Profile Final",
        "signed_non_repudiation": "signed request object",
    }.get(value, value.replace("_", " "))


def fapi_plan_title(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    fapi_profile: str,
    fapi_response_mode: str,
) -> str:
    parts = [
        display_value(plan_kind),
        display_value(client_auth_type),
        display_value(sender_constrain),
        display_value(openid),
        display_value(fapi_profile),
    ]
    if plan_kind == "message-final":
        parts.append(display_value(fapi_response_mode))
    return " / ".join(parts)


def fapi_plan_description(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    fapi_profile: str,
    fapi_response_mode: str,
) -> str:
    flow = (
        "client credentials flow"
        if fapi_profile == "fapi_client_credentials_grant"
        else "authorization code flow"
    )
    mode = "OpenID Connect responses" if openid == "openid_connect" else "OAuth resource access"
    response_mode = "JARM" if fapi_response_mode == "jarm" else "plain"
    response = f" with {response_mode} authorization responses" if plan_kind == "message-final" else ""
    return (
        f"Covers {display_value(plan_kind)} for the {flow} using "
        f"{display_value(client_auth_type)} client authentication, "
        f"{display_value(sender_constrain)} sender constraint, and {mode}{response}."
    )


def fapi_plan_focus(plan_kind: str, fapi_profile: str, fapi_response_mode: str) -> list[str]:
    focus = [
        "discovery metadata",
        "PAR request_uri lifetime and replay handling",
        "authorization request parameter binding",
        "PKCE and redirect URI enforcement",
        "client assertion validation",
    ]
    if fapi_profile == "fapi_client_credentials_grant":
        focus.append("client credentials token issuance")
    else:
        focus.extend(["authorization code replay rejection", "refresh token behavior"])
    if plan_kind == "message-final":
        focus.extend(["signed request objects", "JAR"])
        if fapi_response_mode == "jarm":
            focus.append("JARM")
    return focus


def write_oidcc_config_plan_config() -> dict[str, object]:
    config = {
        "alias": "local-nazo-oauth-oidf-config",
        "description": "OIDC Config OP: provider metadata accuracy for the public issuer.",
        "server": oidf_server_config(),
    }
    write_plan_config("oidf-oidcc-config-plan-config.json", config)
    return config


def write_frontchannel_logout_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-frontchannel-logout",
        "description": "OIDC Front-Channel Logout OP: RP-initiated logout, frontchannel iframe notification, and post-logout redirect validation.",
        "server": oidf_server_config(),
        "client": {
            "client_id": "local-oidf-frontchannel-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
    }
    write_plan_config("oidf-oidcc-frontchannel-logout-plan-config.json", config)
    return config


def write_session_management_plan_config() -> dict[str, object]:
    browser = browser_automation()
    config = {
        "alias": f"{BASIC_ALIAS}-session-management",
        "description": "OIDC Session Management OP: check_session_iframe, session_state, and RP-initiated logout state transition validation.",
        "server": oidf_server_config(),
        "client": {
            "client_id": "local-oidf-session-client",
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email",
        },
        "nazo": nazo_login_metadata(),
        "browser": browser,
    }
    write_plan_config("oidf-oidcc-session-management-plan-config.json", config)
    return config


def fapi_client_ids(plan_slug: str) -> tuple[str, str]:
    return (
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-1",
        f"{FAPI_CLIENT_PREFIX}-{plan_slug}-client-2",
    )


def fapi_plan_config(
    alias: str,
    description: str,
    plan_slug: str,
    include_id2_overrides: bool,
    *,
    client_auth_type: str = "private_key_jwt",
    sender_constrain: str = "dpop",
    openid: str = "openid_connect",
    fapi_profile: str = "plain_fapi",
    fapi_response_mode: str = "plain_response",
    fapi_request_method: str | None = None,
) -> dict[str, object]:
    browser = browser_automation()
    client1_id, client2_id = fapi_client_ids(plan_slug)
    client1_jwks = client_private_jwks(client1_id)
    client2_jwks = client_private_jwks(client2_id)
    scope = fapi_scope(openid, fapi_profile)
    resource_base_url = MTLS_ISSUER if sender_constrain == "mtls" else ISSUER
    config: dict[str, object] = {
        "alias": alias,
        "description": description,
        "server": oidf_server_config(),
        "resource": {
            "resourceUrl": f"{resource_base_url}/fapi/resource",
            "resourceMethod": "GET",
            "resourceMediaType": "application/json",
            "resourceRequestBody": "",
        },
        "client": fapi_client_config(client1_id, client1_jwks, scope),
        "client2": fapi_client_config(client2_id, client2_jwks, scope),
        "mtls": mtls_named_config(mtls_client_cert_name(client1_id)),
        "mtls2": mtls_named_config(mtls_client_cert_name(client2_id)),
        "nazo": {
            **nazo_login_metadata(),
            "client_auth_type": client_auth_type,
            "sender_constrain": sender_constrain,
            "openid": openid,
            "fapi_profile": fapi_profile,
            "fapi_response_mode": fapi_response_mode,
        },
        "browser": browser,
        "override": fapi_overrides(browser, include_id2_overrides),
    }
    if fapi_request_method is not None:
        config["nazo"]["fapi_request_method"] = fapi_request_method
    return config


def fapi_matrix_plan_config(
    plan_kind: str,
    client_auth_type: str,
    sender_constrain: str,
    openid: str,
    *,
    fapi_profile: str = "plain_fapi",
    fapi_response_mode: str = "plain_response",
    fapi_request_method: str | None = None,
) -> tuple[str, dict[str, object]]:
    slug = "-".join(
        value.replace("_", "-")
        for value in [
            plan_kind,
            client_auth_type,
            sender_constrain,
            openid,
            fapi_profile,
            fapi_response_mode,
        ]
    )
    name = f"oidf-fapi-matrix-{slug}-plan-config.json"
    title = fapi_plan_title(
        plan_kind,
        client_auth_type,
        sender_constrain,
        openid,
        fapi_profile,
        fapi_response_mode,
    )
    description = fapi_plan_description(
        plan_kind,
        client_auth_type,
        sender_constrain,
        openid,
        fapi_profile,
        fapi_response_mode,
    )
    config = fapi_plan_config(
        f"local-nazo-oauth-oidf-{slug}",
        description,
        slug,
        False,
        client_auth_type=client_auth_type,
        sender_constrain=sender_constrain,
        openid=openid,
        fapi_profile=fapi_profile,
        fapi_response_mode=fapi_response_mode,
        fapi_request_method=fapi_request_method,
    )
    nazo = config["nazo"]
    assert isinstance(nazo, dict)
    nazo["matrix_title"] = title
    nazo["matrix_description"] = description
    nazo["matrix_focus"] = fapi_plan_focus(plan_kind, fapi_profile, fapi_response_mode)
    return name, config


def write_fapi_plan_configs() -> dict[str, dict[str, object]]:
    configs = {
        "oidf-fapi-security-final-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-security-final",
            "Local Podman Nazo OAuth FAPI2 Security Final conformance configuration",
            "security-final",
            False,
        ),
        "oidf-fapi-message-final-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-message-final",
            "Local Podman Nazo OAuth FAPI2 Message Signing Final conformance configuration",
            "message-final",
            False,
        ),
        "oidf-fapi-security-id2-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-security-id2",
            "Local Podman Nazo OAuth FAPI2 Security ID2 conformance configuration",
            "security-id2",
            True,
        ),
        "oidf-fapi-message-id1-plan-config.json": fapi_plan_config(
            "local-nazo-oauth-oidf-fapi-message-id1",
            "Local Podman Nazo OAuth FAPI2 Message Signing ID1 conformance configuration",
            "message-id1",
            True,
        ),
    }
    for name, config in configs.items():
        write_plan_config(name, config)
    return configs


def write_fapi_ciba_plan_config() -> dict[str, dict[str, object]]:
    slug = "fapi-ciba-plain-private-key-jwt-poll"
    client1_id, client2_id = fapi_client_ids(slug)
    client1_jwks = client_private_jwks(client1_id)
    client2_jwks = client_private_jwks(client2_id)
    config = {
        "alias": f"local-nazo-oauth-oidf-{slug}",
        "description": "FAPI-CIBA ID1 AS: plain FAPI profile with private_key_jwt client authentication and poll delivery mode.",
        "server": oidf_server_config(),
        "resource": {
            "resourceUrl": f"{ISSUER}/fapi/resource",
            "resourceMethod": "GET",
            "resourceMediaType": "application/json",
            "resourceRequestBody": "",
        },
        "automated_ciba_approval_url": (
            f"{ISSUER}/auth/ciba-automated-decision"
            f"?token={{auth_req_id}}&type={{action}}"
            f"&decision_token={OIDF_CIBA_AUTOMATED_DECISION_TOKEN}"
        ),
        "client": {
            **fapi_client_config(client1_id, client1_jwks, "openid profile email offline_access"),
            "hint_type": "login_hint",
            "hint_value": USER_EMAIL,
            "acr_value": "1",
        },
        "client2": {
            **fapi_client_config(
                client2_id,
                client2_jwks,
                "openid profile email offline_access",
            ),
            "acr_value": "1",
        },
        "mtls": mtls_named_config(mtls_client_cert_name(client1_id)),
        "mtls2": mtls_named_config(mtls_client_cert_name(client2_id)),
        "nazo": {
            **nazo_login_metadata(),
            "client_auth_type": "private_key_jwt",
            "sender_constrain": "mtls",
            "openid": "openid_connect",
            "fapi_profile": "plain_fapi",
            "fapi_ciba_profile": "plain_fapi",
            "ciba_mode": "poll",
            "matrix_title": "FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI",
            "matrix_description": "Covers FAPI-CIBA OP discovery, backchannel authentication, polling token exchange, negative CIBA request handling, refresh token behavior, and resource access.",
            "matrix_focus": [
                "CIBA discovery metadata",
                "backchannel authentication endpoint",
                "private_key_jwt client authentication",
                "poll mode token issuance",
                "FAPI-CIBA request-object and error handling",
            ],
        },
        "browser": browser_automation(),
    }
    name = "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json"
    write_plan_config(name, config)
    return {name: config}


def write_fapi_matrix_plan_configs() -> dict[str, dict[str, object]]:
    configs: dict[str, dict[str, object]] = {}
    for client_auth_type in FAPI_MATRIX_CLIENT_AUTHS:
        for sender_constrain in FAPI_MATRIX_SENDER_CONSTRAINS:
            for openid in FAPI_MATRIX_OPENID_MODES:
                name, config = fapi_matrix_plan_config(
                    "security-final",
                    client_auth_type,
                    sender_constrain,
                    openid,
                )
                configs[name] = config

    for response_mode in ("plain_response", "jarm"):
        name, config = fapi_matrix_plan_config(
            "message-final",
            "private_key_jwt",
            "dpop",
            "openid_connect",
            fapi_response_mode=response_mode,
            fapi_request_method="signed_non_repudiation",
        )
        configs[name] = config

    for client_auth_type in FAPI_MATRIX_CLIENT_AUTHS:
        for sender_constrain in FAPI_MATRIX_SENDER_CONSTRAINS:
            name, config = fapi_matrix_plan_config(
                "security-final",
                client_auth_type,
                sender_constrain,
                "plain_oauth",
                fapi_profile="fapi_client_credentials_grant",
            )
            configs[name] = config

    for name, config in configs.items():
        write_plan_config(name, config)
    return configs


def write_all_plan_configs() -> None:
    configs: dict[str, dict[str, object]] = {
        "oidf-oidcc-basic-plan-config.json": write_basic_plan_config(),
        "oidf-oidcc-dynamic-plan-config.json": write_dynamic_plan_config(),
        "oidf-oidcc-dynamic-crypto-plan-config.json": write_dynamic_crypto_plan_config(),
        "oidf-oidcc-config-plan-config.json": write_oidcc_config_plan_config(),
        "oidf-oidcc-frontchannel-logout-plan-config.json": write_frontchannel_logout_plan_config(),
        "oidf-oidcc-session-management-plan-config.json": write_session_management_plan_config(),
    }
    configs.update(write_fapi_plan_configs())
    configs.update(write_fapi_ciba_plan_config())
    configs.update(write_fapi_matrix_plan_configs())
    plan_set = plan_expressions_for_configs(configs)
    concurrent, frontchannel, session = partition_plan_expressions(plan_set)
    if len(frontchannel) != 1 or len(session) != 1:
        raise RuntimeError(
            "OIDF full matrix must contain exactly one front-channel and one session-management plan"
        )
    plan_manifest = plan_manifest_for_expressions(plan_set, configs)
    write_text(RUNTIME / "oidf-plan-configs.json", json.dumps({"configs": configs}, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "oidf-plan-set.json", json.dumps(plan_set, indent=2) + "\n", 0o600)
    write_text(
        RUNTIME / "oidf-plan-set-concurrent.json",
        json.dumps(concurrent, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-frontchannel.json",
        json.dumps(frontchannel, indent=2) + "\n",
        0o600,
    )
    write_text(
        RUNTIME / "oidf-plan-set-session.json",
        json.dumps(session, indent=2) + "\n",
        0o600,
    )
    write_text(RUNTIME / "oidf-plan-set-manifest.json", json.dumps(plan_manifest, indent=2) + "\n", 0o600)
    write_text(
        RUNTIME / "oidf-local.env",
        "\n".join(
            [
                f"OIDF_PLAN_CONFIG_JSON={json.dumps({'configs': configs})}",
                f"OIDF_PLAN_SET_JSON={json.dumps(plan_set)}",
                f"OIDF_PLAN_MANIFEST_JSON={json.dumps(plan_manifest)}",
                "",
            ]
        ),
        0o600,
    )
    callbacks = {
        name: callback_for(str(config["alias"]))
        for name, config in configs.items()
        if name != "oidf-oidcc-config-plan-config.json"
    }
    write_text(RUNTIME / "callbacks.json", json.dumps(callbacks, indent=2) + "\n", 0o600)
    write_text(RUNTIME / "callback.txt", callback_for(BASIC_ALIAS) + "\n")
    write_expected_skips()


def write_expected_skips() -> None:
    expected_skips = [
        {
            "test-name": "oidcc-idtoken-unsigned",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
        {
            "test-name": "oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
            "variant": "*",
            "configuration-filename": "oidf-oidcc-dynamic-plan-config.json",
        },
    ]
    write_text(
        RUNTIME / "oidf-expected-skips.json",
        json.dumps(expected_skips, indent=2) + "\n",
        0o600,
    )


def plan_expressions_for_configs(configs: dict[str, dict[str, object]]) -> list[str]:
    expressions = [
        "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] "
        "oidf-oidcc-basic-plan-config.json",
        "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] "
        "oidf-oidcc-dynamic-plan-config.json",
        "oidcc-dynamic-certification-test-plan[response_type=code]:"
        "oidcc-userinfo-rs256 "
        "oidf-oidcc-dynamic-crypto-plan-config.json",
        "oidcc-config-certification-test-plan oidf-oidcc-config-plan-config.json",
        "oidcc-frontchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-frontchannel-logout-plan-config.json",
        "oidcc-session-management-certification-test-plan[client_registration=static_client][response_type=code] "
        "oidf-oidcc-session-management-plan-config.json",
    ]
    for name, config in sorted(configs.items()):
        if name.startswith("oidf-fapi-ciba-"):
            expressions.append(
                "fapi-ciba-id1-test-plan"
                "[client_auth_type=private_key_jwt]"
                "[fapi_ciba_profile=plain_fapi]"
                "[ciba_mode=poll]"
                "[client_registration=static_client] "
                f"{name}"
            )
            continue
        if name.startswith("oidf-fapi-matrix-"):
            nazo = config.get("nazo")
            if not isinstance(nazo, dict):
                continue
            plan_kind = "fapi2-message-signing-final-test-plan" if "message-final" in name else "fapi2-security-profile-final-test-plan"
            variants = [
                f"client_auth_type={nazo['client_auth_type']}",
                f"fapi_profile={nazo['fapi_profile']}",
            ]
            if plan_kind == "fapi2-message-signing-final-test-plan":
                variants.append(f"fapi_request_method={nazo.get('fapi_request_method', 'signed_non_repudiation')}")
                variants.append(f"fapi_response_mode={nazo['fapi_response_mode']}")
            variants.append(f"sender_constrain={nazo['sender_constrain']}")
            variants.append(f"openid={nazo['openid']}")
            expressions.append(f"{plan_kind}[{']['.join(variants)}] {name}")
    return expressions


def partition_plan_expressions(
    expressions: list[str],
) -> tuple[list[str], list[str], list[str]]:
    frontchannel = [
        expression
        for expression in expressions
        if "frontchannel-rp-initiated-logout" in expression
    ]
    session = [
        expression
        for expression in expressions
        if "session-management-certification-test-plan" in expression
    ]
    browser_sensitive = set(frontchannel + session)
    concurrent = [
        expression for expression in expressions if expression not in browser_sensitive
    ]
    return concurrent, frontchannel, session


def plan_manifest_for_expressions(
    expressions: list[str], configs: dict[str, dict[str, object]]
) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    oidc_titles = {
        "oidf-oidcc-basic-plan-config.json": "OIDC Basic OP",
        "oidf-oidcc-dynamic-plan-config.json": "OIDC Basic OP Dynamic Registration",
        "oidf-oidcc-dynamic-crypto-plan-config.json": "OIDC Dynamic Registration: Signed UserInfo",
        "oidf-oidcc-config-plan-config.json": "OIDC Config OP",
        "oidf-oidcc-frontchannel-logout-plan-config.json": "OIDC Front-Channel Logout OP",
        "oidf-oidcc-session-management-plan-config.json": "OIDC Session Management OP",
    }
    oidc_focus = {
        "oidf-oidcc-basic-plan-config.json": [
            "discovery metadata",
            "authorization code flow",
            "static client registration",
            "userinfo and ID token interoperability",
        ],
        "oidf-oidcc-dynamic-plan-config.json": [
            "RFC 7591 dynamic client registration",
            "registration endpoint metadata",
            "authorization code flow",
            "userinfo and ID token interoperability",
        ],
        "oidf-oidcc-dynamic-crypto-plan-config.json": [
            "RFC 7591 dynamic client registration",
            "userinfo_signed_response_alg=RS256",
            "signed UserInfo content type and claims",
            "client response cryptography metadata",
        ],
        "oidf-oidcc-config-plan-config.json": [
            "provider metadata accuracy",
            "endpoint advertisement",
            "supported algorithms and response metadata",
        ],
        "oidf-oidcc-frontchannel-logout-plan-config.json": [
            "frontchannel_logout_supported metadata",
            "RP-initiated logout",
            "frontchannel logout iframe notification",
            "post_logout_redirect_uri validation",
        ],
        "oidf-oidcc-session-management-plan-config.json": [
            "check_session_iframe metadata",
            "session_state authorization response",
            "RP-initiated logout",
            "session state transition after logout",
        ],
    }
    for index, expression in enumerate(expressions, 1):
        config_name = expression.rsplit(" ", 1)[1]
        config = configs[config_name]
        nazo = config.get("nazo")
        title = oidc_titles.get(config_name)
        description = config.get("description")
        focus = oidc_focus.get(config_name, [])
        if isinstance(nazo, dict) and "matrix_title" in nazo:
            title = str(nazo["matrix_title"])
            description = str(nazo["matrix_description"])
            focus = list(nazo["matrix_focus"])
        plans.append(
            {
                "index": index,
                "title": title,
                "description": description,
                "expression": expression,
                "config": config_name,
                "coverage_focus": focus,
            }
        )
    return {
        "name": "NazoAuth OIDF full conformance matrix",
        "description": (
            "Twenty-one-plan OpenID Foundation regression matrix for the public issuer. "
            "Targeted TP/PS checks are mapped onto these plans instead of being run as a separate matrix."
        ),
        "plans": plans,
    }


def main() -> int:
    ensure_cert()
    ensure_mtls_certs()
    ensure_server_oidf_keyset()
    if WRITE_ENV_YAML:
        write_env_yaml()
    write_nginx()
    write_ui()
    write_all_plan_configs()
    print(f"Prepared local OIDF runtime files under {RUNTIME}")
    print(f"Issuer: {ISSUER}")
    print(f"Suite callback base: {SUITE_BASE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
