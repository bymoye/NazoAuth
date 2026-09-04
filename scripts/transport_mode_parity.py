#!/usr/bin/env python3
"""Black-box transport parity probes for a live NazoAuth deployment."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import ssl
import sys
import unittest
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request
from urllib.request import build_opener as open_url

SCHEMA = 1
MAX_BODY = 2 * 1024 * 1024
FORGED = ":Zm9yZ2VkLWNsaWVudC1jZXJ0:"
ALIAS_SUFFIXES = {
    "token_endpoint": "/token",
    "pushed_authorization_request_endpoint": "/par",
    "revocation_endpoint": "/revoke",
    "introspection_endpoint": "/introspect",
    "userinfo_endpoint": "/userinfo",
    "backchannel_authentication_endpoint": "/bc-authorize",
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
def base_url(value):
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain credentials, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base URL has an invalid port") from exc
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port and (parsed.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path.rstrip("/"), "", ""))
def origin(value):
    parsed = urlsplit(value)
    return f"{parsed.scheme}://{parsed.netloc}"
def canonical(value, replacements):
    if isinstance(value, dict):
        return {str(k): canonical(value[k], replacements) for k in sorted(value, key=str)}
    if isinstance(value, list):
        return [canonical(item, replacements) for item in value]
    if isinstance(value, str):
        for source, replacement in replacements:
            value = value.replace(source, replacement)
    return value
def cases(client_id):
    body = urlencode({"grant_type": "client_credentials", "client_id": client_id}).encode()
    return (
        ("health", "GET", "/health", None),
        ("oidc_discovery", "GET", "/.well-known/openid-configuration", None),
        ("oauth_as_metadata", "GET", "/.well-known/oauth-authorization-server", None),
        ("token_unauthenticated", "POST", "/token", body),
    )
def request(opener, target, case, url, timeout):
    name, method, path, body = case
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if target == "public_forged_client_cert":
        headers["Client-Cert"] = FORGED
    response, error = None, None
    try:
        response = opener.open(Request(url, data=body, headers=headers, method=method), timeout)
    except HTTPError as exc:
        response = exc
    except Exception as exc:  # network/TLS failures become JSON evidence
        error = f"{type(exc).__name__}: {exc}"
    raw, status, content_type = b"", None, None
    if response is not None:
        try:
            status = response.getcode()
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() or None
            raw = response.read(MAX_BODY + 1)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            response.close()
    truncated = len(raw) > MAX_BODY
    raw = raw[:MAX_BODY]
    payload = None
    if raw and not truncated:
        try:
            payload = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {
        "target": target, "case": name, "method": method, "path": path, "url": url,
        "status": status, "content_type": content_type, "json": payload,
        "json_valid": payload is not None, "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(), "truncated": truncated, "error": error,
    }
def context(ca, cert=None, key=None, insecure=False):
    if insecure:
        result = ssl.create_default_context()
        result.check_hostname = False
        result.verify_mode = ssl.CERT_NONE
    else:
        result = ssl.create_default_context(cafile=ca)
    if cert:
        result.load_cert_chain(cert, key)
    return result
def opener(ssl_context):
    return open_url(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl_context))
def replacements(public, mtls):
    return ((origin(public), "{public-origin}"), (origin(mtls), "{mtls-origin}"))
def alias_check(payload):
    issues = []
    if not isinstance(payload, dict):
        return [{"field": "body", "expected": "JSON object", "actual": type(payload).__name__}]
    if payload.get("tls_client_certificate_bound_access_tokens") is not True:
        issues.append({"field": "tls_client_certificate_bound_access_tokens", "expected": True, "actual": payload.get("tls_client_certificate_bound_access_tokens")})
    aliases = payload.get("mtls_endpoint_aliases")
    if not isinstance(aliases, dict) or not aliases:
        return issues + [{"field": "mtls_endpoint_aliases", "expected": "non-empty object", "actual": type(aliases).__name__}]
    for key, suffix in ALIAS_SUFFIXES.items():
        if key not in aliases:
            if key != "backchannel_authentication_endpoint":
                issues.append({"field": f"mtls_endpoint_aliases.{key}", "expected": "present", "actual": None})
            continue
        value = aliases[key]
        try:
            parsed = urlsplit(value)
            valid = parsed.scheme == "https" and bool(parsed.hostname) and not parsed.query and not parsed.fragment and parsed.path.endswith(suffix)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            issues.append({"field": f"mtls_endpoint_aliases.{key}", "expected": f"HTTPS URL ending in {suffix}", "actual": value})
    return issues


def semantic(item, replace):
    payload = item["json"]
    body = {"error": payload.get("error")} if item["case"] == "token_unauthenticated" and isinstance(payload, dict) else canonical(payload, replace)
    return {"status": item["status"], "content_type": item["content_type"], "body": body, "error": item["error"]}


def expected(item):
    result = []
    wanted = 401 if item["case"] == "token_unauthenticated" else 200
    if item["error"]:
        result.append({"field": "transport", "expected": "completed", "actual": item["error"]})
    if item["status"] != wanted:
        result.append({"field": "status", "expected": wanted, "actual": item["status"]})
    if item["content_type"] != "application/json":
        result.append({"field": "content_type", "expected": "application/json", "actual": item["content_type"]})
    payload = item["json"]
    if not isinstance(payload, dict):
        return result + [{"field": "body", "expected": "JSON object", "actual": type(payload).__name__}]
    if item["case"] == "health" and payload.get("status") != "ready":
        result.append({"field": "status_body", "expected": "ready", "actual": payload.get("status")})
    if item["case"] == "token_unauthenticated" and payload.get("error") != "invalid_client":
        result.append({"field": "error", "expected": "invalid_client", "actual": payload.get("error")})
    if item["case"] in {"oidc_discovery", "oauth_as_metadata"}:
        result.extend(alias_check(payload))
    return result


def report_observation(item, replace):
    result = {key: item[key] for key in ("target", "case", "method", "path", "url", "status", "content_type", "json_valid", "body_length", "body_sha256", "truncated", "error")}
    result["json"] = {"error": item["json"].get("error")} if item["case"] == "token_unauthenticated" and isinstance(item["json"], dict) else item["json"]
    result["semantic"] = semantic(item, replace)
    return result


def capture(args):
    public, mtls = base_url(args.public_base_url), base_url(args.mtls_base_url)
    if urlsplit(mtls).scheme != "https":
        raise ValueError("mTLS base URL must use https")
    client_id = args.token_client_id or f"transport-mode-parity-{uuid.uuid4().hex}"
    matrix, replace = cases(client_id), replacements(public, mtls)
    public_opener = opener(context(args.ca_file, insecure=args.insecure))
    mtls_opener = opener(context(args.ca_file, args.client_cert_file, args.client_key_file, args.insecure))
    items = []
    for target, base, client_opener in (("public", public, public_opener), ("public_forged_client_cert", public, public_opener), ("mtls", mtls, mtls_opener)):
        for case in matrix:
            items.append(request(client_opener, target, case, f"{base}/{case[2].lstrip('/')}", args.timeout))
    differences = []
    for item in items:
        differences.extend({"kind": "protocol", "target": item["target"], "case": item["case"], **issue} for issue in expected(item))
    by = {(item["target"], item["case"]): item for item in items}
    for case in matrix:
        for left, right, kind in (("public", "mtls", "public_vs_mtls"), ("public", "public_forged_client_cert", "forged_client_cert")):
            a, b = semantic(by[(left, case[0])], replace), semantic(by[(right, case[0])], replace)
            if a != b:
                differences.append({"kind": kind, "case": case[0], "left": left, "right": right, "left_semantic": a, "right_semantic": b})
    return {
        "schema": SCHEMA, "kind": "transport-mode-parity-capture", "success": not differences,
        "mode": args.mode, "matrix": [{"name": c[0], "method": c[1], "path": c[2]} for c in matrix],
        "observations": [report_observation(item, replace) for item in items], "differences": differences,
    }


def load(path):
    with Path(path).open(encoding="utf-8") as source:
        result = json.load(source)
    if not isinstance(result, dict) or result.get("schema") != SCHEMA or result.get("kind") != "transport-mode-parity-capture":
        raise ValueError(f"invalid capture snapshot: {path}")
    return result


def compare_snapshots(left_path, right_path):
    left, right = load(left_path), load(right_path)
    differences = []
    for side, snapshot in (("left", left), ("right", right)):
        if snapshot.get("success") is not True:
            differences.append({"side": side, "expected": "successful capture", "actual": snapshot.get("success")})
    if left.get("matrix") != right.get("matrix"):
        differences.append({"field": "matrix", "expected": left.get("matrix"), "actual": right.get("matrix")})
    def index(snapshot):
        return {(item["target"], item["case"]): item.get("semantic") for item in snapshot.get("observations", [])}
    left_items, right_items = index(left), index(right)
    for target in ("public", "public_forged_client_cert", "mtls"):
        for case in left.get("matrix", []):
            name = case["name"]
            a, b = left_items.get((target, name)), right_items.get((target, name))
            if a is None or b is None:
                differences.append({"target": target, "case": name, "expected": "present in both snapshots", "actual": {"left": a is not None, "right": b is not None}})
            elif a != b:
                differences.append({"target": target, "case": name, "left": a, "right": b})
    return {"schema": SCHEMA, "kind": "transport-mode-parity-compare", "success": not differences, "left": left_path, "right": right_path, "differences": differences}


class SelfTest(unittest.TestCase):
    def test_url_and_canonicalization(self):
        self.assertEqual(base_url("HTTPS://Example.test:443/"), "https://example.test")
        self.assertEqual(canonical({"issuer": "https://example.test/x"}, (("https://example.test", "{origin}"),)), {"issuer": "{origin}/x"})


def emit(result, output=None):
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv and argv[0] == "capture":
            parser = argparse.ArgumentParser(prog="transport_mode_parity.py capture")
            parser.add_argument("--mode", required=True)
            parser.add_argument("--public-base-url", required=True)
            parser.add_argument("--mtls-base-url", required=True)
            parser.add_argument("--ca-file")
            parser.add_argument("--client-cert-file", required=True)
            parser.add_argument("--client-key-file", required=True)
            parser.add_argument("--timeout", type=float, default=10.0)
            parser.add_argument("--token-client-id")
            parser.add_argument("--insecure", action="store_true")
            parser.add_argument("--output", required=True)
            args = parser.parse_args(argv[1:])
            result = capture(args)
            emit(result, args.output)
            return 0 if result["success"] else 1
        if argv and argv[0] == "compare":
            parser = argparse.ArgumentParser(prog="transport_mode_parity.py compare")
            parser.add_argument("left")
            parser.add_argument("right")
            parser.add_argument("--output")
            args = parser.parse_args(argv[1:])
            result = compare_snapshots(args.left, args.right)
            emit(result, args.output)
            return 0 if result["success"] else 1
        parser = argparse.ArgumentParser(prog="transport_mode_parity.py")
        parser.add_argument("--self-test", action="store_true")
        args = parser.parse_args(argv)
        if not args.self_test:
            parser.error("use capture, compare, or --self-test")
        tests = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest))
        result = {"schema": SCHEMA, "success": tests.wasSuccessful(), "self_test": {"tests_run": tests.testsRun, "failures": len(tests.failures), "errors": len(tests.errors)}}
        emit(result)
        return 0 if result["success"] else 1
    except Exception as exc:
        emit({"schema": SCHEMA, "success": False, "differences": [{"kind": "runtime", "error": f"{type(exc).__name__}: {exc}"}]})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
