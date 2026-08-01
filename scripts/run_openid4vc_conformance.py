#!/usr/bin/env python3
"""Drive issuer/verifier management APIs while the official OIDF runner executes.

The upstream OpenID4VC plans test an issuer or verifier, so they wait for the
implementation under test to initiate the flow. This wrapper is deliberately
small: it never reads protocol state from the database and can only observe the
OIDF API plus the public and management HTTP surfaces.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_oidf_conformance as oidf  # noqa: E402
import materialize_openid4vc_oidf_config as materializer  # noqa: E402
from oidf_evidence import sanitize_evidence_tree  # noqa: E402
from apply_public_conformance_onboarding import (  # noqa: E402
    ControlPlaneSession,
    OnboardingError,
)


PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
OIDF_TERMINAL_MODULE_STATUSES = {"FINISHED", "FAILED", "INTERRUPTED"}


def fail(message: str) -> None:
    raise SystemExit(message)


def install_credential_datasets(
    config: dict[str, object],
) -> tuple[ControlPlaneSession, list[tuple[str, str]]]:
    issuer = config.get("issuer")
    if not isinstance(issuer, dict) or issuer.get("dedicated_conformance_subject") is not True:
        raise RuntimeError(
            "OpenID4VC black-box runs require an explicitly dedicated conformance subject"
        )
    subject_id = issuer.get("subject_id")
    try:
        subject_id = str(uuid.UUID(str(subject_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise RuntimeError("issuer subject_id must be a UUID") from error
    datasets = issuer.get("credential_datasets")
    if not isinstance(datasets, dict) or not datasets:
        raise RuntimeError("issuer credential_datasets must be a non-empty object")
    if any(
        not isinstance(configuration_id, str)
        or not configuration_id
        or not isinstance(claims, dict)
        or not claims
        for configuration_id, claims in datasets.items()
    ):
        raise RuntimeError("issuer credential_datasets contains an invalid entry")
    origin = canonical_https_origin(str(config.get("target_origin", "")), label="target_origin")
    admin_email = os.environ.get("OIDF_ADMIN_EMAIL", "")
    admin_password = os.environ.get("OIDF_ADMIN_PASSWORD", "")
    if not admin_email or not admin_password:
        raise RuntimeError("OIDF_ADMIN_EMAIL and OIDF_ADMIN_PASSWORD are required")
    try:
        admin = ControlPlaneSession.login(origin, admin_email, admin_password)
        profile = admin.request_json("GET", "/auth/me", expected_status=200)
    except OnboardingError as error:
        raise RuntimeError(f"OpenID4VC admin control-plane login failed: {error}") from error
    if int(profile.get("admin_level", 0)) < 1:
        raise RuntimeError("OpenID4VC dataset operator is not an administrator")

    installed: list[tuple[str, str]] = []
    try:
        for configuration_id, claims in sorted(datasets.items()):
            encoded_configuration = urllib.parse.quote(configuration_id, safe="")
            path = (
                f"/admin/openid4vci/credential-datasets/{subject_id}/"
                f"{encoded_configuration}"
            )
            admin.request_json(
                "PUT",
                path,
                {"claims": claims},
                expected_status=200,
                csrf=True,
            )
            installed.append((subject_id, encoded_configuration))
    except OnboardingError as error:
        cleanup_credential_datasets(admin, installed)
        raise RuntimeError(f"OpenID4VC dataset installation failed: {error}") from error
    return admin, installed


def cleanup_credential_datasets(
    admin: ControlPlaneSession,
    installed: list[tuple[str, str]],
) -> None:
    failures: list[str] = []
    for subject_id, encoded_configuration in reversed(installed):
        path = (
            f"/admin/openid4vci/credential-datasets/{subject_id}/"
            f"{encoded_configuration}"
        )
        try:
            admin.request("DELETE", path, expected_status=204, csrf=True)
        except OnboardingError as error:
            failures.append(str(error))
    if failures:
        raise RuntimeError(
            "OpenID4VC dataset cleanup failed: " + "; ".join(failures)
        )


def request_json(method: str, url: str, token: str, payload: object | None = None) -> object:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError("management request URL must be HTTPS without credentials or fragment")
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(),
        NoRedirectHandler(),
    )
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        detail = error.read(64 * 1024).decode("utf-8", errors="replace")
        raise RuntimeError(f"management request failed with HTTP {error.code}: {detail}") from error
    with response:
        encoded = response.read(1024 * 1024 + 1)
        if len(encoded) > 1024 * 1024:
            raise RuntimeError("management response exceeds 1 MiB")
        if "application/json" not in response.headers.get("Content-Type", "").lower():
            raise RuntimeError("management response is not JSON")
    return json.loads(encoded) if encoded else {}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RuntimeError(f"unexpected redirect while delivering conformance input: {code} {newurl}")


class ExactRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, expected_url: str) -> None:
        super().__init__()
        self.expected_url = strict_https_url(expected_url, label="expected completion URL")

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        if code not in {302, 303} or strict_https_url(
            resolved, label="wallet redirect URL"
        ) != self.expected_url:
            raise RuntimeError(
                f"unexpected redirect while delivering conformance input: {code} {resolved}"
            )
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def strict_https_url(value: str, *, label: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError(f"{label} must be HTTPS without credentials or fragment")
    return urllib.parse.urlunsplit(parsed)


def get_url(url: str, *, expected_redirect_url: str | None = None) -> None:
    redirect_handler: urllib.request.BaseHandler = (
        NoRedirectHandler()
        if expected_redirect_url is None
        else ExactRedirectHandler(expected_redirect_url)
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=oidf.OIDF_API_SSL_CONTEXT),
        redirect_handler,
    )
    with opener.open(url, timeout=30) as response:
        response.read()


def canonical_https_origin(value: str, *, label: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{label} must be an HTTPS origin")
    port = parsed.port
    authority = parsed.hostname.lower() if port in {None, 443} else f"{parsed.hostname.lower()}:{port}"
    return f"https://{authority}"


def suite_callback_url(conformance_server: str, value: str) -> str:
    suite_origin = canonical_https_origin(conformance_server, label="conformance_server")
    parsed = urllib.parse.urlsplit(value)
    candidate_origin = canonical_https_origin(
        f"{parsed.scheme}://{parsed.netloc}", label="suite callback origin"
    )
    if (
        candidate_origin != suite_origin
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/test/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("suite callback must be a query-free /test/ URL on the configured public suite origin")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def module_entries(
    base_url: str,
    token: str | None,
    aliases: set[str],
    *,
    ignored_module_ids: set[str] | None = None,
    max_workers: int = 8,
) -> list[dict[str, object]]:
    ignored = ignored_module_ids or set()
    candidates: list[tuple[str, object]] = []
    for plan in oidf.fetch_alias_plans(base_url, token, aliases):
        plan_name = plan.get("planName")
        for module_id in sorted(oidf.module_ids_from_plan(plan)):
            if module_id not in ignored:
                candidates.append((module_id, plan_name))

    def fetch_entry(candidate: tuple[str, object]) -> dict[str, object] | None:
        module_id, plan_name = candidate
        status, info = oidf.oidf_api_request(
            "GET", base_url, f"api/info/{module_id}", token, expected_statuses={200, 404}
        )
        if status != 200 or not isinstance(info, dict):
            return None
        entry = {
            **info,
            "_driver_module_id": module_id,
            "_driver_plan": plan_name,
        }
        if str(info.get("status", "")).upper() != "WAITING":
            return entry
        runner_status, runner_info = oidf.oidf_api_request(
            "GET",
            base_url,
            f"api/runner/{module_id}",
            token,
            expected_statuses={200, 404},
        )
        exposed = (
            runner_info.get("exposed")
            if runner_status == 200 and isinstance(runner_info, dict)
            else None
        )
        return {**entry, **({"exposed": exposed} if isinstance(exposed, dict) else {})}

    if not candidates:
        return []
    workers = max(1, min(max_workers, len(candidates)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        return [
            entry
            for entry in executor.map(fetch_entry, candidates)
            if entry is not None
        ]


class Openid4vcDriver:
    def __init__(self, config: dict[str, object], stop: threading.Event) -> None:
        self.config = config
        self.stop = stop
        self.triggered: set[str] = set()
        self.terminal_modules: set[str] = set()

    def run(self) -> None:
        interval = max(1, int(self.config.get("poll_interval_seconds", 2)))
        while not self.stop.is_set():
            try:
                self.drive_once()
            except Exception as exc:  # runner monitor remains authoritative
                print(f"OpenID4VC driver retryable error: {type(exc).__name__}: {exc}", flush=True)
            if self.stop.wait(interval):
                break

    def drive_once(self) -> None:
        server = str(self.config["conformance_server"])
        configured_token = str(
            self.config.get("conformance_token") or os.environ.get("OIDF_CONFORMANCE_TOKEN", "")
        )
        if configured_token == "":
            raise RuntimeError("OIDF conformance API token is required")
        token = configured_token
        aliases = {str(value) for value in self.config["aliases"]}
        max_workers = int(self.config.get("driver_scan_workers", 8))
        start = time.monotonic()
        entries = module_entries(
            server,
            token,
            aliases,
            ignored_module_ids=self.triggered | self.terminal_modules,
            max_workers=max_workers,
        )
        triggered_before = len(self.triggered)
        for info in entries:
            module_id = str(info["_driver_module_id"])
            status = str(info.get("status", "")).upper()
            if status in OIDF_TERMINAL_MODULE_STATUSES:
                self.terminal_modules.add(module_id)
                continue
            if module_id in self.triggered or status != "WAITING":
                continue
            plan_name = str(info.get("_driver_plan", ""))
            variant = info.get("variant") if isinstance(info.get("variant"), dict) else {}
            if plan_name.startswith("oid4vci-"):
                if variant.get("vci_authorization_code_flow_variant") == "issuer_initiated":
                    self.drive_issuer(module_id, info, variant)
            elif plan_name.startswith("oid4vp-"):
                self.drive_verifier(module_id, info, variant, "haip" in plan_name)
        if entries:
            print(
                "OpenID4VC driver scan completed: "
                f"{len(entries)} live modules, "
                f"{len(self.terminal_modules)} cached terminal, "
                f"{len(self.triggered) - triggered_before} newly triggered, "
                f"{time.monotonic() - start:.2f}s",
                flush=True,
            )

    def drive_issuer(self, module_id: str, info: dict[str, object], variant: dict[str, object]) -> None:
        exposed = info.get("exposed")
        endpoint = exposed.get("credential_offer_endpoint") if isinstance(exposed, dict) else None
        if not isinstance(endpoint, str):
            return
        endpoint = suite_callback_url(str(self.config["conformance_server"]), endpoint)
        issuer = self.config["issuer"]
        format_name = str(variant.get("credential_format", "sd_jwt_vc"))
        configuration_ids = issuer["credential_configuration_ids"]
        configuration_id = str(configuration_ids[format_name])
        grant = str(variant.get("vci_grant_type", "authorization_code"))
        grant_type = PRE_AUTHORIZED_CODE_GRANT if grant == "pre_authorization_code" else "authorization_code"
        tx_code = issuer.get("tx_code") if grant == "pre_authorization_code" else None
        offer = request_json(
            "POST",
            urllib.parse.urljoin(
                str(self.config["target_origin"]), "/openid4vci/offers"
            ),
            str(issuer["management_token"]),
            {
                "subject_id": issuer["subject_id"],
                "credential_configuration_ids": [configuration_id],
                "grant_types": [grant_type],
                **({"tx_code": tx_code} if tx_code else {}),
                "expires_in": 300,
            },
        )
        if issuer.get("offer_delivery", "uri") == "value":
            value = json.dumps(offer["credential_offer"], separators=(",", ":"))
            callback = (
                f"{endpoint}?"
                f"{urllib.parse.urlencode({'credential_offer': value})}"
            )
        else:
            callback = (
                f"{endpoint}?"
                f"{urllib.parse.urlencode({'credential_offer_uri': offer['credential_offer_uri']})}"
            )
        get_url(callback)
        print(
            f"OpenID4VC driver delivered credential offer to {module_id}",
            flush=True,
        )
        self.triggered.add(module_id)

    def drive_verifier(self, module_id: str, info: dict[str, object], variant: dict[str, object], haip: bool) -> None:
        verifier = self.config["verifier"]
        alias = info.get("alias")
        if not isinstance(alias, str) or not alias:
            return
        format_name = str(variant.get("credential_format", "sd_jwt_vc"))
        dcql_format = "mso_mdoc" if format_name == "iso_mdl" else "dc+sd-jwt"
        credential_type_values = verifier.get("credential_type_values")
        if not isinstance(credential_type_values, dict):
            raise RuntimeError("verifier credential_type_values are required")
        credential_type = credential_type_values.get(format_name)
        if not isinstance(credential_type, str) or not credential_type:
            raise RuntimeError(f"verifier credential type is missing for {format_name}")
        credential_meta = (
            {"doctype_value": credential_type}
            if dcql_format == "mso_mdoc"
            else {"vct_values": [credential_type]}
        )
        prefix = str(variant.get("client_id_prefix", "x509_hash"))
        method = str(variant.get("request_method", "request_uri_signed"))
        test_name = str(info.get("testName", ""))
        request_method = (
            "url_query"
            if method == "url_query"
            else "request_uri_signed_post"
            if test_name == "oid4vp-1final-verifier-request-uri-method-post"
            else "request_uri_signed_get"
        )
        response_mode = str(variant.get("response_mode", "direct_post.jwt" if haip else "direct_post"))
        wallet_endpoint = urllib.parse.urljoin(
            str(self.config["conformance_server"]), f"/test/a/{alias}/authorize"
        )
        created = request_json(
            "POST",
            urllib.parse.urljoin(str(self.config["target_origin"]), "/openid4vp/presentations"),
            str(verifier["management_token"]),
            {
                "wallet_authorization_endpoint": wallet_endpoint,
                "dcql_query": {
                    "credentials": [
                        {
                            "id": "credential",
                            "format": dcql_format,
                            "meta": credential_meta,
                            "require_cryptographic_holder_binding": True,
                        }
                    ]
                },
                "haip": haip,
                "client_id_prefix": prefix,
                "request_method": request_method,
                "response_mode": response_mode,
            },
        )
        authorization_url = created.get("authorization_url") if isinstance(created, dict) else None
        if not isinstance(authorization_url, str):
            raise RuntimeError("verifier management response lacks authorization_url")
        transaction_id = created.get("transaction_id")
        try:
            transaction_id = str(uuid.UUID(str(transaction_id)))
        except (TypeError, ValueError, AttributeError) as error:
            raise RuntimeError("verifier management response lacks a valid transaction_id") from error
        completion_url = urllib.parse.urljoin(
            f"{str(self.config['target_origin']).rstrip('/')}/",
            f"openid4vp/complete/{transaction_id}",
        )
        get_url(authorization_url, expected_redirect_url=completion_url)
        self.triggered.add(module_id)
        print(f"OpenID4VC driver initiated presentation for {module_id}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver-config-json-file", required=True)
    parser.add_argument(
        "--plan-group-size",
        type=int,
        default=0,
        help=(
            "run the OpenID4VC plan set in bounded groups of this size; "
            "0 preserves the upstream runner's default parallel scheduling"
        ),
    )
    parser.add_argument(
        "--require-no-expected-problems",
        action="store_true",
        help=(
            "require the expected-problems file to be empty; intended for "
            "strict diagnostic runs against a patched conformance suite"
        ),
    )
    parser.add_argument("runner_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def option_value(arguments: list[str], option: str) -> str | None:
    try:
        index = arguments.index(option)
    except ValueError:
        return None
    if index + 1 >= len(arguments):
        fail(f"{option} requires a value")
    return arguments[index + 1]


def suite_plan_config_paths(arguments: list[str]) -> list[Path]:
    suite_dir = option_value(arguments, "--suite-dir")
    config_json_file = option_value(arguments, "--config-json-file")
    if not suite_dir or not config_json_file:
        raise RuntimeError(
            "OpenID4VC runner requires --suite-dir and --config-json-file"
        )
    document = json.loads(Path(config_json_file).read_text(encoding="utf-8"))
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict) or not configs:
        raise RuntimeError("OpenID4VC plan configs must contain a non-empty configs object")
    scripts = Path(suite_dir).resolve() / "scripts"
    paths: list[Path] = []
    for name in configs:
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"invalid OpenID4VC suite config file name: {name!r}")
        candidate = Path(name)
        if candidate.name != name or candidate.suffix != ".json":
            raise RuntimeError(f"invalid OpenID4VC suite config file name: {name!r}")
        paths.append(scripts / name)
    return paths


def cleanup_suite_plan_configs(paths: list[Path]) -> None:
    for path in paths:
        path.unlink(missing_ok=True)


def replace_option(arguments: list[str], option: str, value: str) -> list[str]:
    updated = list(arguments)
    try:
        index = updated.index(option)
    except ValueError:
        updated.extend([option, value])
        return updated
    if index + 1 >= len(updated):
        fail(f"{option} requires a value")
    updated[index + 1] = value
    return updated


def chunked(values: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        fail("--plan-group-size must be greater than zero when grouping is enabled")
    return [values[index : index + size] for index in range(0, len(values), size)]


def filter_records_for_configs(source: Path | None, selected_configs: set[str], target: Path) -> Path | None:
    if source is None:
        return None
    records = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        fail(f"{source} must contain a JSON array")
    filtered = [
        item
        for item in records
        if isinstance(item, dict)
        and str(item.get("configuration-filename", "")) in selected_configs
    ]
    target.write_text(json.dumps(filtered, indent=2) + "\n", encoding="utf-8")
    return target


def validate_materialized_matrix(
    driver_config: dict[str, object],
    runner_args: list[str],
    *,
    require_no_expected_problems: bool = False,
) -> None:
    required_options = {
        "--config-json-file": "plan configurations",
        "--plan-set-json-file": "plan set",
        "--expected-failures-file": "expected warnings",
        "--expected-skips-file": "expected skips",
    }
    paths: dict[str, Path] = {}
    for option, label in required_options.items():
        value = option_value(runner_args, option)
        if not value:
            fail(f"OpenID4VC public matrix requires {label} via {option}")
        paths[option] = Path(value)

    config_document = json.loads(paths["--config-json-file"].read_text(encoding="utf-8"))
    configs = config_document.get("configs") if isinstance(config_document, dict) else None
    if not isinstance(configs, dict):
        fail("OpenID4VC plan configurations must contain a configs object")

    cases = materializer.matrix_cases()
    expected_config_names = [f"openid4vc-{slug}.json" for _, slug, _ in cases]
    if len(configs) != len(expected_config_names) or set(configs) != set(expected_config_names):
        fail("OpenID4VC plan configurations do not match the current matrix registry")

    plans = json.loads(paths["--plan-set-json-file"].read_text(encoding="utf-8"))
    expected_plans = [
        materializer.plan_expression(plan, variants, filename)
        for (plan, _, variants), filename in zip(cases, expected_config_names, strict=True)
    ]
    if plans != expected_plans:
        fail("OpenID4VC plan set does not match the current matrix registry")

    aliases = [
        config.get("alias") if isinstance(config, dict) else None
        for config in configs.values()
    ]
    if any(not isinstance(alias, str) or not alias for alias in aliases) or len(set(aliases)) != len(
        aliases
    ):
        fail("OpenID4VC plan configurations require unique non-empty aliases")
    driver_aliases = driver_config.get("aliases")
    if (
        not isinstance(driver_aliases, list)
        or any(not isinstance(alias, str) or not alias for alias in driver_aliases)
        or len(driver_aliases) != len(set(driver_aliases))
        or set(driver_aliases) != set(aliases)
    ):
        fail("OpenID4VC driver aliases do not match the materialized plan configurations")

    issuer = driver_config.get("issuer")
    tx_code = issuer.get("tx_code") if isinstance(issuer, dict) else None
    if not isinstance(tx_code, str) or not tx_code:
        fail("OpenID4VC driver requires a non-empty issuer transaction code")
    for (_, _, variants), filename in zip(cases, expected_config_names, strict=True):
        config = configs[filename]
        if not isinstance(config, dict):
            fail(f"OpenID4VC plan configuration {filename} must be an object")
        vci = config.get("vci")
        static_tx_code = vci.get("static_tx_code") if isinstance(vci, dict) else None
        if variants.get("vci_grant_type") == "pre_authorization_code":
            if static_tx_code != tx_code:
                fail(
                    "OpenID4VC pre-authorized plan transaction codes do not match "
                    "the driver material"
                )
        elif static_tx_code is not None:
            fail(
                f"OpenID4VC non-pre-authorized plan {filename} must not contain a transaction code"
            )

    warnings = json.loads(paths["--expected-failures-file"].read_text(encoding="utf-8"))
    if require_no_expected_problems and warnings != []:
        fail("OpenID4VC strict diagnostic runs require an empty expected-problems file")
    if (
        not require_no_expected_problems
        and warnings != materializer.expected_problems_for_cases(cases)
    ):
        fail("OpenID4VC expected problems do not match the current matrix registry")
    skips = json.loads(paths["--expected-skips-file"].read_text(encoding="utf-8"))
    if skips != materializer.expected_skips_for_cases(cases):
        fail("OpenID4VC expected skips do not match the current matrix registry")


def grouped_runner_args(runner_args: list[str], group_size: int, temp_dir: Path) -> list[list[str]]:
    plan_set_file = option_value(runner_args, "--plan-set-json-file")
    config_json_file = option_value(runner_args, "--config-json-file")
    if not plan_set_file:
        fail("--plan-group-size requires --plan-set-json-file")
    if not config_json_file:
        fail("--plan-group-size requires --config-json-file")

    plans = json.loads(Path(plan_set_file).read_text(encoding="utf-8"))
    if not isinstance(plans, list) or not all(isinstance(item, str) and item.strip() for item in plans):
        fail(f"{plan_set_file} must contain a JSON array of plan expression strings")
    config_payload = json.loads(Path(config_json_file).read_text(encoding="utf-8"))
    configs = config_payload.get("configs") if isinstance(config_payload, dict) else None
    if not isinstance(configs, dict):
        fail(f"{config_json_file} must contain a configs object")
    config_names = {str(name) for name in configs}

    expected_failures = option_value(runner_args, "--expected-failures-file")
    expected_skips = option_value(runner_args, "--expected-skips-file")
    export_dir = option_value(runner_args, "--export-dir")

    invocations: list[list[str]] = []
    for index, group in enumerate(chunked([item.strip() for item in plans], group_size), start=1):
        selected_configs = oidf.config_names_from_plan_expressions(group, config_names)
        if not selected_configs:
            fail(f"OpenID4VC plan group {index} does not reference a known config")
        group_dir = temp_dir / f"group-{index:02d}"
        group_dir.mkdir(parents=True, exist_ok=True)
        group_plan_set = group_dir / "openid4vc-plan-set.json"
        group_plan_set.write_text(json.dumps(group, indent=2) + "\n", encoding="utf-8")
        group_args = replace_option(runner_args, "--plan-set-json-file", str(group_plan_set))
        if expected_failures:
            filtered = filter_records_for_configs(
                Path(expected_failures),
                selected_configs,
                group_dir / "openid4vc-expected-problems.json",
            )
            group_args = replace_option(group_args, "--expected-failures-file", str(filtered))
        if expected_skips:
            filtered = filter_records_for_configs(
                Path(expected_skips),
                selected_configs,
                group_dir / "openid4vc-expected-skips.json",
            )
            group_args = replace_option(group_args, "--expected-skips-file", str(filtered))
        if export_dir:
            group_args = replace_option(group_args, "--export-dir", str(Path(export_dir) / f"group-{index:02d}"))
        invocations.append(group_args)
    return invocations


def terminate_runner_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        try:
            killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=20)
            return
        except subprocess.TimeoutExpired:
            killpg(process.pid, signal.SIGKILL)
            process.wait()
            return
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_runner_invocations(invocations: list[list[str]]) -> int:
    for index, runner_args in enumerate(invocations, start=1):
        print(f"OpenID4VC official runner group {index}/{len(invocations)}", flush=True)
        command = [sys.executable, str(Path(__file__).with_name("run_oidf_conformance.py")), *runner_args]
        process = subprocess.Popen(command, start_new_session=True)
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def interrupt_runner(_signum, _frame) -> None:  # noqa: ANN001
            raise InterruptedError("OpenID4VC wrapper received SIGTERM")

        signal.signal(signal.SIGTERM, interrupt_runner)
        try:
            try:
                returncode = process.wait()
            except BaseException:
                terminate_runner_process(process)
                raise
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
        if returncode != 0:
            return returncode
    return 0


def main() -> int:
    args = parse_args()
    runner_args = args.runner_args[1:] if args.runner_args[:1] == ["--"] else args.runner_args
    if not runner_args:
        fail("arguments for run_oidf_conformance.py are required after --")
    if args.plan_group_size < 0:
        fail("--plan-group-size must be zero or greater")
    config = json.loads(Path(args.driver_config_json_file).read_text(encoding="utf-8"))
    if "--no-api-token" in runner_args or "--disable-ssl-verify" in runner_args:
        fail("public black-box OpenID4VC runs require API authentication and TLS verification")
    validate_materialized_matrix(
        config,
        runner_args,
        require_no_expected_problems=args.require_no_expected_problems,
    )
    plan_config_paths = suite_plan_config_paths(runner_args)
    existing_plan_configs = [path for path in plan_config_paths if path.exists()]
    if existing_plan_configs:
        raise RuntimeError(
            "OpenID4VC suite contains stale generated plan configs: "
            + ", ".join(path.name for path in existing_plan_configs)
        )
    admin, installed_datasets = install_credential_datasets(config)
    stop = threading.Event()
    driver = Openid4vcDriver(config, stop)
    thread = threading.Thread(target=driver.run, name="openid4vc-oidf-driver", daemon=True)
    thread.start()
    export_dir = option_value(runner_args, "--export-dir")
    try:
        if args.plan_group_size:
            with tempfile.TemporaryDirectory(prefix="openid4vc-oidf-groups-") as directory:
                invocations = grouped_runner_args(runner_args, args.plan_group_size, Path(directory))
                return run_runner_invocations(invocations)
        return run_runner_invocations([runner_args])
    finally:
        stop.set()
        thread.join(timeout=5)
        try:
            cleanup_credential_datasets(admin, installed_datasets)
        finally:
            try:
                cleanup_suite_plan_configs(plan_config_paths)
            finally:
                if export_dir:
                    sanitize_evidence_tree(Path(export_dir))


if __name__ == "__main__":
    raise SystemExit(main())
