from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
CHECKSUMS = ROOT / "tests" / "contracts" / "migrations.sha256"
ROUTES = ROOT / "tests" / "contracts" / "routes.json"
RFC9967_MATRIX = ROOT / "tests" / "contracts" / "rfc9967-scim-set-matrix.json"
RFC9967_RUNNER = ROOT / "scripts" / "rfc9967_scim_set_e2e.py"
SECURITY_NON_IMPLEMENTATION_POLICY = (
    ROOT / "docs" / "protocol" / "not-implemented-security-policy.md"
)
WORKSTATION_PATH = re.compile(r"(?i)\b[A-Z]:[\\/](?:self|projects)[\\/]")
REMOVED_ADAPTER_CLAIMS = (
    "Actix Web, Axum/Tower, and tonic adapters",
    "Actix Web、Axum/Tower、tonic adapter",
    "TowerResourceServerLayer",
    "authorize_tonic_request",
)
GLOB_REEXPORT = re.compile(r"(?m)^\s*pub(?:\([^)]*\))?\s+use\s+[^;]*::\*\s*;")
PRELUDE_MODULE = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+prelude\s*;")
EXACT_RUST_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
FORBIDDEN_CRATE_DEPENDENCIES = {
    "authorization-server-core": {
        "actix-web",
        "diesel",
        "diesel-async",
        "fred",
        "nazo-http-actix",
        "nazo-postgres",
        "nazo-valkey",
    },
    "identity": {
        "actix-web",
        "diesel",
        "diesel-async",
        "fred",
        "nazo-auth",
        "nazo-http-actix",
        "nazo-postgres",
        "nazo-valkey",
    },
    "resource-server": {
        "actix-web",
        "nazo-auth",
        "nazo-http-actix",
        "nazo-identity",
    },
    "http-actix": {"diesel", "diesel-async", "fred", "nazo-postgres", "nazo-valkey"},
}

RFC9967_CASES = {
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


def read_rust_module_tree(root_file: Path) -> str:
    """Read a Rust module facade and every source file in its child directory."""
    sources = [root_file]
    child_directory = root_file.with_suffix("")
    if child_directory.is_dir():
        sources.extend(sorted(child_directory.rglob("*.rs")))
    return "\n".join(source.read_text(encoding="utf-8") for source in sources)


def read_rust_source_family(directory: Path, prefix: str) -> str:
    """Read a facade plus private sibling modules sharing a capability prefix."""
    return "\n".join(
        source.read_text(encoding="utf-8")
        for source in sorted(directory.glob(f"{prefix}*.rs"))
    )


def migration_line(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"{digest}  {path.relative_to(ROOT).as_posix()}"


def migration_lines() -> list[str]:
    return [migration_line(path) for path in sorted(MIGRATIONS.glob("*/*.sql"))]


def write_migration_checksums() -> None:
    if CHECKSUMS.exists():
        raise SystemExit("checksum manifest already exists; use --append-migration")
    CHECKSUMS.write_text("\n".join(migration_lines()) + "\n", encoding="utf-8")


def check_migration_checksums() -> None:
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    actual = migration_lines()
    if actual != expected:
        raise SystemExit("migration history or manifest changed unexpectedly")


def append_migration(directory_name: str) -> None:
    directory = MIGRATIONS / directory_name
    paths = sorted(directory.glob("*.sql"))
    if [path.name for path in paths] != ["down.sql", "up.sql"]:
        raise SystemExit("new migration must contain exactly down.sql and up.sql")
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    recorded_paths = [line.split("  ", 1)[1] for line in expected]
    recorded_directories = [Path(path).parent.name for path in recorded_paths]
    if directory_name in recorded_directories or directory_name <= max(recorded_directories):
        raise SystemExit("migration append must use a new monotonically later directory")
    CHECKSUMS.write_text(
        "\n".join([*expected, *(migration_line(path) for path in paths)]) + "\n",
        encoding="utf-8",
    )


def check_route_fixture() -> None:
    payload = json.loads(ROUTES.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or not payload.get("routes"):
        raise SystemExit("route contract fixture is missing or invalid")
    paths = [item["path"] for item in payload["routes"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("route contract contains duplicate paths")
    for item in payload["routes"]:
        methods = item.get("methods")
        if not methods or methods != sorted(set(methods)):
            raise SystemExit("route methods must be non-empty, unique, and sorted")
        if item.get("condition") not in {"always", "perf_metrics"}:
            raise SystemExit("route condition is invalid")


def public_document_paths() -> list[Path]:
    paths = [ROOT / "README.md", ROOT / "README.zh-CN.md"]
    paths.extend((ROOT / "docs").rglob("*.md"))
    return paths


def check_documentation_boundaries() -> None:
    for path in public_document_paths():
        text = path.read_text(encoding="utf-8")
        if WORKSTATION_PATH.search(text):
            raise SystemExit(
                f"public documentation contains a workstation-specific path: "
                f"{path.relative_to(ROOT)}"
            )
        for obsolete in REMOVED_ADAPTER_CLAIMS:
            if obsolete in text:
                raise SystemExit(
                    f"public documentation advertises a removed adapter in "
                    f"{path.relative_to(ROOT)}: {obsolete}"
                )


def check_authorization_server_import_boundaries() -> None:
    for path in sorted((ROOT / "crates" / "authorization-server" / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if GLOB_REEXPORT.search(text):
            raise SystemExit(
                f"authorization-server source contains a glob re-export: {relative}"
            )
        if PRELUDE_MODULE.search(text):
            raise SystemExit(
                f"authorization-server source declares a prelude module: {relative}"
            )


def check_toolchain_pins() -> None:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    version = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(version, str) or not EXACT_RUST_VERSION.fullmatch(version):
        raise SystemExit("rust-toolchain.toml must pin an exact stable Rust version")

    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    rust_builder = re.search(
        r"FROM docker\.io/library/rust:(\d+\.\d+\.\d+)-slim"
        r"@sha256:[0-9a-f]{64} AS build-base",
        containerfile,
    )
    if rust_builder is None or rust_builder.group(1) != version:
        raise SystemExit("Containerfile Rust builder pin differs from rust-toolchain.toml")
    if f"ENV RUSTUP_TOOLCHAIN={version}" not in containerfile:
        raise SystemExit(
            "Containerfile must select the preinstalled Rust toolchain without network sync"
        )
    if not re.search(
        r"FROM docker\.io/library/debian:[^\s@]+@sha256:[0-9a-f]{64} AS runtime-base",
        containerfile,
    ):
        raise SystemExit("Containerfile runtime base image must be pinned by digest")
    if "cargo build --release --locked" not in containerfile:
        raise SystemExit("Containerfile release build must use Cargo.lock")
    if (
        "COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./"
        not in containerfile
    ):
        raise SystemExit("Containerfile builder must include the embedded initial config template")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    if ".env.*" not in dockerignore or "!.env.yaml.example" not in dockerignore:
        raise SystemExit(
            ".dockerignore must exclude local environment files but include the initial template"
        )

    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    rust_actions = []
    for path in workflows:
        rust_actions.extend(
            (path, match.group(1))
            for match in re.finditer(r"dtolnay/rust-toolchain@(\d+\.\d+\.\d+)", path.read_text())
        )
    if not rust_actions:
        raise SystemExit("CI has no exact dtolnay/rust-toolchain pin")
    mismatches = [path.relative_to(ROOT) for path, pin in rust_actions if pin != version]
    if mismatches:
        raise SystemExit(f"CI Rust toolchain pins differ from {version}: {mismatches}")

    renovate_candidates = [
        ROOT / "renovate.json",
        ROOT / "renovate.jsonc",
        ROOT / "renovate.json5",
        ROOT / ".github" / "renovate.json",
        ROOT / ".github" / "renovate.jsonc",
        ROOT / ".github" / "renovate.json5",
    ]
    present_renovate_configs = [path for path in renovate_candidates if path.exists()]
    if present_renovate_configs != [ROOT / "renovate.json"]:
        relative = [path.relative_to(ROOT) for path in present_renovate_configs]
        raise SystemExit(
            "Renovate must have one authoritative root renovate.json; "
            f"found: {relative}"
        )

    renovate = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
    enabled_managers = renovate.get("enabledManagers")
    if enabled_managers is not None:
        required_managers = {
            "cargo",
            "custom.regex",
            "docker-compose",
            "dockerfile",
            "github-actions",
            "pip_requirements",
        }
        missing_managers = required_managers - set(enabled_managers)
        if missing_managers:
            raise SystemExit(
                "Renovate enabledManagers disables required update coverage: "
                f"{sorted(missing_managers)}"
            )
    managers = renovate.get("customManagers")
    if not isinstance(managers, list) or not any(
        manager.get("datasourceTemplate") == "rust-version" for manager in managers
    ):
        raise SystemExit("Renovate must update the coordinated Rust stable pins")


def check_crate_dependency_boundaries() -> None:
    for crate, forbidden in FORBIDDEN_CRATE_DEPENDENCIES.items():
        manifest_path = ROOT / "crates" / crate / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        declared = set()
        for section in ("dependencies", "build-dependencies"):
            declared.update(manifest.get(section, {}))
        violations = sorted(declared & forbidden)
        if violations:
            raise SystemExit(
                f"{manifest_path.relative_to(ROOT)} violates dependency boundaries: {violations}"
            )


def check_workspace_package_metadata() -> None:
    workspace_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    for member in workspace_manifest["workspace"]["members"]:
        manifest_path = ROOT / member / "Cargo.toml"
        package = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        for field in ("version", "edition", "license", "repository"):
            if package.get(field) != {"workspace": True}:
                raise SystemExit(
                    f"{manifest_path.relative_to(ROOT)} must inherit package.{field} "
                    "from [workspace.package]"
                )


def check_rust_test_structure() -> None:
    inline_test_module = re.compile(
        r"(?m)^\s*#\[cfg\(test\)\]\s*"
        r"(?:#\[[^\]]+\]\s*)*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
    )
    test_attribute = re.compile(r"(?m)^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]")
    top_level_cfg = re.compile(r"(?m)^#\[cfg\(test\)\]$")
    top_level_hook = re.compile(
        r"(?m)^#\[cfg\(test\)\]\r?\n"
        r"(?:(?:#\[[^\r\n]+\]\r?\n)*)"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*;"
    )
    top_level_test_import = re.compile(
        r"(?:\r?\n#\[[^\r\n]+\])*\r?\n"
        r"\s*(?:pub(?:\([^)]*\))?\s+)?use\b"
    )
    nested_cfg = re.compile(
        r"(?m)^(?P<indent>[ \t]+)#\[cfg\(test\)\]\r?\n"
        r"(?P=indent)(?P<item>[^\r\n]+)"
    )
    allowed_nested_seams = {
        "crates/authorization-server/src/bootstrap/startup/configuration.rs": (
            "let valkey = nazo_valkey::test_support::connect(",
            "let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey);",
        ),
        "crates/authorization-server/src/bootstrap/startup/services/identity.rs": (
            "let session_profiles = web::Data::new(SessionProfileHandles::new(",
        ),
    }

    violations = []
    for crate in (ROOT / "crates").iterdir():
        source_root = crate / "src"
        if not source_root.is_dir():
            continue
        legacy_files = [
            *source_root.rglob("tests.rs"),
            *source_root.rglob("*_tests.rs"),
        ]
        if legacy_files:
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} keeps test files under src: "
                f"{[path.relative_to(ROOT).as_posix() for path in legacy_files]}"
            )

        for source_file in source_root.rglob("*.rs"):
            source = source_file.read_text(encoding="utf-8")
            relative = source_file.relative_to(ROOT).as_posix()
            if inline_test_module.search(source) or test_attribute.search(source):
                violations.append(f"{relative} embeds executable tests in production source")
            if "include!(" in source:
                violations.append(f"{relative} includes another source file")

            hook_matches = list(top_level_hook.finditer(source))
            for cfg_match in top_level_cfg.finditer(source):
                if not any(
                    hook.start() == cfg_match.start() for hook in hook_matches
                ) and top_level_test_import.match(source[cfg_match.end() :]) is None:
                    violations.append(f"{relative} has a non-mount top-level cfg(test) item")

            actual_nested = tuple(
                match.group("item").strip() for match in nested_cfg.finditer(source)
            )
            expected_nested = allowed_nested_seams.get(relative, ())
            if len(actual_nested) != len(expected_nested) or any(
                not actual.startswith(expected)
                for actual, expected in zip(actual_nested, expected_nested, strict=True)
            ):
                violations.append(
                    f"{relative} has unreviewed nested test seams: {actual_nested}"
                )

            for hook in hook_matches:
                hook_source = hook.group(0)
                path_match = re.search(r'#\[path\s*=\s*"([^"]+)"\]', hook_source)
                if path_match is None:
                    violations.append(f"{relative} has a test module without an explicit path")
                    continue
                target = (source_file.parent / path_match.group(1)).resolve()
                if not target.is_file():
                    violations.append(
                        f"{relative} mounts a missing test file: {path_match.group(1)}"
                    )

        seam_root = crate / "tests" / "support" / "seams"
        seam_files = list(seam_root.rglob("*.rs")) if seam_root.is_dir() else []
        if seam_files:
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} retains forbidden tests/support/seams: "
                f"{[path.relative_to(ROOT).as_posix() for path in seam_files]}"
            )
        if (crate / "tests" / "source_mounted").exists():
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} retains tests/source_mounted"
            )

        test_root = crate / "tests"
        if test_root.is_dir():
            for test_file in test_root.rglob("*.rs"):
                relative_parts = test_file.relative_to(test_root).parts
                if "src" in relative_parts or relative_parts.count("tests") > 0:
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} repeats production/test layout"
                    )
                source = test_file.read_text(encoding="utf-8")
                if "include!(" in source:
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} includes another source file"
                    )
                for literal in re.finditer(
                    r'#\[path\s*=\s*"([^"]+)"\]|include!\("([^"]+)"\)', source
                ):
                    raw_target = literal.group(1) or literal.group(2)
                    target = (test_file.parent / raw_target).resolve()
                    try:
                        target.relative_to(source_root.resolve())
                    except ValueError:
                        continue
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} recompiles production source "
                        f"through {raw_target}"
                    )

    if violations:
        raise SystemExit("Rust test structure violations:\n- " + "\n- ".join(violations))


def check_rfc9967_test_boundaries() -> None:
    production_sources = [
        *(ROOT / "crates" / "scim-events" / "src").rglob("*.rs"),
        ROOT / "crates" / "http-actix" / "src" / "scim.rs",
    ]
    forbidden_markers = ("#[cfg(test)]", "#[test]", "#[tokio::test]", "mod tests")
    for path in production_sources:
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden_markers if marker in source]
        if markers:
            raise SystemExit(
                f"{path.relative_to(ROOT)} embeds tests in production source: {markers}"
            )

    required_test_files = [
        ROOT / "crates" / "scim-events" / "tests" / "domain_contract.rs",
        ROOT / "crates" / "http-actix" / "tests" / "scim_transport.rs",
        ROOT / "tests" / "unit" / "test_rfc9967_scim_set_e2e_source_policy.py",
    ]
    missing = [path.relative_to(ROOT) for path in required_test_files if not path.is_file()]
    if missing:
        raise SystemExit(f"RFC 9967 separated test files are missing: {missing}")

    payload = json.loads(RFC9967_MATRIX.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    names = [case.get("name") for case in cases]
    if (
        payload.get("schema") != 1
        or payload.get("standard") != "RFC 9967"
        or set(names) != RFC9967_CASES
        or len(names) != len(RFC9967_CASES)
        or any(not case.get("handler") for case in cases)
    ):
        raise SystemExit("RFC 9967 black-box matrix must contain the exact required cases")

    runner = RFC9967_RUNNER.read_text(encoding="utf-8")
    forbidden_tables = ("scim_security_" + "events", "scim_security_event_" + "receipts")
    if any(table in runner for table in forbidden_tables):
        raise SystemExit("RFC 9967 black-box runner must not inspect event persistence tables")

    workflow = (ROOT / ".github" / "workflows" / "conformance-security.yml").read_text(
        encoding="utf-8"
    )
    required_workflow_fragments = (
        "ENABLE_SCIM_SECURITY_EVENTS: true",
        "python scripts/rfc9967_scim_set_e2e.py",
        "python tests/unit/test_rfc9967_scim_set_e2e_source_policy.py",
    )
    if any(fragment not in workflow for fragment in required_workflow_fragments):
        raise SystemExit("conformance-security workflow does not enforce the RFC 9967 matrix")


def check_removed_security_capabilities() -> None:
    active_files = [
        *(ROOT / "crates").glob("*/src/**/*.rs"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "scripts").glob("*.sh"),
        *(ROOT / "perf").glob("*.py"),
        *(ROOT / "perf").glob("*.yaml"),
        *(ROOT / ".github" / "workflows").glob("*.yml"),
    ]
    forbidden = (
        "ENABLE_REQUEST_URI_" + "PARAMETER",
        "ENABLE_LEGACY_AUDIENCE_" + "PARAM",
        "SCIM_BEARER_" + "TOKEN",
        "allow_authorization_code_" + "without_pkce",
        "enable_request_uri_" + "parameter",
        "enable_legacy_audience_" + "param",
        "RequestObject" + "Mode",
        "unsigned_request_object_" + "allowed",
    )
    violations = []
    for path in active_files:
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            violations.append((path.relative_to(ROOT).as_posix(), markers))
    if violations:
        raise SystemExit(f"removed security capabilities reappeared: {violations}")

    removed_test_harness = [
        ROOT / "crates" / "authorization-server" / "src" / "http" / "scim.rs",
        ROOT / "crates" / "authorization-server" / "src" / "http" / "scim",
    ]
    present = [path.relative_to(ROOT) for path in removed_test_harness if path.exists()]
    if present:
        raise SystemExit(f"SCIM test-only transport implementation reappeared: {present}")

    policy = SECURITY_NON_IMPLEMENTATION_POLICY.read_text(encoding="utf-8")
    required_policy_evidence = (
        "RFC 9700",
        "RFC 9101",
        "RFC 9126",
        "RFC 8707",
        "RFC 6750",
        "RFC 8314",
        "Never supported by security policy",
    )
    missing = [item for item in required_policy_evidence if item not in policy]
    if missing:
        raise SystemExit(f"security non-implementation policy lacks evidence: {missing}")


def check_fapi_ciba_boundaries() -> None:
    delivery = (
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "ciba_ping_delivery.rs"
    ).read_text(encoding="utf-8")
    forbidden_test_markers = ("#[cfg(test)]", "mod tests", "#[test]")
    if any(marker in delivery for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping delivery tests must remain outside production source")
    required_delivery_guards = (
        "apply_ciba_ping_tls_policy(reqwest::Client::builder().no_proxy())",
        "reqwest::redirect::Policy::none()",
        ".resolve_to_addrs(host, &addresses)",
        ".bearer_auth(&delivery.client_notification_token)",
        "is_blocked_ip(address.ip())",
        "classify_ciba_ping_status(response.status().as_u16())",
    )
    missing = [guard for guard in required_delivery_guards if guard not in delivery]
    if missing:
        raise SystemExit(f"CIBA ping delivery security guards are missing: {missing}")

    tls_policy = (
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "ciba_ping_tls.rs"
    ).read_text(encoding="utf-8")
    if any(marker in tls_policy for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    if (
        "CIBA_PING_TLS_MIN: reqwest::tls::Version = reqwest::tls::Version::TLS_1_2"
        not in tls_policy
        or ".tls_version_min(CIBA_PING_TLS_MIN)" not in tls_policy
    ):
        raise SystemExit("CIBA ping delivery must reject TLS versions below 1.2")
    if (
        "CIBA_PING_TLS_MAX: reqwest::tls::Version = reqwest::tls::Version::TLS_1_3"
        not in tls_policy
        or ".tls_version_max(CIBA_PING_TLS_MAX)" not in tls_policy
    ):
        raise SystemExit("CIBA ping delivery must offer TLS 1.3")
    if ".use_rustls_tls()" not in tls_policy:
        raise SystemExit("CIBA ping delivery must use the Rustls TLS backend")
    if 'std::env::var_os("CIBA_PING_TLS_TRUST_BUNDLE")' not in tls_policy:
        raise SystemExit("CIBA ping delivery must explicitly load its configured trust bundle")
    tls_policy_test = (
        ROOT
        / "crates"
        / "authorization-server"
        / "tests"
        / "unit"
        / "domain"
        / "ciba_ping_delivery.rs"
    )
    if not tls_policy_test.is_file():
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    tls_policy_test_source = tls_policy_test.read_text(encoding="utf-8")

    delivery_policy = (
        ROOT / "crates" / "authorization-server-core" / "src" / "ciba_ping.rs"
    ).read_text(encoding="utf-8")
    for required_test in (
        "ciba_ping_transport_policy_is_bounded_to_tls12_and_tls13",
        "ciba_ping_transport_supports_the_tls12_fapi_baseline",
        "ciba_ping_transport_supports_tls13",
    ):
        if required_test not in tls_policy_test_source:
            raise SystemExit(f"missing CIBA ping TLS policy test: {required_test}")
    if any(marker in delivery_policy for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping policy tests must remain outside production source")
    for guard in (
        'parsed.scheme() != "https"',
        "200..=299 => CibaPingResponseAction::Delivered",
        "300..=499 => CibaPingResponseAction::TerminalFailure",
        "_ => CibaPingResponseAction::Retry",
        "3 => 9",
        "next < expires_at",
    ):
        if guard not in delivery_policy:
            raise SystemExit(f"CIBA ping delivery policy guard is missing: {guard}")
    delivery_policy_test = (
        ROOT
        / "crates"
        / "authorization-server-core"
        / "tests"
        / "ciba_ping_delivery_policy.rs"
    )
    if not delivery_policy_test.is_file():
        raise SystemExit("CIBA ping delivery policy tests must remain outside production source")

    migration = (
        ROOT / "migrations" / "20260715000400_ciba_delivery_modes" / "up.sql"
    ).read_text(encoding="utf-8")
    for constraint in (
        "ck_oauth_clients_ciba_delivery_mode",
        "ck_oauth_clients_ciba_notification_endpoint",
        "ck_oauth_clients_ciba_user_code_disabled",
    ):
        if constraint not in migration:
            raise SystemExit(f"CIBA persistence constraint is missing: {constraint}")


def check_openid4vc_boundaries() -> None:
    production_roots = (
        ROOT / "crates" / "digital-credentials" / "src",
        ROOT / "crates" / "openid4vci" / "src",
        ROOT / "crates" / "openid4vp" / "src",
        ROOT / "crates" / "openid4vc-http-actix" / "src",
    )
    forbidden_test_markers = ("#[cfg(test)]", "#[test]", "#[tokio::test]", "mod tests")
    for production_root in production_roots:
        for source_file in production_root.rglob("*.rs"):
            source = source_file.read_text(encoding="utf-8")
            if any(marker in source for marker in forbidden_test_markers):
                raise SystemExit(
                    f"OpenID4VC tests must remain outside production source: {source_file}"
                )

    required_test_files = (
        ROOT / "crates" / "digital-credentials" / "tests" / "domain_contract.rs",
        ROOT / "crates" / "digital-credentials" / "tests" / "jwe_contract.rs",
        ROOT / "crates" / "openid4vci" / "tests" / "protocol_contract.rs",
        ROOT / "crates" / "openid4vci" / "tests" / "service_contract.rs",
        ROOT / "crates" / "openid4vp" / "tests" / "protocol_contract.rs",
        ROOT / "crates" / "openid4vp" / "tests" / "service_contract.rs",
        ROOT / "crates" / "openid4vc-http-actix" / "tests" / "transport_contract.rs",
        ROOT / "crates" / "openid4vc-http-actix" / "tests" / "transport_contract.rs",
    )
    missing_tests = [str(path.relative_to(ROOT)) for path in required_test_files if not path.is_file()]
    if missing_tests:
        raise SystemExit(f"OpenID4VC separated test contracts are missing: {missing_tests}")

    server_settings = read_rust_module_tree(
        ROOT / "crates" / "authorization-server" / "src" / "settings.rs"
    )
    server_config = (
        ROOT / "crates" / "authorization-server" / "src" / "config.rs"
    ).read_text(encoding="utf-8")
    server_routes = (
        ROOT / "crates" / "authorization-server" / "src" / "bootstrap" / "routes.rs"
    ).read_text(encoding="utf-8")
    dataset_admin = (
        ROOT / "crates" / "authorization-server" / "src" / "http" / "admin" / "openid4vc.rs"
    ).read_text(encoding="utf-8")
    openid4vc_protocol_adapter = (
        ROOT / "crates" / "openid4vc-http-actix" / "src" / "vci.rs"
    ).read_text(encoding="utf-8")
    openid4vc_server_domain = read_rust_module_tree(
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "openid4vc_endpoints.rs"
    )
    for forbidden in (
        "OPENID4VCI_CREDENTIAL_DATASET_MANAGEMENT_TOKEN",
        "/openid4vci/management/credential-datasets",
    ):
        if forbidden in server_settings or forbidden in server_routes:
            raise SystemExit(f"OpenID4VC dataset control plane exposes retired bearer surface: {forbidden}")
    for marker in (
        "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
        "OPENID4VC_KEY_ATTESTATION_JWKS_JSON",
        "client_attestation_jwks",
        "key_attestation_jwks",
        "public verification keys only",
    ):
        if marker not in server_settings:
            raise SystemExit(f"OpenID4VC purpose-scoped attestation trust boundary is missing: {marker}")
    if "OPENID4VC_ATTESTATION_JWKS_JSON" in server_settings or "OPENID4VC_ATTESTATION_JWKS_JSON" in server_config:
        raise SystemExit("OpenID4VC generic attestation trust store must not be reintroduced")
    for marker in (
        "require_admin_or_forbidden_with_handles",
        "has_valid_csrf_token_for_cookies",
        "admin.user_id().as_uuid()",
        "json_response_no_store",
    ):
        if marker not in dataset_admin:
            raise SystemExit(f"OpenID4VC dataset admin boundary is missing: {marker}")
    for forbidden in (
        "PutCredentialDatasetRequest",
        "CredentialDatasetResponse",
        "put_dataset",
        "delete_dataset",
    ):
        if forbidden in openid4vc_protocol_adapter:
            raise SystemExit(
                f"non-standard dataset administration polluted the OpenID4VC protocol adapter: {forbidden}"
            )
    for marker in (
        "CredentialDatasetAdminService",
        "#[serde(deny_unknown_fields)]",
        "validate_managed_dataset",
    ):
        if marker not in openid4vc_server_domain:
            raise SystemExit(f"OpenID4VC internal control-plane boundary is missing: {marker}")
    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    runtime_start = containerfile.index("FROM runtime-base AS runtime")
    runtime_body = containerfile[runtime_start:]
    if "conformance" in runtime_body.lower() or "oidf" in runtime_body.lower():
        raise SystemExit("production runtime image must not contain conformance provisioning")
    keyctl = (ROOT / "crates" / "authorization-server" / "src" / "keyctl.rs").read_text(
        encoding="utf-8"
    )
    key_store = "\n".join(
        (
            ROOT / "crates" / "key-management" / "src" / name
        ).read_text(encoding="utf-8")
        for name in ("store.rs", "serialization.rs", "lifecycle.rs")
    )
    for marker in (
        "generate-local",
        "LocalKeyRegistration",
    ):
        if marker not in keyctl:
            raise SystemExit(f"OpenID4VC purpose-scoped key CLI boundary is missing: {marker}")
    for marker in ('entry.get("purposes").is_some()', "key_entry_purposes"):
        if marker not in key_store:
            raise SystemExit(f"OpenID4VC purpose-scoped rotation boundary is missing: {marker}")
    migration = (
        ROOT / "migrations" / "20260716000100_openid4vc_final" / "up.sql"
    ).read_text(encoding="utf-8")
    for forbidden in ("verifier_attestation", "decentralized_identifier", "dc_api"):
        if forbidden in migration:
            raise SystemExit(f"unsupported OpenID4VP mechanism entered persistence: {forbidden}")
    dataset_migration = (
        ROOT / "migrations" / "20260718000100_openid4vci_credential_datasets" / "up.sql"
    ).read_text(encoding="utf-8")
    for marker in (
        "openid4vci_credential_dataset_events",
        "fk_openid4vci_dataset_subject_tenant",
        "fk_openid4vci_dataset_event_actor_tenant",
        "claims_ciphertext BYTEA",
        "ck_openid4vci_dataset_ciphertext",
        "source = 'admin-session'",
    ):
        if marker not in dataset_migration:
            raise SystemExit(f"OpenID4VC dataset persistence boundary is missing: {marker}")


def check_conformance_provisioning_boundaries() -> None:
    """Keep external Suite orchestration out of the server repository."""

    retired_assets = (
        ROOT / "compose.oidf.yml",
        ROOT / "deploy" / "oidf-suite",
        ROOT / "deploy" / "oidf-proxy",
        ROOT / "requirements" / "oidf-conformance.in",
        ROOT / "requirements" / "oidf-conformance.txt",
    )
    present = [
        str(path.relative_to(ROOT))
        for path in retired_assets
        if path.is_file() or (path.is_dir() and any(child.is_file() for child in path.rglob("*")))
    ]
    if present:
        raise SystemExit(f"external Suite assets remain in NazoAuth: {present}")

    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    runtime_start = containerfile.index("FROM runtime-base AS runtime")
    runtime_body = containerfile[runtime_start:].lower()
    if "oidf" in runtime_body or "conformance" in runtime_body:
        raise SystemExit("production runtime image must not contain Suite provisioning")


def check_bootstrap_secret_log_boundary() -> None:
    server = (
        ROOT
        / "crates"
        / "authorization-server"
        / "src"
        / "http"
        / "bootstrap_admin.rs"
    ).read_text(encoding="utf-8")
    routes = (
        ROOT
        / "crates"
        / "authorization-server"
        / "src"
        / "bootstrap"
        / "routes.rs"
    ).read_text(encoding="utf-8")
    repository = (
        ROOT
        / "crates"
        / "persistence-postgres"
        / "src"
        / "repositories"
        / "initial_admin_bootstrap.rs"
    ).read_text(encoding="utf-8")
    operations = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "docs" / "operations").glob("*.md")
    )

    for forbidden in (
        "initial_admin_setup_page",
        "text/html",
        "<!doctype html>",
        "web::{Data, Form",
        "web::{Data, Query",
    ):
        if forbidden in server or forbidden in routes:
            raise SystemExit(
                f"authorization server still embeds administrator setup UI: {forbidden}"
            )
    if 'route("/setup"' in routes:
        raise SystemExit("authorization server still exposes the legacy setup route")
    for source in (server, routes, operations):
        if "/setup?token=" in source or "setup URL" in source:
            raise SystemExit(
                "initial administrator bootstrap exposes a query-token URL"
            )
    if "use the operator workflow to read the private runtime-owned token file" not in server:
        raise SystemExit("initial administrator bootstrap lacks a non-secret recovery hint")
    for marker in (
        "request_id: String",
        ".claim(&payload.request_id, &token_hash, &email, password_hash)",
        '"request_id": request_id',
        "InitialAdminClaimOutcome::IdempotencyConflict",
    ):
        if marker not in server:
            raise SystemExit(f"idempotent bootstrap API boundary is missing: {marker}")
    created_start = server.index("nazo_postgres::InitialAdminClaimOutcome::Created")
    created_end = server.index("nazo_postgres::InitialAdminClaimOutcome::Closed", created_start)
    created_branch = server[created_start:created_end]
    if "endpoint.close()" in created_branch or "remove_consumed_token" in created_branch:
        raise SystemExit("server destroys bootstrap retry proof before ctl verifies the receipt")
    for marker in (
        "insert_initial_admin_created_event(",
        "InitialAdminClaimOutcome::IdempotencyConflict",
        "InitialAdminBootstrapState::Claimed",
    ):
        if marker not in repository:
            raise SystemExit(f"database-owned bootstrap receipt boundary is missing: {marker}")
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-migrations", action="store_true")
    parser.add_argument("--append-migration")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write_migrations:
        write_migration_checksums()
    if args.append_migration:
        append_migration(args.append_migration)
    if args.check:
        check_migration_checksums()
        check_route_fixture()
        check_documentation_boundaries()
        check_authorization_server_import_boundaries()
        check_toolchain_pins()
        check_crate_dependency_boundaries()
        check_workspace_package_metadata()
        check_rust_test_structure()
        check_rfc9967_test_boundaries()
        check_removed_security_capabilities()
        check_fapi_ciba_boundaries()
        check_openid4vc_boundaries()
        check_conformance_provisioning_boundaries()
        check_bootstrap_secret_log_boundary()


if __name__ == "__main__":
    main()
