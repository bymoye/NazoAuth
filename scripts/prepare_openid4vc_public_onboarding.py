#!/usr/bin/env python3
"""Prepare OpenID4VC wallet applications for public control-plane onboarding.

This tool translates already materialized OIDF wallet configuration into the
same client application document used by ordinary production operators.  It
does not call the product, read a database, install trust, or mint credentials.
Private JWK members are removed before an application document is written.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import urllib.parse


PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth"}
PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


def fail(message: str) -> None:
    raise SystemExit(message)


def public_https_origin(value: str, *, label: str) -> str:
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
        fail(f"{label} must be an HTTPS origin")
    hostname = parsed.hostname.lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if (
            hostname == "localhost"
            or hostname.endswith(".local")
            or "." not in hostname
        ):
            fail(f"{label} must use a public DNS hostname")
    else:
        fail(f"{label} must use a public DNS hostname, not a raw IP address")
    authority = hostname if parsed.port in {None, 443} else f"{hostname}:{parsed.port}"
    return f"https://{authority}"


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def public_jwks(value: object, *, source: str) -> dict[str, object]:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        fail(f"{source} must contain a jwks.keys array")
    keys: list[dict[str, object]] = []
    for index, candidate in enumerate(value["keys"]):
        if not isinstance(candidate, dict):
            fail(f"{source}.keys[{index}] must be an object")
        key = {
            name: item
            for name, item in candidate.items()
            if name not in PRIVATE_JWK_MEMBERS
        }
        if not isinstance(key.get("kty"), str):
            fail(f"{source}.keys[{index}] has no key type")
        keys.append(key)
    if not keys:
        fail(f"{source} must contain at least one key")
    return {"keys": keys}


def callback_url(suite_origin: str, alias: str) -> str:
    if not alias or any(character in alias for character in "/?#"):
        fail("OpenID4VC configuration contains an invalid alias")
    return f"{suite_origin}/test/a/{alias}/callback"


def base_client_request(
    *,
    name: str,
    auth_method: str,
    redirect_uris: list[str],
    scopes: list[str],
    audiences: list[str],
    jwks: dict[str, object],
) -> dict[str, object]:
    return {
        "client_name": name,
        "client_type": "confidential",
        "redirect_uris": sorted(set(redirect_uris)),
        "post_logout_redirect_uris": [],
        "scopes": sorted(set(scopes)),
        "allowed_audiences": sorted(set(audiences)),
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": auth_method,
        "require_dpop_bound_tokens": True,
        "require_mtls_bound_tokens": False,
        "allow_client_assertion_audience_array": False,
        "allow_client_assertion_endpoint_audience": auth_method == "private_key_jwt",
        # HAIP 1.0 requires client-authenticated PAR for issuance, but it does
        # not apply the separate FAPI 2.0 Message Signing profile. Requiring a
        # JAR Request Object here would conflate those two profiles and reject
        # conforming HAIP authorization requests.
        "require_par_request_object": False,
        "backchannel_token_delivery_mode": "poll",
        "backchannel_user_code_parameter": False,
        "backchannel_logout_session_required": False,
        "frontchannel_logout_session_required": False,
        "jwks": jwks,
    }


def prepare_clients(
    configs: dict[str, object],
    *,
    target_origin: str,
    suite_origin: str,
) -> list[dict[str, object]]:
    clients: dict[str, dict[str, object]] = {}
    for filename, raw_config in sorted(configs.items()):
        if not filename.startswith("openid4vc-vci-"):
            continue
        if not isinstance(raw_config, dict):
            fail(f"{filename} must be an object")
        alias = raw_config.get("alias")
        vci = raw_config.get("vci")
        nazo = raw_config.get("nazo")
        if not isinstance(alias, str) or not isinstance(vci, dict) or not isinstance(nazo, dict):
            fail(f"{filename} lacks its alias, vci, or nazo policy object")
        configuration_id = vci.get("credential_configuration_id")
        auth_type = nazo.get("client_auth_type")
        if not isinstance(configuration_id, str) or not configuration_id:
            fail(f"{filename} has no credential_configuration_id")
        auth_method = {
            "private_key_jwt": "private_key_jwt",
            "client_attestation": "attest_jwt_client_auth",
        }.get(auth_type)
        if auth_method is None:
            fail(f"{filename} uses an unsupported wallet authentication policy")
        for field in ("client", "client2"):
            metadata = raw_config.get(field)
            if not isinstance(metadata, dict):
                fail(f"{filename}.{field} must be an object")
            logical_id = metadata.get("client_id")
            if not isinstance(logical_id, str) or not logical_id:
                fail(f"{filename}.{field}.client_id is required")
            candidate_jwks = public_jwks(
                metadata.get("jwks"), source=f"{filename}.{field}.jwks"
            )
            entry = clients.setdefault(
                logical_id,
                {
                    "auth_method": auth_method,
                    "jwks": candidate_jwks,
                    "redirect_uris": set(),
                    "scopes": set(),
                },
            )
            if entry["auth_method"] != auth_method or entry["jwks"] != candidate_jwks:
                fail(f"conflicting wallet policy for {logical_id}")
            callback = callback_url(suite_origin, alias)
            entry["redirect_uris"].add(callback)
            if field == "client2":
                # The second wallet exercises an independently registered URI
                # whose query component is significant. Register both exact
                # values through the normal client-approval flow; the
                # authorization server must not relax redirect URI matching.
                entry["redirect_uris"].add(f"{callback}?dummy1=lorem&dummy2=ipsum")
            entry["scopes"].add(configuration_id)
            configured_scopes = str(metadata.get("scope", "")).split()
            if "offline_access" in configured_scopes:
                entry["scopes"].add("offline_access")

    if len(clients) != 4:
        fail(f"OpenID4VC onboarding requires exactly four wallet clients, found {len(clients)}")
    audiences = [
        "resource://default",
        target_origin,
        f"{target_origin}/openid4vci/credential",
    ]
    result: list[dict[str, object]] = []
    for logical_id, policy in sorted(clients.items()):
        digest = hashlib.sha256(logical_id.encode("utf-8")).hexdigest()[:16]
        result.append(
            {
                "logical_client_id": logical_id,
                "request": base_client_request(
                    name=f"OpenID4VC wallet {digest}",
                    auth_method=str(policy["auth_method"]),
                    redirect_uris=sorted(policy["redirect_uris"]),
                    scopes=sorted(policy["scopes"]),
                    audiences=audiences,
                    jwks=policy["jwks"],
                ),
                "mtls_trust_anchor_pem": None,
            }
        )
    return result


def plan_manifest(expressions: list[str], configs: dict[str, object]) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    for index, expression in enumerate(expressions, start=1):
        config_name = expression.rsplit(" ", 1)[-1]
        config = configs.get(config_name)
        if not isinstance(config, dict):
            fail(f"plan expression references unknown configuration {config_name}")
        plans.append(
            {
                "index": index,
                "title": str(config.get("description", config_name)),
                "expression": expression,
                "config": config_name,
            }
        )
    return {
        "name": "OpenID4VC Final and HAIP public black-box matrix",
        "description": f"{len(plans)}-plan public issuer and verifier regression matrix.",
        "plans": plans,
    }


def prepare_onboarding_bundle(
    *,
    plan_configs: Path,
    plan_set: Path,
    target_issuer: str,
    suite_base_url: str,
    applicant_email: str,
    output_dir: Path,
) -> None:
    """Write the private, public-control-plane onboarding inputs.

    Keeping this operation callable separates secret transport from the
    deterministic client-policy construction.  CLI callers may obtain the
    applicant address from their own safe source; callers must not need to
    reimplement the four-wallet aggregation logic.
    """
    output = output_dir
    target_origin = public_https_origin(target_issuer, label="target_issuer")
    suite_origin = public_https_origin(suite_base_url, label="suite_base_url")
    if target_origin == suite_origin:
        fail("the target issuer and conformance suite must use different origins")
    normalized_email = applicant_email.strip()
    if "@" not in normalized_email or any(character.isspace() for character in normalized_email):
        fail("applicant_email must be a non-empty email address")

    plan_document = read_json(plan_configs)
    configs = plan_document.get("configs") if isinstance(plan_document, dict) else None
    expressions = read_json(plan_set)
    if not isinstance(configs, dict):
        fail("plan_configs must contain a configs object")
    if not isinstance(expressions, list) or not all(
        isinstance(expression, str) and expression.strip() for expression in expressions
    ):
        fail("plan_set must contain a non-empty array of plan expressions")

    write_private_json(
        output / "oidf-onboarding-manifest.json",
        {
            "schema": 1,
            "target_issuer": target_origin,
            "suite_base_url": suite_origin,
            "applicant_email": normalized_email,
            "clients": prepare_clients(
                configs,
                target_origin=target_origin,
                suite_origin=suite_origin,
            ),
        },
    )
    write_private_json(
        output / "openid4vc-plan-set-manifest.json",
        plan_manifest(expressions, configs),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-configs", type=Path, required=True)
    parser.add_argument("--plan-set", type=Path, required=True)
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--suite-base-url", required=True)
    parser.add_argument("--applicant-email", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    prepare_onboarding_bundle(
        plan_configs=args.plan_configs,
        plan_set=args.plan_set,
        target_issuer=args.target_issuer,
        suite_base_url=args.suite_base_url,
        applicant_email=args.applicant_email,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
