#!/usr/bin/env python3
"""Materialize the bounded OpenID4VC Final/HAIP OIDF regression matrix."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import uuid


VCI_STANDARD = "oid4vci-1_0-issuer-test-plan"
VCI_HAIP = "oid4vci-1_0-issuer-haip-test-plan"
VP_STANDARD = "oid4vp-1final-verifier-test-plan"
VP_HAIP = "oid4vp-1final-verifier-haip-test-plan"
OIDF_VP_SD_JWT_VCT = "urn:eudi:pid:1"
OFFICIAL_VCI_PRIVATE_KEY_CLIENT_ID = "nazo-openid4vc-oidf-private-key-jwt"
OFFICIAL_VCI_ATTESTED_CLIENT_ID = "nazo-openid4vc-oidf-client-attestation"
VCI_UNSUPPORTED_ENCRYPTION_MODULE = "oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm"
VCI_MULTIPLE_CLIENTS_MODULE = "oid4vci-1_0-issuer-happy-flow-multiple-clients"
VCI_PREAUTHORIZED_APPLICABLE_MODULES = (
    "oid4vci-1_0-issuer-metadata-test",
    "oid4vci-1_0-issuer-metadata-test-signed",
    "oid4vci-1_0-issuer-happy-flow",
    "oid4vci-1_0-issuer-happy-flow-additional-requests",
    "oid4vci-1_0-issuer-happy-flow-skip-notification",
    "oid4vci-1_0-issuer-batch-issuance",
    "oid4vci-1_0-issuer-fail-invalid-nonce",
    "oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature",
    "oid4vci-1_0-issuer-fail-invalid-key-attestation-signature",
    "oid4vci-1_0-issuer-fail-missing-proof",
    VCI_UNSUPPORTED_ENCRYPTION_MODULE,
    "oid4vci-1_0-issuer-fail-unknown-credential-configuration",
    "oid4vci-1_0-issuer-fail-unknown-credential-identifier",
    "oid4vci-1_0-issuer-fail-on-access-token-in-query",
)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = -3
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def apply_official_mtls_material(
    base: dict[str, object], material: object
) -> None:
    if not isinstance(material, dict) or set(material) != {"ca", "mtls", "mtls2"}:
        raise SystemExit(
            "official OpenID4VC mTLS material must contain exactly ca, mtls, and mtls2"
        )
    ca = material.get("ca")
    if not isinstance(ca, str) or "-----BEGIN CERTIFICATE-----" not in ca:
        raise SystemExit("official OpenID4VC mTLS material requires a PEM CA certificate")
    identities: dict[str, dict[str, str]] = {}
    for name in ("mtls", "mtls2"):
        identity = material.get(name)
        if not isinstance(identity, dict) or set(identity) != {"cert", "key"}:
            raise SystemExit(
                f"official OpenID4VC {name} material must contain exactly cert and key"
            )
        cert = identity.get("cert")
        key = identity.get("key")
        if not isinstance(cert, str) or "-----BEGIN CERTIFICATE-----" not in cert:
            raise SystemExit(f"official OpenID4VC {name} requires a PEM certificate")
        if not isinstance(key, str) or "PRIVATE KEY-----" not in key:
            raise SystemExit(f"official OpenID4VC {name} requires a PEM private key")
        identities[name] = {"ca": ca, "cert": cert, "key": key}
    for section in ("vci", "vci_haip"):
        target = base.get(section)
        if not isinstance(target, dict):
            raise SystemExit(f"base configuration requires a {section} object")
        for name, identity in identities.items():
            target[name] = copy.deepcopy(identity)


def vci_client_ids(onboarding_profile: str, run_namespace: str | None) -> dict[str, str]:
    if onboarding_profile == "operator-black-box":
        namespace = (run_namespace or "").strip().lower()
        if (
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", namespace)
            or namespace in {"official", "oidf", "production"}
        ):
            raise SystemExit(
                "operator-black-box OpenID4VC material requires a valid client namespace"
            )
        prefix = f"oidf-{namespace}-openid4vc"
        private_key = f"{prefix}-private-key-jwt"
        attested = f"{prefix}-client-attestation"
    elif onboarding_profile == "official":
        if run_namespace:
            raise SystemExit("official OpenID4VC material must not declare an operator namespace")
        private_key = OFFICIAL_VCI_PRIVATE_KEY_CLIENT_ID
        attested = OFFICIAL_VCI_ATTESTED_CLIENT_ID
    else:
        raise SystemExit(f"unsupported OpenID4VC onboarding profile: {onboarding_profile}")
    return {
        "private_key": private_key,
        "attested": attested,
        "private_key2": f"{private_key}-2",
        "attested2": f"{attested}-2",
    }


def plan_alias(prefix: str, slug: str, run_namespace: str | None) -> str:
    """Keep official aliases stable and isolate every operator run."""
    return "-".join(
        part for part in (prefix, run_namespace, slug) if isinstance(part, str) and part
    )


def bind_subject_id(
    issuer_settings: dict[str, object],
    onboarding_profile: str,
    subject_id: str | None,
) -> None:
    if subject_id:
        try:
            issuer_settings["subject_id"] = str(uuid.UUID(subject_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise SystemExit("--subject-id must be a UUID") from error
    elif onboarding_profile == "operator-black-box":
        raise SystemExit(
            "operator-black-box OpenID4VC material requires --subject-id "
            "for the current dedicated conformance user"
        )


def matrix_cases() -> list[tuple[str, str, dict[str, str]]]:
    return [
        (VCI_STANDARD, "vci-sd-wallet-plain", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-mdoc-wallet-encrypted", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"mdoc","vci_credential_encryption":"encrypted"}),
        (VCI_STANDARD, "vci-sd-issuer-encrypted", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"encrypted"}),
        (VCI_STANDARD, "vci-mdoc-issuer-plain", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-sd-preauth", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"pre_authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-mdoc-preauth", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"pre_authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc","vci_credential_encryption":"encrypted"}),
        (VCI_HAIP, "vci-haip-sd-wallet", {"vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"sd_jwt_vc"}),
        (VCI_HAIP, "vci-haip-mdoc-wallet", {"vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"mdoc"}),
        (VCI_HAIP, "vci-haip-sd-issuer", {"vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc"}),
        (VCI_HAIP, "vci-haip-mdoc-issuer", {"vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc"}),
        (VP_STANDARD, "vp-sd-redirect-query", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"redirect_uri","request_method":"url_query","response_mode":"direct_post"}),
        (VP_STANDARD, "vp-sd-x509dns-signed", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"x509_san_dns","request_method":"request_uri_signed","response_mode":"direct_post"}),
        (VP_STANDARD, "vp-mdoc-x509dns-signed-jwt", {"vp_profile":"plain_vp","credential_format":"iso_mdl","client_id_prefix":"x509_san_dns","request_method":"request_uri_signed","response_mode":"direct_post.jwt"}),
        (VP_STANDARD, "vp-sd-x509hash-signed-jwt", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"x509_hash","request_method":"request_uri_signed","response_mode":"direct_post.jwt"}),
        (VP_STANDARD, "vp-mdoc-x509hash-signed", {"vp_profile":"plain_vp","credential_format":"iso_mdl","client_id_prefix":"x509_hash","request_method":"request_uri_signed","response_mode":"direct_post"}),
        (VP_HAIP, "vp-haip-sd", {"credential_format":"sd_jwt_vc","response_mode":"direct_post.jwt"}),
        (VP_HAIP, "vp-haip-mdoc", {"credential_format":"iso_mdl","response_mode":"direct_post.jwt"}),
    ]


def plan_expression(plan: str, variants: dict[str, str], filename: str) -> str:
    expression = plan + "".join(
        f"[{name}={value}]" for name, value in variants.items()
    )
    if plan == VCI_STANDARD and variants.get("vci_grant_type") == "pre_authorization_code":
        # The pinned official multiple-client module starts its second client
        # without requesting another Credential Offer. Select every applicable
        # module explicitly so it cannot reuse a single-use pre-authorized code.
        expression += ":" + ",".join(VCI_PREAUTHORIZED_APPLICABLE_MODULES)
    return f"{expression} {filename}"


def expected_skips_for_cases(cases: list[tuple[str, str, dict[str, str]]]) -> list[dict[str, object]]:
    unsupported_encryption = [
        {
            "test-name": VCI_UNSUPPORTED_ENCRYPTION_MODULE,
            "variant": "*",
            "configuration-filename": f"openid4vc-{slug}.json",
        }
        for plan, slug, variants in cases
        if plan == VCI_STANDARD and variants.get("vci_credential_encryption") == "plain"
    ]
    return unsupported_encryption


def full_vci_variant(plan: str, variants: dict[str, str]) -> dict[str, str]:
    if plan != VCI_HAIP:
        return dict(variants)
    expanded = {
        "sender_constrain": "dpop",
        "client_auth_type": "client_attestation",
        "authorization_request_type": "simple",
        "openid": "plain_oauth",
        "fapi_request_method": "unsigned",
        "vci_grant_type": "authorization_code",
        "vci_credential_encryption": "plain",
        "fapi_profile": "vci_haip",
        "fapi_response_mode": "plain_response",
    }
    expanded.update(variants)
    return expanded


def expected_problems_for_cases(cases: list[tuple[str, str, dict[str, str]]]) -> list[dict[str, object]]:
    return []


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def b64url_uint(value: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).decode("ascii").rstrip("=")


def p256_add(
    p: tuple[int, int] | None,
    q: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p == q:
        slope = ((3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)) % P256_P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, P256_P)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def p256_multiply(scalar: int, point: tuple[int, int] = P256_G) -> tuple[int, int]:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = p256_add(result, addend)
        addend = p256_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise SystemExit("derived P-256 public key is the point at infinity")
    return result


def derive_client2_ec_p256_key(key: dict[str, object], *, source: str) -> dict[str, object]:
    d_value = key.get("d")
    if not isinstance(d_value, str) or not d_value:
        raise SystemExit(f"{source} requires a private EC P-256 JWK")
    d_bytes = b64url_decode(d_value)
    d_int = int.from_bytes(d_bytes, "big")
    if not 0 < d_int < P256_N:
        raise SystemExit(f"{source} contains an invalid P-256 private scalar")
    kid = key.get("kid")
    kid_bytes = kid.encode("utf-8") if isinstance(kid, str) else b""
    seed = hashlib.sha256(b"nazo-openid4vc-client2-ec-p256\0" + d_bytes + kid_bytes).digest()
    derived = int.from_bytes(seed, "big") % (P256_N - 1) + 1
    if derived == d_int:
        derived = derived % (P256_N - 1) + 1
    x, y = p256_multiply(derived)
    result = {
        "kty": "EC",
        "use": key.get("use", "sig"),
        "crv": "P-256",
        "alg": "ES256",
        "d": b64url_uint(derived),
        "x": b64url_uint(x),
        "y": b64url_uint(y),
    }
    if isinstance(kid, str) and kid:
        result["kid"] = f"{kid}-client2"
    return result


def derived_ec_p256_client2_keys(jwks: object, *, source: str) -> list[dict[str, object]]:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise SystemExit(f"{source} requires a jwks.keys array")
    keys = [
        derive_client2_ec_p256_key(key, source=f"{source}.jwks.keys[{index}]")
        for index, key in enumerate(jwks["keys"])
        if isinstance(key, dict)
        and key.get("kty") == "EC"
        and key.get("crv") == "P-256"
    ]
    if not keys:
        raise SystemExit(f"{source} requires at least one private EC P-256 JWK")
    return keys


def use_ec_client2(config: dict[str, object], *, source: str, client_id: str) -> None:
    client = config.get("client")
    client2 = config.get("client2")
    if not isinstance(client, dict):
        raise SystemExit(f"{source} requires a client object")
    if not isinstance(client2, dict):
        raise SystemExit(f"{source} configurations require a client2 object")
    client2["client_id"] = client_id
    client2["jwks"] = {
        "keys": derived_ec_p256_client2_keys(client.get("jwks"), source=f"{source}.client")
    }


def require_scope(metadata: dict[str, object], scope: str) -> None:
    current = metadata.get("scope")
    scopes = [item for item in current.split() if item] if isinstance(current, str) else []
    if scope not in scopes:
        scopes.append(scope)
    metadata["scope"] = " ".join(scopes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-config-json-file", required=True)
    parser.add_argument("--mtls-config-json-file")
    parser.add_argument("--driver-config-json-file", required=True)
    parser.add_argument("--credential-datasets-json-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--conformance-server")
    parser.add_argument("--target-origin")
    parser.add_argument(
        "--onboarding-profile",
        choices=("official", "operator-black-box"),
        required=True,
    )
    parser.add_argument("--run-namespace")
    parser.add_argument("--subject-id")
    args = parser.parse_args()
    base = json.loads(Path(args.base_config_json_file).read_text(encoding="utf-8"))
    if args.onboarding_profile == "official":
        if not args.mtls_config_json_file:
            raise SystemExit(
                "official OpenID4VC material requires --mtls-config-json-file"
            )
        apply_official_mtls_material(
            base,
            json.loads(Path(args.mtls_config_json_file).read_text(encoding="utf-8")),
        )
    elif args.mtls_config_json_file:
        raise SystemExit(
            "operator-black-box OpenID4VC material must use its run-scoped mTLS identities"
        )
    driver = json.loads(Path(args.driver_config_json_file).read_text(encoding="utf-8"))
    credential_datasets = json.loads(
        Path(args.credential_datasets_json_file).read_text(encoding="utf-8")
    )
    if not isinstance(credential_datasets, dict) or set(credential_datasets) != {
        "sd_jwt_vc",
        "mdoc",
    }:
        raise SystemExit(
            "credential datasets must contain exactly sd_jwt_vc and mdoc objects"
        )
    if not all(
        isinstance(value, dict) and value for value in credential_datasets.values()
    ):
        raise SystemExit("credential datasets must be non-empty JSON objects")
    issuer_settings = driver.get("issuer")
    configuration_ids = (
        issuer_settings.get("credential_configuration_ids")
        if isinstance(issuer_settings, dict)
        else None
    )
    if not isinstance(configuration_ids, dict) or any(
        not isinstance(configuration_ids.get(format_name), str)
        or not configuration_ids[format_name]
        for format_name in ("sd_jwt_vc", "mdoc")
    ):
        raise SystemExit(
            "driver issuer requires credential_configuration_ids for sd_jwt_vc and mdoc"
        )
    if issuer_settings.get("dedicated_conformance_subject") is not True:
        raise SystemExit(
            "driver issuer must explicitly mark its subject as a dedicated conformance identity"
        )
    bind_subject_id(issuer_settings, args.onboarding_profile, args.subject_id)
    issuer_settings["credential_datasets"] = {
        configuration_ids[format_name]: copy.deepcopy(dataset)
        for format_name, dataset in credential_datasets.items()
    }
    if args.conformance_server:
        driver["conformance_server"] = args.conformance_server
    if args.target_origin:
        driver["target_origin"] = args.target_origin
    if not driver.get("conformance_server") or not driver.get("target_origin"):
        raise SystemExit("driver configuration requires conformance_server and target_origin")
    namespace = (
        (args.run_namespace or "").strip().lower()
        if args.onboarding_profile == "operator-black-box"
        else None
    )
    ids = vci_client_ids(args.onboarding_profile, namespace)
    target_origin = urllib.parse.urlparse(str(driver["target_origin"]))
    target_hostname = target_origin.hostname
    if (
        target_origin.scheme != "https"
        or not target_hostname
        or target_origin.username is not None
        or target_origin.password is not None
        or target_origin.path not in ("", "/")
        or target_origin.params
        or target_origin.query
        or target_origin.fragment
    ):
        raise SystemExit("driver target_origin must be an HTTPS origin with a hostname")
    verifier = driver.get("verifier")
    credential_type_values = verifier.get("credential_type_values") if isinstance(verifier, dict) else None
    if not isinstance(credential_type_values, dict) or any(
        not isinstance(credential_type_values.get(format_name), str)
        or not credential_type_values[format_name]
        for format_name in ("sd_jwt_vc", "iso_mdl")
    ):
        raise SystemExit(
            "driver verifier requires non-empty sd_jwt_vc and iso_mdl credential_type_values"
        )
    request_object_trust_anchor_pem = verifier.get("request_object_trust_anchor_pem") if isinstance(verifier, dict) else None
    if (
        not isinstance(request_object_trust_anchor_pem, str)
        or "-----BEGIN CERTIFICATE-----" not in request_object_trust_anchor_pem
        or "-----END CERTIFICATE-----" not in request_object_trust_anchor_pem
    ):
        raise SystemExit("driver verifier requires request_object_trust_anchor_pem")
    # The OIDF verifier plans issue SD-JWT VC test credentials with the ARF vct
    # value. The similarly named VCI credential configuration id is not the vct
    # and must not leak into VP DCQL matching.
    credential_type_values["sd_jwt_vc"] = OIDF_VP_SD_JWT_VCT
    required = {"vci", "vci_haip", "vp", "vp_haip"}
    if set(base) != required or not all(isinstance(base[name], dict) for name in required):
        raise SystemExit(f"base configuration must contain exactly {sorted(required)}")
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    configs: dict[str, object] = {}
    expressions: list[str] = []
    aliases: list[str] = []
    cases = matrix_cases()
    for plan, slug, variants in cases:
        key = "vci_haip" if plan == VCI_HAIP else "vci" if plan == VCI_STANDARD else "vp_haip" if plan == VP_HAIP else "vp"
        config = copy.deepcopy(base[key])
        if plan in (VCI_STANDARD, VCI_HAIP):
            issuer = driver.get("issuer")
            if not isinstance(issuer, dict):
                raise SystemExit("driver configuration requires issuer settings")
            configuration_ids = issuer.get("credential_configuration_ids")
            if not isinstance(configuration_ids, dict):
                raise SystemExit("driver issuer requires credential_configuration_ids")
            format_name = variants["credential_format"]
            configuration_id = configuration_ids.get(format_name)
            if not isinstance(configuration_id, str) or not configuration_id:
                raise SystemExit(f"driver issuer lacks credential configuration for {format_name}")
            vci = config.get("vci")
            if not isinstance(vci, dict):
                raise SystemExit(f"{key} base configuration requires a vci object")
            vci["credential_issuer_url"] = str(driver["target_origin"])
            vci["credential_configuration_id"] = configuration_id
            vci.pop("static_tx_code", None)
            if variants.get("vci_grant_type") == "pre_authorization_code":
                tx_code = issuer.get("tx_code")
                if isinstance(tx_code, str) and tx_code:
                    vci["static_tx_code"] = tx_code
            client = config.get("client")
            if not isinstance(client, dict):
                raise SystemExit(f"{key} base configuration requires a client object")
            client_auth_type = variants.get(
                "client_auth_type", "client_attestation" if plan == VCI_HAIP else "private_key_jwt"
            )
            if (
                plan == VCI_HAIP
                and full_vci_variant(plan, variants).get("vci_grant_type") == "authorization_code"
            ):
                require_scope(client, "offline_access")
            client["client_id"] = (
                ids["attested"]
                if client_auth_type == "client_attestation"
                else ids["private_key"]
            )
            client2_id = (
                ids["attested2"]
                if client_auth_type == "client_attestation"
                else ids["private_key2"]
            )
            use_ec_client2(config, source=key, client_id=client2_id)
            client2 = config.get("client2")
            if (
                isinstance(client2, dict)
                and plan == VCI_HAIP
                and full_vci_variant(plan, variants).get("vci_grant_type") == "authorization_code"
            ):
                require_scope(client2, "offline_access")
            config["nazo"] = {
                "openid4vc_role": "issuer",
                "client_auth_type": client_auth_type,
                "credential_format": format_name,
                "credential_dataset": copy.deepcopy(
                    credential_datasets[format_name]
                ),
            }
        else:
            client = config.get("client")
            if not isinstance(client, dict):
                raise SystemExit(f"{key} base configuration requires a client object")
            # The suite uses this value to validate x509_san_dns verifier IDs.
            # Bind it to the deployed verifier rather than the local suite host.
            client["client_id"] = target_hostname
            if plan == VP_HAIP or variants.get("request_method") == "request_uri_signed":
                client["request_object_trust_anchor_pem"] = request_object_trust_anchor_pem
        prefix = str(config.get("alias", "nazo-openid4vc"))
        alias = plan_alias(prefix, slug, namespace)
        config["alias"] = alias
        config["description"] = f"NazoAuth {slug} OpenID4VC Final regression"
        filename = f"openid4vc-{slug}.json"
        configs[filename] = config
        aliases.append(alias)
        expressions.append(plan_expression(plan, variants, filename))
    driver["aliases"] = aliases
    (output / "openid4vc-plan-configs.json").write_text(json.dumps({"configs": configs}, indent=2) + "\n", encoding="utf-8")
    (output / "openid4vc-plan-set.json").write_text(json.dumps(expressions, indent=2) + "\n", encoding="utf-8")
    (output / "openid4vc-expected-skips.json").write_text(
        json.dumps(expected_skips_for_cases(cases), indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "openid4vc-expected-problems.json").write_text(
        json.dumps(expected_problems_for_cases(cases), indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "openid4vc-driver.json").write_text(json.dumps(driver, indent=2) + "\n", encoding="utf-8")
    (output / "oidf-onboarding-contract.json").write_text(
        json.dumps(
            {
                "schema": 1 if args.onboarding_profile == "operator-black-box" else 2,
                "onboarding_profile": args.onboarding_profile,
                "target_issuer": str(driver["target_origin"]).rstrip("/"),
                "suite_base_url": str(driver["conformance_server"]).rstrip("/"),
                **({"run_namespace": namespace} if namespace else {}),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
