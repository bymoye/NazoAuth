# NI-004 RFC 7591 OIDF Coverage

## Scope

NI-004 implements RFC 7591 / OIDC Dynamic Client Registration as a
default-closed registration endpoint:

- `/register` is routed only when the Dynamic Client Registration runtime
  module is enabled and an initial-access token is present.
- Discovery advertises `registration_endpoint` only when the endpoint is
  enabled.
- Public deployments can require `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`.
- RFC 7592 registration management, software statements, and remote `jwks_uri`
  fetching are not part of the implemented profile.

## OIDF Suite Mapping

The OpenID Foundation conformance suite includes OIDC Basic certification
plans parameterized by `client_registration=dynamic_client`. This is the
closest official coverage for the implemented RFC 7591 surface, because it
exercises provider metadata, dynamic client registration, authorization code
flow, ID Token/UserInfo behavior, and registration response consistency.

The repository-owned full matrix therefore includes:

```text
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] oidf-oidcc-dynamic-plan-config.json
```

Broader Dynamic Client Registration or ecosystem plans that require RFC 7592
management semantics, software statements, sector-specific trust policy, or
remote client metadata fetching are intentionally not added until those
profiles are implemented.

## Runtime Configuration

`scripts/prepare_oidf_black_box.py` generates:

- `oidf-oidcc-dynamic-plan-config.json`
- a 17-plan full matrix in `runtime/oidf/oidf-plan-set.json`
- matching initial access token values for the server `.env.yaml` and OIDF
  client registration config

The generated files are runtime artifacts and remain gitignored.
