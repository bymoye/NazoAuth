# GitHub Actions secrets

Repository Secrets are an execution boundary, not a configuration archive. A
secret stays only while a current workflow references it. Values are never
copied into documentation, logs, artifacts, repository variables, or pull
request descriptions.

## Current inventory

| Secret | Purpose | Rotation trigger |
|---|---|---|
| `CODECOV_TOKEN` | Authenticates coverage upload. | Codecov repository token rotation or suspected disclosure. |
| `OIDF_CONFORMANCE_TOKEN` | Short-lived API access to the public official-suite service. | Expiry, suite account change, or each operator-defined short-lived rotation window. |
| `OIDF_USER_EMAIL`, `OIDF_USER_PASSWORD` | Normal non-admin browser identity used by official plans. | Account/password lifecycle change or suspected disclosure. |
| `OIDF_ADMIN_EMAIL`, `OIDF_ADMIN_PASSWORD` | Separate approver identity for operations that require normal administrative approval. | Account/password lifecycle change or suspected disclosure. |
| `OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN` | Authorizes RFC 7591 registration where the deployment requires an initial access token. | Target deployment token rotation. |
| `OIDF_CIBA_AUTOMATED_DECISION_TOKEN` | Binds official CIBA automation to the current deployment without reusing a prior deployment token. | Every fresh installation or target token rotation. |
| `OIDF_PLAN_CONFIG_AGE_IDENTITY` | Decrypts the versioned OIDC/FAPI runner configuration overlay. | Re-encryption or recipient-key rotation. |
| `OIDF_MTLS_MATERIAL_AGE_IDENTITY` | Decrypts the versioned OIDC/FAPI test-client mTLS identity bundle. | CA/client identity rotation or re-encryption. |
| `OIDF_DELIVERED_CLIENT_MATERIAL_JSON` | Maps approved production client registrations to runner aliases. | Every onboarding/cleanup cycle; never reuse after the clients are deactivated. |
| `OPENID4VC_OIDF_BASE_CONFIG_JSON` | Private OpenID4VC runner base configuration. | Dataset, issuer, wallet, or suite configuration change. |
| `OPENID4VC_OIDF_DRIVER_CONFIG_JSON` | Private OpenID4VC driver configuration. | Driver identity or plan configuration change. |
| `OPENID4VC_OIDF_MTLS_CONFIG_JSON` | OpenID4VC external test-client CA and leaf identities. | CA/client identity rotation or suspected disclosure. |

The repository variables are limited to non-secret runner behavior:
`OIDF_EXPORT_RESULTS`, `OIDF_MONITOR_INTERVAL_SECONDS`, and
`OIDF_RUN_TIMEOUT_SECONDS`. Target issuer, deployed commit, and selected plan
are workflow inputs; they are not repository defaults.

## Audit procedure

1. Extract every `secrets.NAME` reference from `.github/workflows`.
2. Compare the resulting set with `gh secret list --repo <owner>/<repo>`.
3. Delete names not referenced by a current workflow.
4. Fail if a workflow reference has no repository or explicitly documented
   organization/environment Secret.
5. Rotate a retained value only from its authoritative provider. GitHub does
   not expose stored values, so an audit must never claim value freshness from
   a name or timestamp alone.

Organization Secrets require organization-administrator access and must be
audited separately. This repository does not use GitHub Environments.
