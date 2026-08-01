# Host-local OpenID4VC black-box matrix

Run the OpenID4VC Final/HAIP matrix on the same Hostinger host that runs the deployment and its local OIDF Conformance Suite. It uses only the public NazoAuth control plane, public issuer endpoints, and Suite HTTP API; it never reads PostgreSQL, Valkey, runtime files, or internal management endpoints.

## Boundary and accounting

`run_host_local_openid4vc_conformance.py` owns exactly the fixed 17-plan OpenID4VC registry from `materialize_openid4vc_oidf_config.matrix_cases()`. It provisions one dedicated non-administrator subject, bounded credential datasets, and exactly four namespaced wallet clients through ordinary application, approval, and one-time credential delivery.

Those 17 cases use `private_key_jwt` or client attestation with DPoP. They do not exercise RFC 8705 mTLS. The runner therefore asserts that all four onboarding records have `mtls_trust_anchor_pem: null` and never changes an ingress proxy client-CA bundle. The independent 27-plan OIDC/FAPI/CIBA runner owns real mTLS client trust and transactional proxy install/restore. Reports may aggregate their independent credential-free evidence as **44 plans**, but neither runner may borrow the other's trust boundary.

The VP request-object trust anchor is different: it is a public certificate used by NazoAuth to validate verifier request-object signatures. Supply `--request-object-trust-anchor-pem`; it must be a regular non-symlink ASCII PEM certificate file, no larger than 1 MiB and with no private key. It is not an ingress client-CA and is never installed with the reverse proxy.

For a standards-full managed installation, create that public file only through
the control plane immediately before the matrix. This exports the `CA:TRUE`
certificate from the active atomic OpenID4VC bundle; it never exports the leaf
or any private key:

```bash
install -d -m 0755 /etc/nazoauth/public
nazoauthctl keys export-openid4vc-trust \
  --output /etc/nazoauth/public/vp-request-object-anchor.pem
```

## Secret handoff

The runner accepts one strict UTF-8 JSON object only through non-interactive stdin or an inherited descriptor. It rejects secret files, secret argv, and secret environment variables:

```json
{
  "applicant_email": "...",
  "applicant_password": "...",
  "admin_email": "...",
  "admin_password": "...",
  "suite_token": "...",
  "issuer_management_token": "...",
  "verifier_management_token": "..."
}
```

There is deliberately no OpenID4VC base or driver configuration field. After the release, Suite, network and output boundaries are verified, the runner creates a new `0700` material directory and generates unique P-256 wallet, client-attestation, key-attestation and credential-signing keys for that run, plus a short-lived run-local CA and leaf `x5c` certificates. It builds the four fixed configuration families from the pinned Suite configuration shape, binds the freshly provisioned subject ID, management tokens and public request-object trust anchor, then verifies that the four public onboarding JWKS records exactly match the generated private suite configuration. No repository, historical, shared, or caller-supplied private key is accepted.

The material directory and every generated private configuration are `0600` and removed in `finally`, including when a prior setup step fails. Each official runner invocation receives the Suite token through a new inherited FD, never a token file. The run-local CA is for client-attestation/key-attestation/credential test material only; it is not an ingress client CA and is never installed with the reverse proxy.

## Hostinger command

Use a clean checkout matching the deployed release identity and a clean local Suite checkout at the exact revision. Do not add filters, ad-hoc expected skips, `--disable-ssl-verify`, or an unpinned Suite revision.

```bash
umask 077
run_id="oid4vc-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
work_dir="/var/lib/nazoauth/conformance/${run_id}/private"
export_dir="/var/lib/nazoauth/conformance/${run_id}/evidence"

secret_provider_for_this_host | python3 /opt/nazoauth/source/scripts/run_host_local_openid4vc_conformance.py \
  --secrets-stdin \
  --deployed-sha "$DEPLOYED_SOURCE_SHA" \
  --runner-sha "$DEPLOYED_SOURCE_SHA" \
  --target-issuer https://auth.nazo.run \
  --conformance-server https://oauth-test.nazo.run \
  --suite-dir /opt/nazo-oauth/conformance/operator-suite \
  --suite-revision 946451d1ce29965c9ab7aee05f5003552233160e \
  --work-dir "$work_dir" \
  --export-dir "$export_dir" \
  --run-namespace "$run_id" \
  --request-object-trust-anchor-pem /etc/nazoauth/public/vp-request-object-anchor.pem \
  --plan-group-size 4 \
  --timeout-seconds 4800 \
  --monitor-interval-seconds 10
```

`secret_provider_for_this_host` is operator-owned and writes only this document to stdout without logging it, exporting it into the environment, or appending it to shell history. The FD equivalent is `--secret-fd N` with inherited `N >= 3`.

## Completion and failure

Before starting, the command verifies clean runner/deployed commits, a clean exact Suite revision, authenticated versus unauthenticated Suite API behavior, 17 unique aliases, and the fixed registry/expected-record files. After the official runner it performs another complete Suite-state inspection.

`finally` removes generated Suite configs and dedicated datasets, then deactivates the four public clients through the same public control plane. This runner creates no mTLS trust request. It reduces Suite archives to `evidence-manifest.json` and writes the credential-free `host-local-openid4vc-receipt.json`. A cleanup, Suite-pristineness, or final-state error fails the operation; do not repair state through a database or internal endpoint.
