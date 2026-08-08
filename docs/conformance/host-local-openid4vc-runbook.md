# Host-local OpenID4VC black-box matrix

Run the OpenID4VC Final/HAIP matrix on the same private server that runs the deployment and its local OIDF Conformance Suite. It uses only the public NazoAuth control plane, public issuer endpoints, and Suite HTTP API; it never reads PostgreSQL, Valkey, runtime files, or internal management endpoints.

## Boundary and accounting

`run_host_local_openid4vc_conformance.py` owns exactly the fixed 17-plan OpenID4VC registry from `materialize_openid4vc_oidf_config.matrix_cases()`. It provisions one dedicated non-administrator subject, bounded credential datasets, and exactly four namespaced wallet clients through ordinary application, approval, and one-time credential delivery.

Those 17 cases use `private_key_jwt` or client attestation with DPoP. They do not exercise RFC 8705 mTLS. The runner therefore asserts that all four onboarding records have `mtls_trust_anchor_pem: null` and never changes an ingress proxy client-CA bundle. The independent 27-plan OIDC/FAPI/CIBA runner owns real mTLS client trust and transactional proxy install/restore. Reports may aggregate their independent credential-free evidence as **44 plans**, but neither runner may borrow the other's trust boundary.

The VP request-object trust anchor is different: it is a public certificate used by NazoAuth to validate verifier request-object signatures. Supply `--request-object-trust-anchor-pem`; it must be a regular non-symlink ASCII PEM certificate file, no larger than 1 MiB and with no private key. It is not an ingress client-CA and is never installed with the reverse proxy.

For a standards-full managed installation, create that public file only through
the control plane immediately before the matrix. The runner uses it both as the
VCI credential/status-list trust anchor for the deployed issuer and as the VP
request-object trust anchor. This exports the `CA:TRUE`
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
  "admin_mfa_totp_secret": "...",
  "suite_token": "...",
  "issuer_management_token": "...",
  "verifier_management_token": "..."
}
```

There is deliberately no OpenID4VC base or driver configuration field. Before the fresh installation, `prepare_host_local_oidf_install.py` must create a new `0700` directory during the same continuous acceptance run. It contains a `standards-full-profile.json` with no test trust keys, public conformance trust, matching private run material, and a manifest binding the exact source commit, Suite origin, and file SHA-256 values. Installation reads only the baseline profile. The runner revalidates the entire binding through `--prepared-install-dir`, builds the four fixed configuration families from the pinned Suite shape, binds the freshly provisioned subject ID, management tokens and public request-object trust anchor, and proves that the four public onboarding JWKS records match those same private keys. It accepts no repository, historical, shared, or independently generated private key.

The preparation directory is `0700` and its four files are `0600`. Immediately after it successfully materializes the private Suite configurations, the runner rechecks the digest and deletes `openid4vc-run-material.json`. It then creates an eight-hour lease from `openid4vc-conformance-trust.json`, rechecks that digest, and deletes the file after the server stores it. The public baseline profile and manifest remain as installation-source evidence. The server resolves the attestation keys only for clients bound to that lease and binds the run-local credential CA to verifier transactions created for the same Suite origin. Revocation or expiry rejects all of that trust immediately; periodic cleanup deletes the clients and bound verifier transactions and clears the stored public material. Every private work-directory configuration is removed in `finally`. Each official runner invocation receives the Suite token through a new inherited FD, never a token file. The run-local CA is for client-attestation/key-attestation/credential test material only; it is not an ingress client CA and is never installed with the reverse proxy.

The run-local `credential.signing_jwk` contains a Document Signer certificate
with the ISO/IEC 18013-5 mDL Document Signer EKU `1.0.18013.5.1.2`, signed by
that run's CA. The pinned `release-v5.2.2` includes upstream !2123, which
regenerated the source-embedded mdoc Document Signer certificate and fixed the
expired `release-v5.2.1` fixture. The private Suite remains unmodified and
NazoAuth continues to validate certificate time, purpose, chain, and mdoc
signatures. Rerun the previously blocked mdoc plans; do not convert them to
expected skips or reuse stale results.

## Private-server command

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
  --suite-revision 321bc5bc53601b9690b54c023c0cbfac0f0230f2 \
  --work-dir "$work_dir" \
  --export-dir "$export_dir" \
  --run-namespace "$run_id" \
  --prepared-install-dir /run/nazoauth-host-local-oidf-install \
  --nazoauthctl /usr/local/bin/nazoauthctl \
  --nazoauthctl-config /etc/nazoauth/update.json \
  --lease-ttl-seconds 28800 \
  --request-object-trust-anchor-pem /etc/nazoauth/public/vp-request-object-anchor.pem \
  --plan-group-size 4 \
  --timeout-seconds 4800 \
  --monitor-interval-seconds 10
```

`secret_provider_for_this_host` is operator-owned and writes only this document to stdout without logging it, exporting it into the environment, or appending it to shell history. The FD equivalent is `--secret-fd N` with inherited `N >= 3`.

When this is a private pre-release gate, add the four candidate target options
documented in `oidf-public-black-box-runbook.md`. The runner forwards the same
exact release, revision, build ID, and OCI manifest digest to lease creation,
revocation, and cleanup; released deployments omit them and remain bound to the
signed active Release.

## Completion and failure

Before starting, the command verifies clean runner/deployed commits, a clean exact Suite revision, authenticated versus unauthenticated Suite API behavior, 17 unique aliases, and the fixed registry/expected-record files. After the official runner it performs another complete Suite-state inspection.

`finally` removes generated Suite configs and dedicated datasets, deactivates the four public clients through the same public control plane, then invokes `nazoauthctl conformance lease revoke` and `cleanup`. This runner creates no mTLS trust request. It reduces Suite archives to `evidence-manifest.json` and writes the credential-free `host-local-openid4vc-receipt.json`. A cleanup, lease-revocation, Suite-pristineness, or final-state error fails the operation; do not repair state through a database or internal endpoint.
