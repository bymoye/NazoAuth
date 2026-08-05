# Public Black-Box Conformance Runbook

This runbook defines the only supported process for OIDF conformance runs. The
system under test is the normal public production deployment. Conformance tools
must not receive database access, private service-network addresses, privileged
runtime mounts, or alternate protocol behavior.

## Reproduction in four steps

The security boundary makes production onboarding unavoidable, but the operator
path is fixed and short:

1. Deploy an exact immutable Release tag and record both the tag and its full
   source commit SHA.
2. Run `oidf-conformance-full.yml` with `release_tag`, `deployed_sha`,
   `target_issuer`, and `onboarding_material_only=true`; download and verify the
   generated bundle.
3. Apply the bundle through `apply_public_conformance_onboarding.py` using a
   normal applicant and a distinct approver. No database seed or private network
   access is permitted.
4. Run the 27-plan OIDC/FAPI/FAPI-CIBA/Logout matrix with the same inputs and
   `onboarding_material_only=false`, then run the 17-plan OpenID4VC Final/HAIP
   matrix. The workflows check out the deployed SHA, clone the exact official
   suite revision, and refuse tracked modifications before execution.

`--ref` selects the workflow definition to run; it is not a source-trust
allowlist. Both workflows always require the supplied tag to dereference to the
supplied commit. If that commit is not an ancestor of the repository default
branch, they additionally require a non-draft GitHub Release, download the
current runner's Linux `nazoauthctl` bootstrap subject, and verify its GitHub
attestation against the exact
`release-security.yml@refs/tags/<release-tag>` certificate identity, source ref,
source digest, custom Release predicate, and hosted-runner policy. Source from
the requested commit is not checked out or executed until this proof succeeds.
No branch-name exception exists.

The required repository Secret names and their rotation rules are listed in
[`GitHub Actions secrets`](../operations/github-actions-secrets.md). Each fork
supplies its own issuer, accounts, client material, and suite token; this
repository provides no shared deployment target.

## Standards and control-plane boundary

| Surface | Authority | Required boundary |
|---|---|---|
| OAuth client registration and management | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | A conformance client follows the same application, approval, credential-delivery, registration, and management rules as any other client. |
| RP-Initiated Logout | [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | GET and form POST are accepted; redirect URIs are exact registered values; requests without a hint bound to the current OP session require explicit End-User confirmation. Invalid RP data is never trusted for redirect. |
| CIBA token lifecycle | [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | A successful CIBA token response can include a refresh token. Client registration therefore permits `ciba + refresh_token` without inventing an authorization-code dependency; runtime issuance still requires the registered grant and `offline_access` policy. |
| Logout client metadata | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html), [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Both `*_logout_session_required` values default to `false`. A client that needs `sid` explicitly registers the corresponding URI and opts in. Back-Channel delivery disables redirects, blocks unapproved private DNS results, accepts only `200`/`204`, and retries only recoverable transport or HTTP failures. |
| Session Management | [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | `session_state` is bound to the client and redirect origin. The OP iframe rejects malformed messages and any parent origin not represented by an active client's registered redirect URI. |
| mTLS client authentication and certificate-bound access tokens | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | `tls_client_auth` and certificate-bound tokens remain independent capabilities. The authorization server requires one subject selector, canonical DN matching, and type-aware SAN matching. RFC 8705 Section 7.4's cross-CA spoofing boundary is enforced on the public CA-approval path by also requiring a narrowing leaf-certificate pin for `tls_client_auth`. |
| X.509 validation | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | Only a current CA certificate with a supported public key, critical CA basic constraint, and critical `keyCertSign` use may enter a trust request. |
| Trust-anchor administration | [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html) | RFC 6024 supplies the trust-anchor-management security model: authenticate and authorize the source, protect integrity, detect replay, constrain trust purposes, and retain recovery. The product control plane additionally requires a distinct approver, bounded reasons, append-only audit, and revocation. |
| OpenID4VC issuance and presentation | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | Protocol endpoints implement the specifications. Issuer dataset administration is not defined by OpenID4VCI and therefore remains an authenticated, CSRF-protected admin control plane; it is never advertised as a protocol endpoint. |

The absence of a standards-defined operator API is not permission to create an
unbounded endpoint. Non-standard control-plane operations must be least
privilege, same-origin, authenticated, CSRF-protected, size/depth bounded,
tenant-bound, fail closed, and durably audited.

Deployment safety policy limits a tenant to 128 distinct current trust anchors
and a client to 8 current trust anchors. A client may have 4 pending requests,
and one user may have 16 pending requests per tenant. Creation and approval take
a tenant-scoped database advisory lock, so concurrent requests cannot bypass
these limits. These numbers are product resource limits, not requirements
claimed by RFC 8705 or RFC 6024.

## Invariants

- The operator supplies the public HTTPS issuer and public HTTPS suite origin.
  The repository has no default deployment host.
- The public issuer in Discovery must equal the configured target origin.
- The suite reaches only public HTTPS endpoints. Private DNS names, raw IPs,
  loopback addresses, service-network aliases, and disabled TLS verification are
  forbidden.
- Product behavior cannot branch on plan names, suite aliases, callback paths,
  test headers, or a conformance build flag.
- Conformance preparation cannot execute SQL or load production server crates.
- Applicant and approver are distinct active accounts. The approver has a
  positive admin level. Automated identities follow the deployment's normal
  account lifecycle and do not bypass MFA policy.
- Every generated client has a dedicated run namespace and is deactivated after
  the run. Every approved test trust anchor is revoked after the run.
- Expected skips and reviews are exact tuples of configuration, plan, variant,
  and module. An unlisted skip, review, warning, or failure fails the run.
- A public suite runs with development-mode identity injection disabled. Its
  `/api/*` routes return `401` without a suite API token.

## 0. Secure the public suite operator

Register the suite's OIDC operator client through the same application and
approval flow used by other confidential clients. Its redirect URI is the
public HTTPS login callback supplied by the suite; internal ports, raw IPs, and
container hostnames are not registered as alternatives. The complete proxy
chain must preserve the public scheme, host, and port so Spring generates the
same callback and post-login origin seen by the browser.

Disable the suite's development profile before exposing it. A normal,
non-administrator user then signs in through OIDC and creates a short-lived API
token through the suite's `/api/token` endpoint. Store that token in a
root-readable runtime secret file and verify both boundaries before scheduling
plans: bearer access returns `200`, while the same API request without the
token returns `401`. Do not create suite tokens in MongoDB, reuse a product
administrator session as a suite bearer token, or depend on a source-control
provider account.

## Recommended entry point: one reversible run

Use the unified runner for the operator-run public OIDC/FAPI/FAPI-CIBA matrix
instead of assembling the internal commands below by hand. Provide only the
two separate production identities, the CIBA decision token, and a short-lived
public-suite API token. The runner generates a distinct dynamic-registration
initial access token for each lease:

```sh
secret-provider read nazoauth/oidf-run-secrets | \
python scripts/run_public_oidf_conformance.py --secrets-stdin \
  --deployed-sha <deployed-sha> \
  --target-issuer https://issuer.example \
  --conformance-server https://suite.example \
  --suite-dir /opt/oidf/conformance-suite \
  --suite-revision "$(git -C /opt/oidf/conformance-suite rev-parse HEAD)" \
  --work-dir /var/lib/nazo-oidf/runs/<run-id> \
  --export-dir /var/lib/nazo-oidf/results/<run-id> \
  --run-namespace <run-id> \
  --proxy-trust-bundle /etc/proxy/oidf-mtls-ca.crt \
  --proxy-executable /usr/sbin/nginx \
  --nazoauthctl /usr/local/bin/nazoauthctl \
  --nazoauthctl-config /etc/nazoauth/update.json \
  --lease-ttl-seconds 28800
```

The input is strict JSON with exactly `oidf_applicant_email`,
`oidf_applicant_password`, `oidf_admin_email`, `oidf_admin_password`,
`oidf_admin_totp_secret`, and `oidf_conformance_token`. The same
document may instead be supplied through `--secret-fd N` or a regular,
single-link, current-user/root-owned mode-`0600` `--secret-file` on POSIX.
Windows operators must use stdin or an inherited descriptor because POSIX mode
bits do not prove a Windows DACL. No secret has an argv or environment fallback.

For a private pre-release gate, the same runner may bind every lease operation
to an unreleased container by adding all four options below. The active
container must itself use the matching digest-pinned image reference, and its
embedded identity must match every value. Omitting any option fails closed.

```text
--candidate-release vX.Y.Z
--candidate-revision <exact-git-object-id>
--candidate-build-id <exact-embedded-build-id>
--candidate-oci-digest sha256:<manifest-digest>
```

Before testing a schema-changing private candidate, apply its migrations through
the same exact target binding (never through raw SQL or a legacy server command):

```text
sudo nazoauthctl migrate --yes \
  --candidate-release vX.Y.Z \
  --candidate-revision <exact-git-object-id> \
  --candidate-build-id <exact-embedded-build-id> \
  --candidate-oci-digest sha256:<manifest-digest>
```

The exception exists only for this signed candidate migration and
`conformance lease` operations. It neither
changes the signed active Release nor counts as release, provenance, or official
certification evidence. Normal `nazoauthctl` operations continue to require the
signed active Release manifest.

The entry point verifies the deployed product commit, the explicitly selected
official-suite commit, and clean tracked source trees. It then generates source-bound material,
performs application, approval, one-time delivery, and trust approval under
separate identities, atomically installs the approved trust bundle, verifies
the suite API's `401/200` boundary, and runs all 27 plans in concurrent, CIBA,
RP-Initiated Logout, Back-Channel Logout, Front-Channel Logout, and Session
Management groups. Before onboarding it creates a time-bounded conformance
lease through `nazoauthctl`, binds the SHA-256 of the generated registration
and CIBA automated-decision tokens to that lease, and binds every temporary
client to the same lease. These independently generated tokens open only their
lease-owned DCR and CIBA transactions and become unusable immediately on expiry
or revocation. Browser-driving modules and plan groups run serially because the
official suite shares browser cookie/session state across parallel modules.
Success and failure both deactivate the run's clients, revoke and physically
clean the lease-owned data, revoke trust through the public control plane, and
restore the proxy configuration. Private inputs remain in unique work
directories. Raw suite ZIPs are reduced to `evidence-manifest.json` and deleted,
so credentials and log bodies are not retained as evidence.

After the last group completes, the driver re-inspects every module from every
alias in the complete run, waits 45 seconds for asynchronous callbacks and
delivery workers to settle, and then re-inspects the complete matrix again. A
late state change in an earlier group fails the whole run; per-group exports are
never sufficient evidence of overall success by themselves.

Approval remains a real, auditable authorization event. Automation removes file
copying, path inference, command assembly, and recovery work; it does not
collapse applicant and approver identities.

The unified runner idempotently provisions the applicant through administrator
login, CSRF, and public `POST /admin/users`, then verifies the applicant by a
normal public login. Browser credentials are copied only into mode-`0600`
private plan files. Spawned processes receive a closed environment allowlist;
unknown parent settings are not copied at all.

## 1. Prepare immutable runner material

Check out the exact commit to be deployed and require a clean worktree. Set
caller-supplied values:

```sh
export OIDF_TARGET_ISSUER=https://issuer.example
export OIDF_MTLS_TARGET_ISSUER=https://mtls.issuer.example
export OIDF_SUITE_BASE_URL=https://suite.example
secret-provider mount nazoauth/oidf-preparation /run/secrets/nazoauth-oidf-preparation.json
chmod 0600 /run/secrets/nazoauth-oidf-preparation.json
python scripts/prepare_oidf_black_box.py \
  --secret-file /run/secrets/nazoauth-oidf-preparation.json
```

The preparation document is a closed four-field JSON object containing only
`oidf_applicant_email`, `oidf_applicant_password`,
`oidf_dynamic_registration_initial_access_token`, and
`oidf_ciba_automated_decision_token`. Remove the provider mount immediately
after preparation. `--secrets-stdin` and `--secret-fd N` accept the same closed
document when a provider can stream it without a filesystem mount.

The command generates runner configurations, keys, certificates, an onboarding
manifest, and exact plan/skip/review registries under `runtime/oidf`. These are
test-runner inputs, not production records. They contain no authority to mutate
the target database.

When the official runner configuration is stored in the repository's encrypted
material, export it without creating suite plans:

```sh
run_url="$(gh workflow run oidf-conformance-full.yml \
  --ref <workflow-definition-ref> \
  -f release_tag=<exact-release-tag> \
  -f deployed_sha=<deployed-sha> \
  -f target_issuer=https://issuer.example \
  -f credential_holder_email_sha256=<sha256-of-fresh-applicant-email> \
  -f onboarding_material_only=true)"
run_id="${run_url##*/}"
test -n "$run_id"
gh run watch "$run_id" --exit-status
gh run download "$run_id" \
  --name oidf-public-onboarding-material \
  --dir runtime/official-onboarding
```

This mode calls the reusable onboarding-material workflow, binds the exact
Release tag to the deployed source commit, and binds the fresh
applicant email commitment without exposing the email or a password hash,
validates the bundle, and uploads the private artifact. Both conformance jobs
are skipped. Capturing the dispatch URL binds the download to that exact run;
do not select the newest run by branch or workflow name. Verify the downloaded
artifact at the same source commit before step 3. The artifact still
has no production authority: client creation and CA approval remain separate
applicant and administrator operations through the public control plane.

Convert the verified official artifact into production applications without
generating replacement clients, keys, or certificates:

```sh
python scripts/prepare_official_oidf_public_onboarding.py \
  --artifact-directory runtime/official-onboarding \
  --expected-source-commit <deployed-sha> \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --suite-base-url "$OIDF_SUITE_BASE_URL" \
  --applicant-email "$OIDF_APPLICANT_EMAIL" \
  --output-dir runtime/official-onboarding-apply
```

The converter verifies the artifact manifest and certificate bundle again,
checks the applicant-email commitment, and emits exactly 55 unique applications
for the current full OIDC/FAPI/CIBA/OpenID4VC matrix. It does not contact the
database or create a client.

Keep the official OpenID4VC mTLS identities in the dedicated
`OPENID4VC_OIDF_MTLS_CONFIG_JSON` repository secret. Its schema is one `ca`
certificate plus `mtls` and `mtls2` objects containing `cert` and `key`. The
base protocol configuration must not duplicate that rotating identity material.
Both the onboarding export and the official runner overlay the same secret, so
the approved CA, exported leaf certificates, and the private keys actually used
by the suite cannot drift. The public artifact strips every private key and
cryptographically verifies each leaf against its declared CA before upload.

Keep the OIDC/FAPI mTLS identities in the age-encrypted repository asset
`docs/conformance/oidf-mtls-material.json.age`; keep only its decryption
identity in the `OIDF_MTLS_MATERIAL_AGE_IDENTITY` repository secret. The public
plan template contains no environment certificate or private key. Both the
onboarding exporter and official runner must apply this same material after all
derived FAPI-CIBA configurations exist. The material has one dedicated CA and
one client certificate/private key per logical mTLS client, so client IDs,
certificates, and private keys rotate as one source-bound set.

Use `scripts/generate_oidf_mtls_material.py` only as an operator-controlled
identity rotation step. It creates an RSA-3072 CA with critical `CA:TRUE` and
critical `keyCertSign`, and RSA-2048 end-entity certificates restricted to
`clientAuth`. Encrypt the output immediately and remove the plaintext plus CA
private key. This creates external client cryptographic identities; it does not
create production client records or grant trust. The latter actions still go
through the applicant/approver flow. Artifact export rejects a CA whose Basic
Constraints or Key Usage would be rejected by the production trust-request
endpoint, including a missing or non-critical `keyCertSign` extension.

Generate OpenID4VC material from the checked-out product commit for every run.
Do not copy a prior run's `openid4vc-plan-configs.json`, driver, or expected
result registries into a new run directory. Public onboarding replaces logical
wallet identifiers with approved client identifiers, so an already-applied
configuration is an output, not a reusable source. Before installing a
credential dataset or creating a suite plan, the OpenID4VC wrapper now requires
the current 17-plan registry, the same 17 configuration files, the exact driver
alias set, seven bounded skips, and four bounded HAIP warnings to agree. Any
cross-run or stale combination fails before a production mutation.

## 2. Deploy the exact product commit

Deploy the normal runtime image and UI for the exact commit. Do not install
clients, credential datasets, or CA material by SQL, a migration, a server-side
provisioning binary, or a special container entrypoint. Verify the running OCI revision,
health endpoint, Discovery issuer, JWKS, UI assets, and rollback record.

## 3. Onboard clients through the production control plane

Create a bounded lease on the deployment host first. The manifest is public
onboarding material; copy the exact, unmodified file to the host without any
runner private keys or delivered client secrets:

```sh
sudo nazoauthctl conformance lease create \
  --profile oidf-full \
  --material /run/nazoauth/oidf-onboarding-manifest.json \
  --ttl-seconds 28800 \
  --yes
```

Record the returned `lease_id`, then run:

```sh
secret-provider read nazoauth/oidf-operator-credentials | \
python scripts/apply_public_conformance_onboarding.py apply --credentials-stdin \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --lease-id "$OIDF_CONFORMANCE_LEASE_ID" \
  --manifest runtime/official-onboarding-apply/oidf-onboarding-manifest.json \
  --plan-configs runtime/official-onboarding-apply/oidf-plan-configs.json \
  --delivered-client-material runtime/official-onboarding-apply/oidf-delivered-client-material.json \
  --state-file runtime/official-onboarding-apply/oidf-onboarding-state.json \
  --trust-bundle runtime/official-onboarding-apply/approved-mtls-trust-anchors.pem \
  --no-runner-env
```

The signed Operator Task stores only the manifest SHA-256 and lease metadata.
The server never receives a runner private key or plaintext client secret from
this command. Client creation atomically binds each production-control-plane
approval to the active lease. The credential payload is strict JSON with exactly `applicant_email`,
`applicant_password`, `admin_email`, and `admin_password`. Automation may use
`--credentials-fd N` instead. The tool has no environment-variable or argv
fallback for passwords.

For every client, the tool performs the same public operations available to an
operator:

1. applicant login;
2. client-access application;
3. review by a distinct administrator;
4. one-time credential delivery to the applicant;
5. replacement of logical runner identifiers with delivered identifiers;
6. CA trust application for clients that need mTLS;
7. review by the distinct administrator;
8. export of the currently approved tenant trust bundle.

Credential delivery uses the ordinary authenticated product UI/API: the owner
lists their approved application, then submits its public `request_id` with a
CSRF-protected JSON `POST`. The server derives the private storage locator from
the authenticated owner and request identifier; no delivery capability is sent
to the browser. The list and delivery responses are `Cache-Control: no-store`,
and no credential is carried in a URL. This enforces the URI disclosure boundary in
[RFC 9110 Section 17.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9)
and avoids the history, proxy-log, and Referer exposure described by
[OWASP](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url).
There is no GET compatibility route.

All requests are exact-origin HTTPS requests with normal certificate
verification, redirects disabled, response-size limits, JSON content checks,
and CSRF tokens on mutations. The resulting state and bundle are private files.
After a successful apply, install the delivered-client material as the private
`OIDF_DELIVERED_CLIENT_MATERIAL_JSON` repository secret through standard input.
The official OIDC and OpenID4VC workflows refuse to start without it and bind it
to both the selected target issuer and suite origin. This mapping contains the
actual client identifiers and the few generated client secrets; it replaces
only exact `client_id` fields in private runner configuration. It is never a
server seed and is removed after cleanup.
The state file is created before the first public mutation and atomically
updated after every application, approval, credential delivery, and trust
decision. A failed or interrupted apply must be cleaned up before another apply;
cleanup rejects journaled pending applications, revokes approved trust anchors,
and deactivates delivered clients through the same public control plane.

## 4. Install only the approved trust bundle

Install `runtime/oidf/approved-mtls-trust-anchors.pem` into the public reverse
proxy's client-certificate trust store using the deployment's normal atomic
configuration procedure. Record the bundle SHA-256, create a rollback copy,
validate the complete proxy configuration, reload, and confirm the public mTLS
alias. Do not install CA material directly from generated runner files.

The proxy validates the certificate chain. The authorization server still
enforces the registered RFC 8705 client subject selector and client policy.
PKI clients admitted through the public CA-approval path must also match their
administrator-registered leaf-certificate pin. Accepting a CA at the proxy does
not authorize every certificate issued by it at the OAuth layer.

## 5. Install dedicated OpenID4VC evidence through the admin API

OpenID4VC runner datasets use a dedicated, explicitly marked conformance user.
The driver logs in to the same public issuer as an administrator and writes only
the configured subject's bounded dataset through
`/admin/openid4vci/credential-datasets/{subject}/{configuration}`. The endpoint
requires an admin session and CSRF token, validates the configured credential
format and validity window, rejects reserved claims and structural abuse, and
records mutation and audit events in one transaction.

The dataset endpoint is an issuer administration surface, not an OpenID4VCI
protocol endpoint. The driver deletes the dataset in `finally`; cleanup failure
fails the run.

## 6. Run the complete public matrix

Run the complete repository matrix against the public issuer. Concurrency-safe
plans may run concurrently. Logout, session-management, and other browser-state
sensitive plans run in isolated jobs. A longer terminal wait absorbs legitimate
suite completion latency; it does not relax protocol assertions.

Expected warnings are environment-scoped evidence, not a global compatibility
list. Bind each warning to the suite origin, configuration, plan, variant, and
module that actually produces it. In particular, a public suite ingress that
successfully negotiates TLS 1.3 must run with no TLS 1.3 warning allowance; the
bounded warning used for an official ingress that cannot negotiate TLS 1.3 must
not be copied into that public-suite run. A listed warning that does not occur is
also a runner-contract failure, because it indicates stale or mis-scoped
evidence.

Do not substitute targeted plans for full-matrix evidence. Targeted plans are
diagnostic only. Preserve the exact target commit, public origins, plan IDs,
module results, expected-skip/review match, and runner version.

## 7. Run the official suite

Request the official OIDF run only after the complete public black-box matrix
passes on the exact deployed commit. Official configuration material must be
onboarded through the same production control plane. Do not overwrite existing
client credentials or trust records by replaying local runner material.

Observe module status directly in the official suite. CI is useful delivery
evidence but is not a substitute for the suite's terminal module results.

After one onboarding cycle, the standard automation entry points are:

```sh
gh workflow run oidf-conformance-full.yml \
  --ref <workflow-definition-ref> \
  -f release_tag=<exact-release-tag> \
  -f deployed_sha=<deployed-sha> \
  -f target_issuer=https://issuer.example \
  -f runner_mode=parallel-isolated \
  -f onboarding_material_only=false

gh workflow run openid4vc-conformance.yml \
  --ref main \
  -f deployed_sha=<deployed-sha> \
  -f target_origin=https://issuer.example
```

GitHub Actions exposes repository secrets to one short-lived materializer step
because that platform boundary has no native inherited-FD input. That step is
the only process with secret environment entries; it writes mode-`0600` files
under `RUNNER_TEMP`, and later steps receive only paths or inherited FDs and
delete the directory with `if: always()`. This narrows but does not pretend to
eliminate the GitHub runner's trust boundary. The workflow isolates
the OIDC/FAPI concurrent groups, four CIBA groups, and two browser-sensitive
plans. OpenID4VC runs its 17 plans in bounded groups. Operators do not manually
split plans, copy configuration, or alter runner concurrency.

## 8. Cleanup and evidence

Always run:

```sh
secret-provider read nazoauth/oidf-operator-credentials | \
python scripts/apply_public_conformance_onboarding.py cleanup \
  --credentials-stdin --target-issuer "$OIDF_TARGET_ISSUER"

sudo nazoauthctl conformance lease revoke \
  --lease-id "$OIDF_CONFORMANCE_LEASE_ID" --yes
sudo nazoauthctl conformance lease cleanup --yes
```

Cleanup revokes approved trust requests and deactivates created clients through
the public admin API. Lease revocation atomically disables all bound clients;
the cleanup task deletes their tokens, grants, revocations, access requests,
mTLS trust events and client records. If explicit cleanup cannot run, the server
rejects the clients at the lease deadline and its periodic idempotent cleaner
performs the same database deletion. The non-secret lease tombstone remains for
audit. Existing TTL-bound Valkey protocol state is unusable after client expiry
and expires on its own schedule; this implementation does not scan the shared
Valkey namespace. Remove installed CA bytes only after the proxy rollback
procedure confirms the previous trust configuration. Retain redacted results,
the exact commit, plan manifest, bundle digest, approval/revocation audit IDs,
and official run IDs. Never retain passwords, private keys, session cookies,
CSRF tokens, client secrets, or one-time delivery tokens in documentation.

Raw suite ZIPs are not redacted evidence. Their `testInfo.config` and log bodies
can contain browser passwords, client secrets, tokens, or private keys. The
repository runner generates a credential-free `evidence-manifest.json` on
normal and handled-error exit paths. It retains only archive names and SHA-256 values, plan/module IDs,
variants, terminal results, signature-file presence, and condition-result
counts, then deletes the raw ZIPs. Workflow artifact paths must point to that
manifest file exactly and must never upload the whole result directory.
