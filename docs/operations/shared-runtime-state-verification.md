# Shared runtime state verification

Verification date: 2026-09-04. Implementation branches are
`feat/shared-runtime-state` (NazoAuth) and `feat/shared-key-install` (NazoAuthCtl).
This record distinguishes test/build evidence from publication and deployment.

## Environment

Hostinger uses isolated PostgreSQL 18 and Valkey 8 containers and a private
MinIO test bucket. Neither production databases nor the running OIDF Suite are
used. Cloudflare R2 verification uses the supplied account's existing bucket,
application-generated test objects, and no changes to bucket CORS or lifecycle.
Credentials are environment input, never repository fixtures.

Hostinger's selected object storage is Cloudflare R2, bucket `nazoauth`, region
`auto`, with path-style requests. Its `r2storage.nazoauth.com` public domain is
deployment configuration, not a core default or a presigned-upload endpoint.
The concrete adapter receives the account's R2 S3 API endpoint and credentials
through deployment configuration. This selection does not switch the currently
running instance to the newly built software.

## Verification commands and results

Source verification and Hostinger Release builds are complete:

```sh
cargo fmt --all --check
python3 scripts/verify_static_contracts.py --check
python3 scripts/check_persistence_dependency_graph.py
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked --no-fail-fast
cargo test -p nazo-postgres --test migrations --all-features --locked
cargo clippy -p nazo-postgres --test migrations --all-features --locked -- -D warnings
```

The workspace command reported 2,667 passed, one failed and five existing
ignored tests. Its only failing target was `nazo-postgres --test migrations`:
the clean-install baseline assertion had read a shared database already
modified by other integration tests. The test now migrates an isolated schema
and retains the original strict count of 16. The corrected target passed all
16 tests against the same previously used database. All 136 test targets are
therefore verified across the workspace run and focused rerun (2,668 passing
cases, five ignored); no production migration or assertion was weakened.

`cargo build --release --locked -p nazoauth` passed. The Hostinger binary is
`/root/build/shared-state-20260904/artifacts/nazoauth` (32,756,040 bytes),
SHA-256 `bf107e15c0228ac66e989b6ed5104ed79250a0489b06d99a7da96d24133dfb0e`.

The same compiled object-store integration test passed against both MinIO and
Cloudflare R2. It exercises raw-body presigned PUT without manually supplying
Content-Length, exact-length rejection, conditional publication, same-length
staging replay, stale-version conflict, immutable final reads and both staging
and final-object deletion. R2 credentials initially lacked object-write
permission; the successful run followed the user's permission correction.
Temporary objects from earlier failed runs were explicitly removed.

The combined avatar test passed in the workspace against PostgreSQL, Valkey
and MinIO. Its exact compiled test binary was then run on Hostinger with R2
environment input and passed again: A authorizes, B finalizes/reads, A retries
after replay, then the service clears the database reference before deleting
the final object. Real operator process tests also passed all four cases,
including migrations before key generation and journal recovery.

Real PostgreSQL signing-key tests cover concurrent initialization and CAS,
tenant isolation, restart without local key files, wrong wrapping-root
rejection and current/previous-root rewrapping. Key-management regressions
also cover preserved imported key IDs/material, incompatible import rejection,
and verification-key retirement in already captured snapshots.

NazoAuthCtl `45b6bf3b3d6d5f7fdf2bad291f0f7dfbe17696aa` passed:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --release --locked -p nazoauthctl
```

Its test run has 760 passed, zero failed and one existing ignored test.
The Hostinger Release binary is
`/root/build/shared-state-20260904/artifacts/nazoauthctl` (16,989,600 bytes),
SHA-256 `74cf8be5f4ffb5f1fc5f5e3a26bc6d766a443d7549f8314ce076c163f3d162b0`.

## Storage compatibility

The tenant storage configuration follow-up was verified on Hostinger with
104 passing tests: four new configuration cases and two existing S3
signing/isolation cases, 63 server settings tests, and 35 avatar HTTP tests.
The HTTP run used this task's PostgreSQL and Valkey containers. An initial
run failed because those containers were stopped; the complete HTTP target
passed after they were started. The scoped verification commands were:

```sh
cargo test --locked -p nazo-oauth-server-object-store --all-features --lib --test provider --test s3
cargo test --locked -p nazo-oauth-server --all-features --lib settings::tests
cargo test --locked -p nazo-oauth-server --all-features --lib http::profile::avatar::tests
cargo clippy --locked -p nazo-oauth-server-object-store -p nazo-oauth-server --all-features --all-targets -- -D warnings
```

Formatting, static contracts and persistence dependency isolation also passed.
Logs are `tenant-storage-*.log` under the same task evidence directory.
This follow-up did not rebuild the Release artifacts listed above, repeat the
full workspace/R2 integration run, or migrate the deployed instance. See
[tenant configuration and migration](avatar-direct-upload.md#global-default-and-tenant-overrides)
before applying the new local directory layout.

The subsequent optional-global-storage change passed 159 scoped tests on
Hostinger: nine object-store cases, 63 settings cases, 40 configuration cases,
ten CLI cases and 37 avatar HTTP cases. This includes the tenant allowlist,
disabled storage when neither configuration applies, propagation of S3
failure without local fallback, authenticated HTTP 403 responses before
multipart consumption, preserved avatar references and unchanged login/CSRF
guards. The same strict Clippy, formatting and architecture checks passed.
Evidence uses `optional-storage-*.log`; the additional filters were
`config::tests` and `cli::tests` on the same server library target. The scoped
builds do not replace the earlier Release binaries or full workspace proof.

R2 does not implement HTML form POST uploads. The concrete S3 adapter uses
presigned PUT with an exact signed content length; the generic application
contract requires a declared size within its avatar limit. Browsers send the
File/Blob directly and supply Content-Length themselves. Completion separately
decodes the bounded object as an image.
See [R2 presigned URL support](https://developers.cloudflare.com/r2/api/s3/presigned-urls/).

Conditional publication must retain `x-amz-copy-source-if-match`. The
`rust-s3` canonical-header implementation sorts combined `name:value` strings,
which misorders a header whose name prefixes another header's name. Conditional
CopyObject exposed this with `x-amz-copy-source` and
`x-amz-copy-source-if-match`. The adapter uses the official AWS SigV4 signer
for conditional copies and deletes instead of removing the condition or
relaying image bytes. The signed requests include the S3 payload-checksum
header; successful copies drain the response and verify the destination before
the database can select it. R2 also exposed a failure with the previous
library-generated DELETE request, while an independently signed DELETE worked;
the same official signing path now handles every S3 operation. Before release,
`rust-s3 was removed because its quick-xml dependency was affected by
`RUSTSEC-2026-0194 and RUSTSEC-2026-0195. The adapter uses reqwest with the
`official AWS signer for presigned PUT, HEAD, GET, COPY and DELETE. No advisory
`exception or third-party XML parser is required.
See the [upstream signing implementation](https://github.com/durch/rust-s3/blob/master/s3/src/signing.rs)
and [CopyObject contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html).

## Proof boundaries

The combined avatar test constructs independent A/B service instances with
real PostgreSQL, Valkey and object-store clients. A authorizes, the client
uploads directly, B finalizes and reads, then A retries after staging replay.
This exercises production service logic and concrete adapters; it does not
launch two authenticated browser-facing server processes. Authentication and
CSRF have separate HTTP regressions. Browser CORS remains deployment
configuration and is not established by a successful server-side HTTP upload.

The supplied R2 bucket's managed `r2.dev` access was disabled, but its custom
domain still served a staging probe anonymously (HTTP 200). The harmless
probe was removed (HTTP 204). The user assigned this R2 service and public
domain to Hostinger's deployment configuration; the domain remains unchanged.
Preventing anonymous staging reads is a deployment access-policy requirement,
not a requirement to remove the whole public domain or add Cloudflare-specific
logic to NazoAuth. Successful authenticated S3 operations do not establish
staging privacy; that deployment policy remains unverified after this choice.

Database-backed signing keys do not migrate mdoc IACA private keys,
certificates or CRLs, which have a separate deployment lifecycle. This work
alone does not close every requirement of Issue #108.

No repository push, release publication, production deployment or issue
closure is implied by these tests or Release-profile builds.
