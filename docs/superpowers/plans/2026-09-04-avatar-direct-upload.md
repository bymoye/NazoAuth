# Avatar direct upload implementation record

## Ownership and dependency direction

`nazo-identity` owns authorization, validation and avatar-reference transitions through
`AvatarDirectUploadPort`, `AvatarUploadStatePort` and `AvatarRepositoryPort`.
The authorization server owns authenticated HTTP endpoints and injects those ports.
It does not parse S3 settings or depend on an S3 SDK.

`nazo-oauth-server-object-store` implements the direct-object port with `reqwest` and the official AWS SigV4 signer for all S3 operations.
Its launcher contributes concrete configuration through the generic configuration
extension and is selected in the executable composition root. Another storage
protocol can implement the same capabilities without changing the avatar service.
The existing local multipart implementation remains available for local storage;
a second unused local object-store implementation was removed during review.

## Accepted upload flow

1. An authenticated, CSRF-protected request creates a tenant/user-bound upload
   authorization in shared transient storage and receives a provider-neutral
   URL, method and headers.
2. The browser uploads directly to the concrete provider. Its authorization fixes
   one staging object, the declared exact byte count and the expiry time.
3. Any server instance claims finalization through an expiring ownership lease.
   It reads a bounded snapshot and decodes a supported PNG, JPEG or WebP image.
4. The service records the snapshot version and content-derived final object ID.
   The provider publishes exactly that source version. PostgreSQL then compares
   and sets the user's avatar reference through its repository adapter.
5. Completion retries recognize an already-selected candidate. Uncertain database
   outcomes retain the final object because it may already be authoritative.

The S3 implementation binds HEAD, GET and CopyObject with conditional ETags.
A reusable staging authorization cannot replace the accepted final object.
Valkey scripts fence stale lease owners and retain the publishing candidate across
retries. Staging objects use the fixed `avatars/staging/` lifecycle prefix.

## Verification targets

- `cargo test -p nazo-identity`: image decoding and direct-flow state transitions.
- `cargo test -p nazo-oauth-server --lib http::profile::avatar::tests`:
  authenticated HTTP, CSRF and existing local upload/read/delete regressions.
- `cargo test -p nazo-valkey --test avatar_upload_state_contract`:
  real shared state and lease transitions when the test backend is configured.
- `cargo test -p nazo-oauth-server-object-store --test s3_minio`:
  real signed PUT, fixed object/size restrictions and immutable publication.
- `cargo test -p nazoauth --test avatar_shared_storage`:
  real PostgreSQL, Valkey and MinIO with separately constructed A/B services;
  A authorizes, the browser uploads, B finalizes/reads, then A retries after
  staging replay and still reads the original final bytes.

The combined test exercises the production service and all concrete adapters;
it does not start two authenticated HTTP server processes. Backend integration
cases require the explicit test environment; a local environment-free skip is
not operational evidence. The final Hostinger results are recorded with the
shared-runtime-state acceptance record.

## Operational boundary

Use a private bucket and browser-origin CORS. Configure lifecycle expiration for
staging objects after the authorization window. Unreferenced final objects need
retention/cleanup based on authoritative references; they must not be deleted on
an ambiguous database result. No frontend source is present in this repository;
the generic client contract is documented in `docs/operations/avatar-direct-upload.md`.
