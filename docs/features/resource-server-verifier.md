# Resource Server Verifier

## Scope

Resource servers use the public verifier API in `src/resource_server.rs`.
Authorization-server internals that skip audience validation for `/userinfo` or
`/introspect` are not resource-server verification APIs.

## Validation Contract

The verifier requires:

- JWT header `typ=at+jwt`.
- Allowed signing algorithm: `EdDSA`, `RS256`, `ES256`, or `PS256` by default.
- `kid` lookup against the configured JWKS.
- JWK `use=sig`, matching `alg`, no private key material, and expected key shape.
- `token_use=access`.
- Exact issuer match.
- At least one configured audience in the JWT `aud` string or array.
- `exp` and optional `nbf` validation with bounded clock skew.
- Required scope checks.
- Optional sender-constraint policy for DPoP `cnf.jkt`, mTLS `cnf.x5t#S256`, or either sender constraint.

The verifier returns structured errors such as `AudienceMismatch`, `MissingScope`, `WrongTokenType`, `DpopBindingMismatch`, and `MtlsBindingMismatch`. Application adapters map these to OAuth bearer-token `WWW-Authenticate` challenges without leaking token contents.

## Core Usage

```rust
use nazo_oauth_server::resource_server::{
    ConfirmationPolicy, ResourceServerVerifier, ResourceServerVerifierConfig,
};
use serde_json::Value;

fn build_verifier(jwks: Value) -> ResourceServerVerifier {
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "https://api.example",
        jwks,
    );
    config.required_scopes = vec!["orders:read".to_owned()];
    config.confirmation = ConfirmationPolicy::RequireAnySenderConstraint;
    ResourceServerVerifier::new(config).expect("resource-server verifier config must be valid")
}

fn authorize(verifier: &ResourceServerVerifier, access_token: &str) {
    let claims = verifier.verify(access_token).expect("token must be valid");
    assert!(claims.scopes.iter().any(|scope| scope == "orders:read"));
}
```

## Framework Adapters

The framework adapters use the same verifier and insert `VerifiedAccessToken` into request extensions only after issuer, audience, expiry, scope, token type, algorithm, key, and sender-constraint checks pass.

Actix Web:

```rust
use actix_web::{get, web};
use nazo_oauth_server::resource_server::{
    ActixVerifiedAccessToken, ResourceServerVerifier,
};

#[get("/orders")]
async fn orders(token: ActixVerifiedAccessToken) -> String {
    token.0.subject
}

fn configure(cfg: &mut web::ServiceConfig, verifier: ResourceServerVerifier) {
    cfg.app_data(web::Data::new(verifier)).service(orders);
}
```

Tower and Axum:

```rust
use nazo_oauth_server::resource_server::{
    ResourceServerVerifier, TowerResourceServerLayer,
};

fn layer(verifier: ResourceServerVerifier) -> TowerResourceServerLayer {
    TowerResourceServerLayer::new(verifier)
}
```

tonic:

```rust
use nazo_oauth_server::resource_server::{
    authorize_tonic_request, ResourceServerVerifier,
};

fn guard<T>(verifier: &ResourceServerVerifier, request: &mut tonic::Request<T>) {
    let claims = authorize_tonic_request(verifier, request).expect("gRPC token must be valid");
    assert!(!claims.subject.is_empty());
}
```

## DPoP Boundary

`ConfirmationPolicy::RequireDpopJkt(expected_jkt)` verifies the token binding material in the JWT access token. A full DPoP-protected resource request must also validate the DPoP proof JWT for:

- `typ=dpop+jwt`
- one and only one `DPoP` request header
- proof signature against the embedded JWK
- proof `jti` replay cache
- `htu` and `htm`
- `ath` matching the presented access token
- nonce policy when configured

`DpopProofVerifier` performs the proof checks and returns a `VerifiedSenderConstraintProof { dpop_jkt: Some(...) }` value. The access-token authorizer then compares that verified `jkt` with the token `cnf.jkt` before accepting the request. The older `SenderConstraintProof` name is only a compatibility alias for this verified context type.

`VerifiedSenderConstraintProof` must never be populated directly from an unverified `DPoP` header. It must come from `DpopProofVerifier` or an equivalent validator that has already checked signature, `jti`, `htu`, `htm`, `ath`, and nonce policy.

For HTTP integrations, `authorize_dpop_http_request` reads the `Authorization: DPoP ...` and `DPoP` headers, verifies the proof, inserts both `VerifiedSenderConstraintProof` and `VerifiedAccessToken` into request extensions, and rejects invalid proof material before token binding is evaluated:

```rust
use nazo_oauth_server::resource_server::{
    authorize_dpop_http_request, DpopProofVerifier, DpopProofVerifierConfig,
    ResourceServerVerifier,
};

fn guard<B>(
    verifier: &ResourceServerVerifier,
    dpop_verifier: &DpopProofVerifier,
    request: &mut http::Request<B>,
) {
    let htu = "https://api.example/orders";
    let claims = authorize_dpop_http_request(verifier, dpop_verifier, request, htu)
        .expect("DPoP-bound request must be valid");
    assert!(!claims.subject.is_empty());
}

fn dpop_verifier() -> DpopProofVerifier {
    DpopProofVerifier::new(DpopProofVerifierConfig::default())
}
```

The `htu` value passed to `authorize_dpop_http_request` must be the deployment-canonical target URI without query or fragment parts. Behind reverse proxies, derive it from the trusted external scheme, host, and path after forwarded-header validation. Do not pass an origin-form URI such as `/orders`, and do not include query parameters in the comparison value.

The built-in replay cache is process-local and bounded by the proof validity window plus a maximum entry count. `DpopProofVerifier::new` uses a default limit of 100000 live replay markers; deployments that need a different bound can construct the verifier with `DpopProofVerifier::new_with_replay_cache_limit`. Expired entries are pruned before new entries are inserted. When the cache is still full after pruning, the verifier fails closed instead of evicting unexpired replay markers. Clustered deployments that require cross-instance replay detection must either route a DPoP key consistently to one resource-server instance or replace this boundary with a shared replay store that preserves the same `jkt:jti` duplicate rejection semantics and bounded-memory behavior.

## mTLS Boundary

`ConfirmationPolicy::RequireMtlsThumbprint(expected_x5t_s256)` verifies the token binding material in the JWT access token. A full mTLS-protected resource request must also compare it with a verified client certificate thumbprint from the local TLS listener or from the trusted proxy boundary described in `docs/operations/deployment.md`.

Forwarded certificate metadata must only be accepted from trusted proxy CIDRs and after duplicate or conflicting forwarded certificate headers have been rejected.

The adapters require a `VerifiedSenderConstraintProof { mtls_x5t_s256: Some(...) }` request extension before accepting an mTLS-bound access token. That extension must come from the local TLS listener or a trusted proxy boundary after certificate metadata has been authenticated.

## Introspection Fallback

JWT validation is the local fast path. Resource servers may fall back to token introspection when:

- the `kid` is unknown and JWKS refresh still cannot find it,
- local revocation freshness requirements are stricter than the JWT lifetime,
- an opaque token profile is introduced by a deployment,
- or policy extensions require authorization-server-side state.

Fallback must not override a local protocol invariant failure such as wrong issuer, wrong audience, wrong `typ`, unsupported algorithm, or sender-constraint mismatch.

## Framework Adapter Contract

Actix Web, Axum/Tower, and tonic adapters all call the same core verifier and preserve these invariants:

- Reject query-string access tokens.
- Reject requests that present multiple token transport methods.
- Map missing or invalid tokens to `401` with `WWW-Authenticate`.
- Map malformed requests to `400`.
- Require verified DPoP proof context before accepting DPoP-bound tokens.
- Require verified mTLS certificate context before accepting mTLS-bound tokens.
- Expose extension points only after issuer, audience, expiry, scope, and sender-constraint checks succeed.
