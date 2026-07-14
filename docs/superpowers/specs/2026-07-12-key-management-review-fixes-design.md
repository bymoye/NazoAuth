# Key Management Review Fixes Design

## Goal

Remove cross-generation signing races, centralize persisted-key schema ownership, enforce signing purpose/state on every signing path, and eliminate legacy/private server test surfaces without changing wire or file formats.

## Architecture

`KeyManager` owns one `ArcSwap<KeyGeneration>`. Each immutable generation contains both the private loaded key state and its public `KeySnapshot`, so refresh publishes them with one atomic store. `snapshot()` clones the public snapshot from one generation.

HTTP message signing uses an opaque `HttpSigningLease`. `KeyManager::prepare_http_signing()` fixes `SigningPurpose::HttpMessage`, selects an allowed key from one generation, and returns a lease that exposes only `kid()`, `algorithm()`, and `sign(input)`. The server constructs `Signature-Input` from that lease identity and the same lease performs signing, preventing label/key races. The lease cannot sign for another purpose and exposes no key handle.

All active and auxiliary key selection locates the corresponding `ManagedKey` and calls `ManagedKey::can_sign(purpose)` before considering its algorithm or backend. Grace, retired, prepublished, or wrong-purpose keys fail closed through `Signer::sign`, JWT encoding, and HTTP signing.

Persisted JSON schema interpretation and mutation stays in key management. Focused concrete `KeyManager` operations list keys, register an external key, and validate storage, returning public `KeyRecord` values where presentation is needed. The server keyctl parses CLI/settings, invokes these operations, and prints results. There is no administration facade and no public low-level schema helper.

Server test support provides opaque client signing fixtures. Tests may obtain public JWKs and ask fixtures to build assertions, JARs, or signatures, but cannot obtain raw DER, PEM, or private JWK material. Key-management internal compatibility tests may continue using crate-private material helpers.

## Lifecycle classification

The active key is `Active` for its configured purposes. A live inactive same-algorithm rotation candidate is `Prepublished` and cannot sign. A genuinely auxiliary live local key of another supported algorithm is `Active` only for `IdToken` and `Jarm`. Future-retired keys are `Grace`; expired keys are omitted as before. The persisted schema remains byte-shape compatible.

## Errors and compatibility

Selection mismatch, unavailable key, unsupported algorithm, generation mismatch, and signer faults fail closed. Existing external command protocol, filenames, JSON/PEM schema, rotation timestamps, output lines, and HTTP/JWT wire behavior remain unchanged.

## Testing

Tests deterministically swap generations between HTTP lease creation and signing and verify the emitted identity matches the actual verification key. Real signing entry points cover wrong-purpose and non-active denial. Keyctl compatibility tests move with schema ownership. Loader tests distinguish prepublished and auxiliary states. Full crate, server library/binaries, workspace, formatting, Clippy, source-boundary, and exact test-count checks complete the change.
