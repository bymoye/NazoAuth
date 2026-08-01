# Test Architecture

## Boundary

Production and test implementations are separate artifacts. A Rust file under
`crates/*/src` may contain runtime code plus only the minimum hooks required to
compile private-unit tests. It must not contain `#[test]`, `#[tokio::test]`, an
inline `mod tests { ... }`, a test fixture implementation, or a test-only helper
implementation.

Each crate uses this layout:

```text
crates/<crate>/
├── src/<module>.rs
└── tests/
    ├── unit/<module>.rs
    ├── unit/<module>/<concern>.rs
    ├── support/
    │   ├── fixtures/<concern>.rs
    │   └── ...
    └── <integration-target>.rs
```

- `tests/unit` contains private-unit tests mounted as children of their owning
  production module. The path mirrors the production module exactly once.
- `tests/support` contains fixtures, macros, schemas, and other test-only
  infrastructure shared by tests.
- `tests/support` may build fixtures, fakes, and infrastructure, but it must not
  parse a production protocol, reproduce a key format, implement a policy, or
  contain a second version of production behavior.
- top-level `tests/*.rs` files are Cargo integration-test targets. They test the
  crate through its public API and must not depend on private implementation.

Names such as `tests/source_mounted`, `tests/.../src`, `src/tests`, and repeated
`.../tests/.../tests/...` segments are forbidden. They describe a compiler
mechanism rather than the product or module responsibility.

## Mount Rules

A private-unit test uses an explicit, minimal mount in its owning module:

```rust
#[cfg(test)]
#[path = "../tests/unit/policy.rs"]
mod tests;
```

Do not compile a production source file into an integration test and do not
`include!` a test implementation into production source. Private-unit tests
belong in the mounted child module; reusable test infrastructure belongs in the
crate's test-support module. If a test can use the public API, make it an
integration test instead. If a behavior cannot be tested without duplicating
it, first move that behavior behind an owned production API.

`tests/support/seams` is forbidden. Test-only dependency composition belongs in
an explicitly named `tests/support` module mounted with `#[path]`; it must not
reimplement policy, parsing, key derivation, cryptography, or state
transitions. Tests that need raw persistence keys use the owning storage
crate's test harness so the derivation still has one implementation.

Conditional runtime behavior under `cfg(test)` is exceptional. It is allowed
only when the production action is unsafe or nondeterministic in a test process
(for example, process abort, real network proxy discovery, or live service
composition). Every exception is enumerated by
`scripts/verify_static_contracts.py`; adding one requires an architectural
review and a concrete explanation.

## Enforcement

`python scripts/verify_static_contracts.py --check` rejects:

- executable tests or inline test modules under `src`;
- test files under `src`;
- top-level `cfg(test)` items that are not explicit unit/support mounts;
- unreviewed nested test seams;
- a test that reaches into `src` with `#[path]` or `include!`;
- missing mount targets, any `tests/support/seams` file, test-side `include!`,
  and the legacy `tests/source_mounted` directory.

Run the structure check before the normal Rust quality gate documented in
[architecture.md](architecture.md#compatibility-and-verification).
