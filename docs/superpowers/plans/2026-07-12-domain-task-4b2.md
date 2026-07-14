# Domain Task 4B2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the remaining server-owned identity Diesel queries and schema while preserving focused auth-domain projections and behavior.

**Architecture:** `nazo-postgres` will own the three residual identity joins/lookups and return focused domain values, never Diesel rows. The server will consume repository methods, retain Diesel only for non-identity auth tables, and keep database fixture schema outside production source for unit-test compilation.

**Tech Stack:** Rust, Diesel/Diesel Async, PostgreSQL, Cargo tests, rustfmt, Clippy, rustdoc.

## Global Constraints

- Do not expose postgres schema or row modules; they remain `pub(crate)`.
- Do not add server compatibility shims or return database rows across the repository boundary.
- Do not use subagents, push, open a PR, or deploy.
- Database-backed tests may skip only when the configured service is unavailable; do not claim they ran against a database.

---

### Task 1: Lock the production-source boundary

**Files:**
- Modify: `crates/persistence-postgres/tests/identity_repositories.rs`

**Interfaces:**
- Consumes: recursive server source scan.
- Produces: a structural contract rejecting identity Row names, exact identity schema tokens, and identity Diesel query fragments while excluding the `http::admin::users` module name.

- [ ] Add exact forbidden-token assertions for production source.
- [ ] Run `cargo test -p nazo-postgres server_has_no_identity_rows_or_identity_diesel_queries --locked` and verify it fails on the 13 known tokens.

### Task 2: Move residual focused queries into postgres

**Files:**
- Modify: `crates/identity/src/ports.rs`
- Modify: `crates/persistence-postgres/src/repositories/users.rs`
- Create or modify focused repository modules under `crates/persistence-postgres/src/repositories/`
- Modify: `crates/authorization-server/src/support/access_requests.rs`
- Modify: `crates/authorization-server/src/http/admin/grants.rs`
- Modify: `crates/authorization-server/src/http/token/refresh.rs`

**Interfaces:**
- Consumes: tenant/user IDs and existing auth-table query parameters.
- Produces: focused access-request/grant projections and active-user checks with `RepositoryError` failure semantics.

- [ ] Add repository behavior/shape tests before implementation.
- [ ] Implement focused postgres projections without exporting Row types.
- [ ] Replace the three server query sites with repository calls.
- [ ] Run focused postgres and server library tests until green.
- [ ] Commit the query-ownership migration.

### Task 3: Remove production identity schema and rows

**Files:**
- Modify: `crates/authorization-server/src/schema.rs`
- Modify: `crates/authorization-server/src/domain/rows.rs`
- Modify: `crates/authorization-server/src/domain/mod.rs`
- Modify: affected server test support files under `crates/authorization-server/tests/in_source/`

**Interfaces:**
- Consumes: completed repository migration from Task 2.
- Produces: server production source with no identity table definition, joinable, allow-list entry, or identity Row remnant.

- [ ] Move any schema needed only by in-source database fixtures into test-only source.
- [ ] Delete identity definitions, joinables, allow-list entries, imports, and reexports from production source.
- [ ] Run the structural contract and exact package library tests until green.
- [ ] Commit the boundary cleanup.

### Task 4: Verify and document Task 4

**Files:**
- Modify: `.superpowers/sdd/domain-task-4-report.md`

**Interfaces:**
- Consumes: clean structural boundary and test evidence.
- Produces: auditable Task 4 completion report with exact commands, outcomes, and database-service limitation.

- [ ] Run rustfmt, exact package library tests, workspace all-target/all-feature check, strict Clippy, rustdoc/API-leak checks, and the structural contract.
- [ ] Record which database-backed tests skipped because no service was configured.
- [ ] Update the report without overstating runtime database coverage.
- [ ] Commit the report and verify the worktree is clean.
