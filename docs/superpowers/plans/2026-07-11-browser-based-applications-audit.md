# Browser-Based Applications Draft-26 Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit and harden NazoAuth and NazoAuthWeb against `draft-ietf-oauth-browser-based-apps-26` while preserving the first-party session/BFF boundary and the third-party public-client Authorization Code + S256 PKCE boundary.

**Architecture:** Split the current shared browser OAuth CORS policy into endpoint-specific token-management and UserInfo policies, prove the composed routes with negative tests, and publish a dated requirement-to-evidence matrix. In NazoAuthWeb, add a deterministic source/build security gate that permits only the exact non-sensitive locale and session-hint persistence already approved by the design.

**Tech Stack:** Rust, Actix Web, PostgreSQL-backed NazoAuth tests, React 19, TypeScript 6, Vite 8, ESLint 10, Node.js ESM scripts, GitHub Actions, OIDF conformance runner.

## Global Constraints

- The standards claim is exactly `draft-ietf-oauth-browser-based-apps-26` audit evidence; do not claim final RFC compliance.
- NazoAuthWeb remains a same-origin server-session application and must not receive or persist OAuth access tokens, refresh tokens, ID Tokens, client secrets, private keys, OIDF private configuration, or PKCE verifiers.
- Third-party browser applications remain public clients using Authorization Code with S256 PKCE; no implicit, password, hybrid shortcut, or browser client-secret authentication is added.
- `/authorize` remains non-CORS; browser-callable OAuth protocol endpoints remain non-credentialed; first-party `/auth/*` session APIs retain exact-origin credentialed CORS plus CSRF.
- Do not add a Browser-draft runtime profile or metadata field.
- Do not absorb unrelated NazoAuthWeb device/CIBA branch commits; create the coordinated Web branch from its current `origin/main`.
- Every behavior change follows red-green TDD and receives a focused commit.

---

## File Structure

### NazoAuth

- Modify `src/bootstrap/cors.rs`: define endpoint-specific public browser OAuth CORS constructors.
- Modify `src/bootstrap/routes.rs`: attach the narrow constructors to `/token`, `/revoke`, and `/userinfo`.
- Modify `tests/in_source/src/bootstrap/tests/cors.rs`: prove constructor and production-route CORS behavior.
- Create `docs/conformance/2026-07-11-browser-based-applications-draft-26-audit.md`: dated requirement/threat/evidence matrix.
- Modify `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`: record the draft-26 audit outcome and final-RFC re-entry trigger.
- Modify `docs/protocol/rfc-compliance-matrix.md`: state the exact Browser Applications standards boundary.
- Modify `docs/protocol/profile-matrix.md`: distinguish first-party BFF/session and third-party public SPA profiles.
- Modify `docs/operations/configuration.md`: document endpoint-specific CORS and browser-client configuration.

### NazoAuthWeb

- Create `scripts/check-browser-security.mjs`: enforce the persistence allowlist and scan production artifacts.
- Modify `package.json`: run the security gate before and after the production build.
- Modify `README.md`: document the first-party session boundary and the security gate.
- Modify `.github/workflows/ci.yml` if present; otherwise rely on the repository's existing `npm test` check because `package.json` becomes the single gate entry point.

---

### Task 1: Establish clean coordinated workspaces and baselines

**Files:**
- Read: `Cargo.toml`
- Read: sibling `NazoAuthWeb/package.json` after repository discovery and validation

**Interfaces:**
- Consumes: NazoAuth branch `codex/browser-apps-audit` at the approved design commit.
- Produces: clean NazoAuth and NazoAuthWeb workspaces with passing focused baselines.

- [ ] **Step 1: Verify the NazoAuth branch and worktree are clean**

Run:

```powershell
git status --short --branch
git rev-parse --show-toplevel
```

Expected: branch `codex/browser-apps-audit`, no uncommitted files, and the linked worktree path.

- [ ] **Step 2: Run the focused NazoAuth baseline**

Run:

```powershell
cargo test --locked cors --lib
cargo test --locked authorization_pkce --lib
cargo test --locked refresh --lib
```

Expected: all selected tests pass with zero failures.

- [ ] **Step 3: Fetch NazoAuthWeb and create an isolated worktree from main**

Discover the sibling repository from the backend repository parent, then verify
that its `origin`, branch, and worktree status match the coordinated change.
Run in that verified repository:

```powershell
git fetch origin main
git check-ignore -q .worktrees
git worktree add .worktrees/browser-apps-audit -b codex/browser-apps-audit origin/main
```

Expected: `.worktrees` is ignored and the new worktree is based only on `origin/main`. If `.worktrees` is not ignored, add only `/.worktrees/` to `.gitignore`, commit that repository hygiene change, then create the worktree.

- [ ] **Step 4: Install and verify the NazoAuthWeb baseline**

Run in the verified `browser-apps-audit` frontend worktree:

```powershell
npm ci
npm test
```

Expected: ESLint, TypeScript, and the production build pass.

---

### Task 2: Split public browser OAuth CORS by endpoint

**Files:**
- Modify: `tests/in_source/src/bootstrap/tests/cors.rs`
- Modify: `src/bootstrap/cors.rs`
- Modify: `src/bootstrap/routes.rs`

**Interfaces:**
- Consumes: `Settings::cors_allowed_origins` and `apply_allowed_origins(Cors, &Settings)`.
- Produces: `cors_browser_token_management(&Settings) -> Cors` for `/token` and `/revoke`, and `cors_browser_userinfo(&Settings) -> Cors` for `/userinfo`.

- [ ] **Step 1: Replace the broad constructor test with failing endpoint-specific tests**

Add tests with these assertions:

```rust
#[actix_web::test]
async fn browser_token_management_cors_allows_post_dpop_without_csrf_or_credentials() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app = test::init_service(
        App::new()
            .wrap(cors_browser_token_management(&settings))
            .route("/token", web::post().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://spa.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type, dpop"))
        .to_request();
    let response = test::call_service(&app, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none());

    let csrf = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://spa.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "x-csrf-token"))
        .to_request();
    assert_eq!(test::call_service(&app, csrf).await.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn browser_userinfo_cors_allows_get_and_post_bearer_or_dpop() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    for method in ["GET", "POST"] {
        let app = test::init_service(
            App::new()
                .wrap(cors_browser_userinfo(&settings))
                .route("/userinfo", web::get().to(|| async { HttpResponse::Ok().finish() }))
                .route("/userinfo", web::post().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/userinfo")
            .insert_header((header::ORIGIN, "https://spa.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization, dpop"))
            .to_request();
        assert_eq!(test::call_service(&app, request).await.status(), StatusCode::OK);
    }
}
```

- [ ] **Step 2: Run the new tests and verify the red state**

Run:

```powershell
cargo test --locked browser_token_management_cors --lib
cargo test --locked browser_userinfo_cors --lib
```

Expected: compilation fails because the endpoint-specific constructors do not exist.

- [ ] **Step 3: Implement the narrow constructors**

Replace `cors_browser_oauth` with:

```rust
fn public_oauth_cors(settings: &Settings, methods: Vec<&str>) -> Cors {
    let cors = Cors::default()
        .allowed_methods(methods)
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("dpop"),
        ])
        .expose_headers(vec![
            header::WWW_AUTHENTICATE,
            header::HeaderName::from_static("dpop-nonce"),
            header::RETRY_AFTER,
        ])
        .max_age(0);
    apply_allowed_origins(cors, settings)
}

pub(crate) fn cors_browser_token_management(settings: &Settings) -> Cors {
    public_oauth_cors(settings, vec!["POST"])
}

pub(crate) fn cors_browser_userinfo(settings: &Settings) -> Cors {
    public_oauth_cors(settings, vec!["GET", "POST"])
}
```

Attach `cors_browser_token_management` to `/token` and `/revoke`, and `cors_browser_userinfo` to `/userinfo` in `src/bootstrap/routes.rs`.

- [ ] **Step 4: Run the focused CORS suite**

Run:

```powershell
cargo fmt --check
cargo test --locked cors --lib
```

Expected: all CORS tests pass, including rejection of `x-csrf-token` on token management and absence of `Access-Control-Allow-Credentials`.

- [ ] **Step 5: Commit the CORS boundary**

Run:

```powershell
git add src/bootstrap/cors.rs src/bootstrap/routes.rs tests/in_source/src/bootstrap/tests/cors.rs
git commit -m "fix: narrow browser OAuth CORS policies"
```

---

### Task 3: Prove the composed production-route browser boundary

**Files:**
- Modify: `tests/in_source/src/bootstrap/tests/cors.rs`

**Interfaces:**
- Consumes: `routes::configure`, `cors_browser_token_management`, and `cors_browser_userinfo`.
- Produces: route-composition regression tests that fail if a future route uses the wrong CORS policy.

- [ ] **Step 1: Add failing route-composition tests**

Add one table-driven test using the production route assembly:

```rust
#[actix_web::test]
async fn production_browser_oauth_routes_expose_only_their_required_cors_surface() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app = test::init_service(
        App::new().configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    for (path, method, headers) in [
        ("/token", "POST", "content-type, dpop"),
        ("/revoke", "POST", "content-type, authorization, dpop"),
        ("/userinfo", "GET", "authorization, dpop"),
        ("/userinfo", "POST", "authorization, content-type, dpop"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri(path)
            .insert_header((header::ORIGIN, "https://spa.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} {method}");
        assert!(response.headers().get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none());
    }
}

#[actix_web::test]
async fn production_token_route_rejects_get_csrf_and_unknown_origins() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app = test::init_service(
        App::new().configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;
    for (origin, method, headers) in [
        ("https://spa.example", "GET", "content-type"),
        ("https://spa.example", "POST", "x-csrf-token"),
        ("https://attacker.example", "POST", "content-type"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::ORIGIN, origin))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }
}
```

- [ ] **Step 2: Temporarily attach the old broad constructor and verify the test detects it**

Run the new test before the Task 2 route fix, or temporarily change `/token` back to the broad constructor, then run:

```powershell
cargo test --locked production_token_route_rejects_get_csrf_and_unknown_origins --lib
```

Expected: FAIL because the broad policy permits GET or `x-csrf-token`. Restore the Task 2 implementation immediately.

- [ ] **Step 3: Run the composed-route tests in the green state**

Run:

```powershell
cargo test --locked production_browser_oauth_routes --lib
cargo test --locked production_token_route --lib
```

Expected: both tests pass.

- [ ] **Step 4: Run adjacent protocol regressions**

Run:

```powershell
cargo test --locked authorization_pkce --lib
cargo test --locked redirect_uri --lib
cargo test --locked refresh --lib
cargo test --locked session --lib
cargo test --locked csrf --lib
cargo test --locked well_known --lib
```

Expected: all selected tests pass with zero failures.

- [ ] **Step 5: Commit route-composition evidence**

Run:

```powershell
git add tests/in_source/src/bootstrap/tests/cors.rs
git commit -m "test: lock browser OAuth route boundaries"
```

---

### Task 4: Publish the draft-26 audit matrix and operator guidance

**Files:**
- Create: `docs/conformance/2026-07-11-browser-based-applications-draft-26-audit.md`
- Modify: `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- Modify: `docs/protocol/rfc-compliance-matrix.md`
- Modify: `docs/protocol/profile-matrix.md`
- Modify: `docs/operations/configuration.md`

**Interfaces:**
- Consumes: exact test names from Tasks 2 and 3 and existing PKCE/redirect/refresh/session tests.
- Produces: a dated evidence record with a final-RFC re-entry trigger and no metadata overclaim.

- [ ] **Step 1: Write the audit evidence table**

Create a table with these exact columns and minimum rows:

```markdown
| Draft-26 area | NazoAuth role | Current control | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| BFF architecture | first-party web/session backend | HttpOnly session + CSRF; no OAuth token delivery to NazoAuthWeb | `src/http/profile/session.rs`, NazoAuthWeb persistence gate | conforming architecture choice |
| Authorization endpoint | authorization server | top-level navigation, no CORS | `authorization_endpoint_is_not_cors_enabled` | covered |
| Public browser client | authorization server | code-only + S256 PKCE + exact redirect | named authorization and token tests | covered |
| Token endpoint CORS | authorization server | exact origins, POST only, no credentials or CSRF header | Task 2 and 3 tests | tightened in this change |
| Refresh tokens | authorization server | policy-gated issuance, rotation, family reuse detection | named refresh tests | covered |
| Browser token storage | third-party responsibility | NazoAuthWeb stores none; arbitrary SPA storage cannot be enforced by AS | coordinated Web gate | bounded claim |
| Malicious JavaScript | BFF/public SPA | session/BFF limits token theft in first-party app; CSP and dependency hygiene remain deployment controls | response-header and Web build checks | covered with stated residual risk |
| Final RFC delta | governance | no RFC number on 2026-07-11 | IETF Datatracker link | mandatory re-audit |
```

Add explicit sections for malicious JavaScript, single/persistent token theft, new-flow token acquisition, client hijacking, CSRF, redirect validation, CORS, refresh rotation, BFF, token-mediating backend, and browser-only public clients.

- [ ] **Step 2: Update roadmap and profile documents**

Use wording that says the draft-26 audit is complete, the final-RFC audit remains pending, NazoAuthWeb uses the first-party BFF/session pattern, and third-party SPAs are public code+PKCE clients. Do not mark a final RFC as supported.

- [ ] **Step 3: Update configuration guidance**

Document:

```markdown
- `CORS_ALLOWED_ORIGINS` is an exact allowlist, not a trust boundary for client confidentiality.
- `/token` and `/revoke` accept browser CORS only for POST and never allow credentials.
- `/userinfo` permits GET/POST bearer or DPoP access without cookies.
- `/authorize` is navigation-only and intentionally has no CORS.
- `/auth/me/*` is the separate first-party credentialed session surface and requires CSRF on unsafe methods.
```

- [ ] **Step 4: Verify documentation precision**

Run:

```powershell
rg -n "Browser-Based|browser-based|draft-ietf-oauth-browser-based-apps|BFF|SPA" README.md README.zh-CN.md docs
git diff --check
```

Expected: every claim names draft-26 or a current architecture; no final RFC number or unsupported profile appears.

- [ ] **Step 5: Commit the audit record**

Run:

```powershell
git add docs/conformance/2026-07-11-browser-based-applications-draft-26-audit.md docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md docs/protocol/rfc-compliance-matrix.md docs/protocol/profile-matrix.md docs/operations/configuration.md
git commit -m "docs: record browser applications draft audit"
```

---

### Task 5: Add the NazoAuthWeb browser persistence and artifact gate

**Files:**
- Create: `scripts/check-browser-security.mjs` in the verified frontend worktree
- Modify: `package.json` in the verified frontend worktree

**Interfaces:**
- Consumes: source tree `src/` and optional built tree `dist/`.
- Produces: `npm run security:source`, `npm run security:dist`, and a strengthened `npm test`.

- [ ] **Step 1: Add the failing package-script references**

Set scripts to:

```json
{
  "security:source": "node scripts/check-browser-security.mjs source",
  "security:dist": "node scripts/check-browser-security.mjs dist",
  "test": "npm run lint && npm run security:source && npm run build && npm run security:dist"
}
```

Run `npm run security:source` and verify it fails because the script does not exist.

- [ ] **Step 2: Implement the source persistence gate**

Create an ESM script that:

```javascript
import { readFile, readdir } from 'node:fs/promises'
import { extname, join, relative, resolve } from 'node:path'
import process from 'node:process'

const root = resolve(import.meta.dirname, '..')
const sourceRoot = join(root, 'src')
const allowedStorageFiles = new Map([
  ['auth/sessionHint.ts', "const SESSION_HINT_KEY = 'nazo_oauth_session_hint';"],
  ['i18n/I18nProvider.tsx', "const STORAGE_KEY = 'nazoauth.locale';"],
])
const persistencePattern = /\b(localStorage|sessionStorage|indexedDB|caches\.open|navigator\.serviceWorker)\b/
const privateArtifactPattern = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|oidf[_-](?:private|client)[_-](?:key|secret)|client_assertion\s*[:=]/i

async function filesBelow(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name)
    return entry.isDirectory() ? filesBelow(path) : [path]
  }))
  return nested.flat()
}

async function checkSource() {
  const failures = []
  for (const path of await filesBelow(sourceRoot)) {
    if (!['.ts', '.tsx', '.js', '.jsx'].includes(extname(path))) continue
    const name = relative(sourceRoot, path).replaceAll('\\', '/')
    const text = await readFile(path, 'utf8')
    if (!persistencePattern.test(text)) continue
    const requiredDeclaration = allowedStorageFiles.get(name)
    if (!requiredDeclaration || !text.includes(requiredDeclaration)) {
      failures.push(`${name}: unapproved durable browser storage`)
    }
    if (/access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|code[_-]?verifier|private[_-]?key/i.test(text)) {
      failures.push(`${name}: sensitive OAuth material appears beside durable browser storage`)
    }
  }
  return failures
}

async function checkDist() {
  const distRoot = join(root, 'dist')
  const failures = []
  for (const path of await filesBelow(distRoot)) {
    const text = await readFile(path, 'utf8').catch(() => '')
    if (privateArtifactPattern.test(text)) {
      failures.push(`${relative(distRoot, path)}: private credential pattern in build output`)
    }
  }
  return failures
}

const mode = process.argv[2]
const failures = mode === 'source' ? await checkSource() : mode === 'dist' ? await checkDist() : [`unknown mode: ${mode}`]
if (failures.length) {
  console.error(failures.join('\n'))
  process.exit(1)
}
console.log(`browser security ${mode} check passed`)
```

- [ ] **Step 3: Prove the gate fails on forbidden storage**

Temporarily add `window.localStorage.setItem('access_token', token)` to `src/lib/api.ts`, run:

```powershell
npm run security:source
```

Expected: non-zero exit with `lib/api.ts: unapproved durable browser storage`. Revert the temporary line.

- [ ] **Step 4: Prove the exact allowlist remains green**

Run:

```powershell
npm run security:source
npm run build
npm run security:dist
```

Expected: all three commands pass; the existing session hint and locale persistence are accepted.

- [ ] **Step 5: Commit the executable gate**

Run in the NazoAuthWeb worktree:

```powershell
git add package.json scripts/check-browser-security.mjs
git commit -m "test: prevent browser credential persistence"
```

---

### Task 6: Document the NazoAuthWeb first-party security boundary

**Files:**
- Modify: `README.md` in the verified frontend worktree

**Interfaces:**
- Consumes: the Task 5 gate names and NazoAuth draft audit record.
- Produces: operator/developer guidance that cannot be mistaken for a browser token-storage recommendation.

- [ ] **Step 1: Add the Browser Security Boundary section**

Document these exact facts:

```markdown
## Browser Security Boundary

NazoAuthWeb is a same-origin first-party session application. It uses secure
server-managed cookies and CSRF-protected `/auth/*` requests. It does not act as
an OAuth public SPA and does not store access tokens, refresh tokens, ID Tokens,
client secrets, private keys, OIDF credentials, or PKCE verifiers in browser
storage.

The only approved durable browser values are the locale preference and a
non-authoritative boolean session hint. The backend always verifies the real
session. `npm test` enforces this source and build boundary.
```

Also distinguish third-party public clients, which use NazoAuth `/authorize`
and `/token` with Authorization Code + S256 PKCE.

- [ ] **Step 2: Run the complete Web gate**

Run:

```powershell
npm test
git diff --check
```

Expected: lint, source security, TypeScript, Vite build, artifact security, and whitespace checks all pass.

- [ ] **Step 3: Commit the Web guidance**

Run:

```powershell
git add README.md
git commit -m "docs: define browser session security boundary"
```

---

### Task 7: Run complete verification and prepare coordinated review

**Files:**
- Verify: all files changed by Tasks 2 through 6.

**Interfaces:**
- Consumes: exact NazoAuth and NazoAuthWeb commits from prior tasks.
- Produces: clean branches with reproducible evidence suitable for coordinated PRs.

- [ ] **Step 1: Run complete NazoAuth local gates**

Run:

```powershell
cargo fmt --check
cargo check --locked
cargo clippy --locked -- -D warnings
cargo test --locked --lib
git diff --check origin/main...HEAD
git status --short --branch
```

Expected: every command exits zero and the worktree is clean.

- [ ] **Step 2: Run complete NazoAuthWeb local gates**

Run in the Web worktree:

```powershell
npm ci
npm test
git diff --check origin/main...HEAD
git status --short --branch
```

Expected: every command exits zero and the Web worktree is clean.

- [ ] **Step 3: Review exact diffs for scope and sensitive material**

Run in each repository:

```powershell
git diff --stat origin/main...HEAD
git diff --name-status origin/main...HEAD
git log --oneline origin/main..HEAD
```

Expected: NazoAuth contains only the approved CORS/tests/docs changes; NazoAuthWeb contains only the security gate and guidance; no unrelated device/CIBA changes or secrets appear.

- [ ] **Step 4: Push and create coordinated PRs**

Push both `codex/browser-apps-audit` branches. Create the NazoAuth PR first, then create the NazoAuthWeb PR and cross-link the exact PR URLs and head SHAs in both descriptions. Keep both as drafts until CI passes.

- [ ] **Step 5: Deploy and run browser/OIDF verification**

Deploy the exact NazoAuth server head and exact NazoAuthWeb head to the existing Hostinger release paths. Verify health, Discovery, JWKS, UI assets, first-party login/session/CSRF/logout, token CORS preflights, wrong-origin rejection, and absence of OAuth credentials in Web Storage. Then run the remote-local OIDC/FAPI 19+2 matrix and request the official full matrix.

- [ ] **Step 6: Merge only evidence-bound commits**

Wait for both PR check sets and the official OIDF run. Re-read both PR head SHAs immediately before merge, mark drafts ready, merge with head-SHA matching, fetch both `origin/main` refs, prove the tested commits are ancestors of main, and re-check production health.
