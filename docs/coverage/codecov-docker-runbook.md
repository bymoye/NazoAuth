# Docker-backed Codecov Runbook

This project runs the coverage compiler on the host and lets the coverage
script own disposable PostgreSQL and Valkey containers. The script binds both
fixtures to fixed loopback ports, labels them for ownership checks, and removes
them on exit.

## Recommended Command

Run this from the repository root in Bash (Git Bash is supported on Windows):

```sh
CARGO_BUILD_JOBS=1 \
CARGO_TERM_COLOR=never \
CARGO_TARGET_DIR="$PWD/target/codecov-coverage" \
RUST_TEST_THREADS=1 \
bash scripts/generate_codecov_lcov.sh
```

PowerShell 7 launcher for Git Bash:

```powershell
$repo = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw "Run from a NazoAuth Git worktree" }
Set-Location $repo
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_TERM_COLOR = 'never'
$env:CARGO_TARGET_DIR = "$repo/target/codecov-coverage"
$env:RUST_TEST_THREADS = '1'
& 'C:\Program Files\Git\bin\bash.exe' scripts/generate_codecov_lcov.sh
if ($LASTEXITCODE -ne 0) { throw "Coverage generation failed" }
```

## Known Failure Modes

- Run the command from the resolved NazoAuth repository root.
  `CARGO_TARGET_DIR` must resolve to `<repository>/target/codecov-coverage`.
  The script rejects other target directories to prevent coverage and ordinary
  Cargo artifacts from contaminating each other.
- Do not set `CODECOV_DOCKER_NETWORK`, fixture host/container overrides, or
  non-default fixture ports. The script deliberately owns loopback ports 15432
  and 16383 and refuses to remove containers without its ownership label.
- If either fixed port is already in use, stop the conflicting process or
  container before starting coverage; do not redirect the script to an external
  database or Valkey instance.
- The two loopback HTTP ports default to 18000 and 18001. On a shared validation
  host, set `CODECOV_PRIMARY_SERVER_PORT` and `CODECOV_SIGNED_SERVER_PORT` to two
  distinct free unprivileged ports. The script validates both ports before it
  creates fixtures or starts a build; it never terminates an existing listener.
- On Linux the script auto-detects `python3`; set `PYTHON` only when the desired
  interpreter is not available under the usual `python3` or `python` names.
- Private-unit tests live under `tests/unit`. They are compiled through a minimal
  `#[cfg(test)] #[path = "..."]` mount from the owning `src/**` module. Reusable
  dependency composition lives under `tests/support` and is also mounted by
  explicit path; `include!` and `tests/support/seams` are forbidden. Coverage
  runs both library and existing integration tests with
  `cargo test --locked --workspace --all-features --lib --tests`, then derives
  the exact instrumented test-object list from Cargo's JSON artifact stream.
  Do not add duplicate top-level integration tests for behavior already covered
  by the owning private-unit or integration suite.
- Avoid unconditional `cargo clean` during the coverage loop. The script uses a
  dedicated `CARGO_TARGET_DIR`, and Cargo fingerprints the llvm-cov
  instrumentation flags. Use `CODECOV_FORCE_CARGO_CLEAN=1` only when changing the
  target directory or investigating stale instrumentation.
- Do not run non-coverage `cargo test` commands in the same
  `CARGO_TARGET_DIR=/docker-target/codecov` directory. Use a separate target
  directory such as `/docker-target/check` for targeted compile/test checks. If
  the coverage target directory has been polluted by a non-llvm-cov build, run
  one clean coverage pass with `CODECOV_FORCE_CARGO_CLEAN=1`, then return to the
  cached command above.

## Targeted Test Command

Use this for fast compile checks before a full coverage run:

```sh
docker run --rm --network nazo-oauth-codecov-net \
  -v "$PWD:/workspace" \
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry \
  -v nazo-oauth-cargo-git:/usr/local/cargo/git \
  -v nazo-oauth-codecov-target:/docker-target \
  -w /workspace \
  -e CARGO_TARGET_DIR=/docker-target/check \
  -e CARGO_BUILD_JOBS=1 \
  -e CARGO_TERM_COLOR=never \
  nazo-oauth-codecov-runner:local \
  bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib --tests <test-filter> -- --nocapture'
```

For targeted tests that need PostgreSQL or Valkey, start disposable dependency
containers on the same Docker network first:

```powershell
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>$null
docker run -d --name nazo-oauth-codecov-postgres `
  --network nazo-oauth-codecov-net `
  -e POSTGRES_PASSWORD=postgres `
  -e POSTGRES_DB=oauth `
  postgres:18-alpine
docker run -d --name nazo-oauth-codecov-valkey `
  --network nazo-oauth-codecov-net `
  valkey/valkey:8-alpine
Start-Sleep -Seconds 3
docker exec nazo-oauth-codecov-postgres pg_isready -U postgres -d oauth
docker exec nazo-oauth-codecov-valkey valkey-cli ping
```

Then run migrations before DB-backed tests and pass the service URLs into the
targeted test runner. Use `RUST_TEST_THREADS=1` for stateful tests so shared
PostgreSQL and Valkey fixtures do not hide ordering bugs behind scheduler
variance:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v ${repo}:/workspace `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e DATABASE_URL=postgresql://postgres:postgres@nazo-oauth-codecov-postgres:5432/oauth `
  -e VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0 `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  -e RUST_TEST_THREADS=1 `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && cargo test --locked -p nazo-postgres --test migrations -- --nocapture && cargo test --locked --workspace --all-features --lib --tests <test-filter> -- --nocapture'
```

If another agent holds `/docker-target/check`, wait for it to finish. Using a
fresh target directory avoids the lock but triggers a slow full rebuild.

If the host checkout has local ignored files that break configuration loading
such as `.env.yaml` being a directory, run the targeted test from a temporary
workspace just like the coverage flow:

```powershell
docker run --rm --network nazo-oauth-codecov-net `
  -v ${repo}:/host `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -e DATABASE_URL=postgresql://postgres:postgres@nazo-oauth-codecov-postgres:5432/oauth `
  -e VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0 `
  -e CARGO_TARGET_DIR=/docker-target/check `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  -e RUST_TEST_THREADS=1 `
  nazo-oauth-codecov-runner:local `
  bash -lc 'set -euo pipefail; rm -rf /workspace-check; mkdir -p /workspace-check; git -C /host archive HEAD | tar -x -C /workspace-check; git -C /host diff | git -C /workspace-check apply; cp /workspace-check/.env.yaml.example /workspace-check/.env.yaml; cd /workspace-check; . /usr/local/cargo/env; cargo test --locked -p nazo-postgres --test migrations -- --nocapture; cargo test --locked --workspace --all-features --lib --tests <test-filter> -- --nocapture'
```
