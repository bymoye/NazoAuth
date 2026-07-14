# Codecov Docker Runbook

This project should run local coverage in Docker on Windows. The host Rust
toolchain may fail on native OpenSSL/libpq linking, while the Docker runner keeps
the compiler, PostgreSQL, Valkey, and Python environment consistent.

## Recommended Command

Create the reusable Docker network once:

```sh
docker network create nazo-oauth-codecov-net || true
```

Run coverage with cached Cargo registry/git/target volumes:

```sh
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>/dev/null || true
docker run --rm --name nazo-oauth-codecov-runner \
  --network nazo-oauth-codecov-net \
  -v "$PWD:/workspace" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry \
  -v nazo-oauth-cargo-git:/usr/local/cargo/git \
  -v nazo-oauth-codecov-target:/docker-target \
  -w /workspace \
  -e CODECOV_DOCKER_NETWORK=nazo-oauth-codecov-net \
  -e CARGO_TARGET_DIR=/docker-target/codecov \
  -e CARGO_BUILD_JOBS=1 \
  -e CARGO_TERM_COLOR=never \
  -e PYTHON=python3 \
  nazo-oauth-codecov-runner:local \
  bash -lc '. /usr/local/cargo/env && bash scripts/generate_codecov_lcov.sh'
```

PowerShell equivalent:

```powershell
$repo = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw "Run from a NazoAuth Git worktree" }
Set-Location $repo
docker network inspect nazo-oauth-codecov-net *> $null
if ($LASTEXITCODE -ne 0) { docker network create nazo-oauth-codecov-net | Out-Null }
docker rm -f nazo-oauth-codecov-postgres nazo-oauth-codecov-valkey 2>$null
docker run --rm --name nazo-oauth-codecov-runner `
  --network nazo-oauth-codecov-net `
  -v ${PWD}:/workspace `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v nazo-oauth-cargo-registry:/usr/local/cargo/registry `
  -v nazo-oauth-cargo-git:/usr/local/cargo/git `
  -v nazo-oauth-codecov-target:/docker-target `
  -w /workspace `
  -e CODECOV_DOCKER_NETWORK=nazo-oauth-codecov-net `
  -e CARGO_TARGET_DIR=/docker-target/codecov `
  -e CARGO_BUILD_JOBS=1 `
  -e CARGO_TERM_COLOR=never `
  -e PYTHON=python3 `
  nazo-oauth-codecov-runner:local `
  bash -lc '. /usr/local/cargo/env && bash scripts/generate_codecov_lcov.sh'
```

## Known Failure Modes

- Run the PowerShell command from the resolved NazoAuth repository root.
  `${PWD}:/workspace` must mount the directory containing `Cargo.toml`. If in
  doubt, set `$repo = git rev-parse --show-toplevel` and mount
  `${repo}:/workspace`; do not commit a workstation-specific absolute path.
- Do not run the coverage runner container with the script defaults for database
  host access. Inside the runner, `127.0.0.1` points to the runner container, not
  the disposable PostgreSQL container. Set `CODECOV_DOCKER_NETWORK` so the script
  uses container DNS names and internal ports.
- Debian-based runner images usually provide `python3`, not `python`. The script
  now auto-detects `python3`, and the Docker command still sets `PYTHON=python3`
  for explicitness.
- Source-mounted tests live under `tests/in_source`. They are compiled through
  `#[cfg(test)] #[path = "..."]` from the owning `src/**` modules and run with
  `cargo test --locked --workspace --all-features --lib`. Do not add duplicate
  top-level Cargo integration tests for behavior already covered there.
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
  bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
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
  bash -lc '. /usr/local/cargo/env && cargo run --locked --bin nazo-oauth-migrate && cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
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
  bash -lc 'set -euo pipefail; rm -rf /workspace-check; mkdir -p /workspace-check; git -C /host archive HEAD | tar -x -C /workspace-check; git -C /host diff | git -C /workspace-check apply; cp /workspace-check/.env.yaml.example /workspace-check/.env.yaml; cd /workspace-check; . /usr/local/cargo/env; cargo run --locked --bin nazo-oauth-migrate; cargo test --locked --workspace --all-features --lib <test-filter> -- --nocapture'
```
