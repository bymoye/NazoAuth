#!/usr/bin/env sh
set -eu
cd /workspace
LOG=perf/results/dev-capacity-repair.log
CPUSETS=perf/results/dev-capacity-cpusets.txt
CHILDREN=perf/results/dev-capacity-repair-children.txt
: >"$CHILDREN"
{
  echo "repair immediate runner started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "current result lengths before repair:"
  python3 - <<'PY'
import json
from pathlib import Path
for name in ["token-only", "oidc-refresh-only", "oidc-cold-login", "oidc-logged-in", "fapi2-full-security"]:
    p = Path(f"perf/results/capacity-dev-{name}.json")
    print(name, len(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else "missing")
PY

  run_child() {
    scenario="$1"
    suffix="$2"
    cpu_set="$3"
    log_path="perf/results/dev-capacity-${suffix}.log"
    echo "repair starting ${scenario} on CPUs ${cpu_set} -> ${log_path}"
    (
      export CAPACITY_SCENARIOS="${scenario}"
      export CAPACITY_REPORT_SUFFIX="dev-${suffix}"
      export PERF_CPUSET="${cpu_set}"
      export CNB_CAPACITY_SKIP_BOOTSTRAP=1
      export CNB_CAPACITY_COMMIT=0
      export CAPACITY_DURATION="${CAPACITY_DURATION:-30m}"
      export CAPACITY_INSTANCES="${CAPACITY_INSTANCES:-1,2,4}"
      export CNB_BUILD_ID="dev-capacity"
      export CNB_REPO_SLUG="nazo_zero/NazoAuth"
      export CNB_BRANCH="$(git branch --show-current 2>/dev/null || echo main)"
      export CNB_COMMIT="$(git rev-parse HEAD)"
      ./perf/cnb_capacity.sh
    ) >"${log_path}" 2>&1 &
    echo "$! ${suffix} ${log_path}" >>"$CHILDREN"
  }

  run_child oidc_cold_login_refresh oidc-cold-login "$(sed -n '2p' "$CPUSETS")"
  run_child oidc_logged_in_authorization_code oidc-logged-in "$(sed -n '3p' "$CPUSETS")"
  run_child fapi2_full_security fapi2-full-security "$(sed -n '5p' "$CPUSETS")"

  status=0
  while :; do
    running=0
    echo "repair heartbeat $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    while read -r pid suffix log_path; do
      [ -n "$pid" ] || continue
      state=exited
      if kill -0 "$pid" 2>/dev/null; then
        state=running
        running=1
      fi
      lines=$(wc -l <"$log_path" 2>/dev/null || echo 0)
      echo "[$suffix] pid=$pid state=$state lines=$lines log=$log_path"
      if [ -s "$log_path" ]; then
        tail -n "${CAPACITY_LOG_TAIL_LINES:-12}" "$log_path" | sed "s/^/[$suffix] /" || true
      fi
    done <"$CHILDREN"
    [ "$running" -eq 1 ] || break
    sleep "${CAPACITY_LOG_INTERVAL_SECONDS:-60}"
  done

  while read -r pid suffix log_path; do
    [ -n "$pid" ] || continue
    if wait "$pid"; then
      echo "repair scenario $suffix completed"
    else
      code=$?
      status=1
      echo "repair scenario $suffix failed with exit code $code"
      tail -n 120 "$log_path" || true
    fi
  done <"$CHILDREN"

  echo "result lengths after repair:"
  python3 - <<'PY'
import json
from pathlib import Path
for name in ["token-only", "oidc-refresh-only", "oidc-cold-login", "oidc-logged-in", "fapi2-full-security"]:
    p = Path(f"perf/results/capacity-dev-{name}.json")
    print(name, len(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else "missing")
PY
  echo "dev capacity repair finished $(date -u '+%Y-%m-%dT%H:%M:%SZ') status=$status"
  exit "$status"
} >>"$LOG" 2>&1
