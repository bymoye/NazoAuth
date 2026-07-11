#!/usr/bin/env sh
set -eu

echo "extended capacity matrix bootstrap started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
. ./perf/cnb_bootstrap.sh
install_capacity_dependencies
docker compose version >/dev/null

mkdir -p docs/performance perf/results
children_file="perf/results/cnb-extended-capacity-children.txt"
cpusets_file="perf/results/cnb-extended-capacity-cpusets.txt"
: >"${children_file}"

python3 - "${PERF_CPU_RESERVE:-4}" "${EXTENDED_CAPACITY_GROUPS:-10}" >"${cpusets_file}" <<'PY'
import sys
from pathlib import Path

reserve = int(sys.argv[1])
groups = int(sys.argv[2])
allowed = ""
for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
    if line.startswith("Cpus_allowed_list:"):
        allowed = line.split(":", 1)[1].strip()
        break
if not allowed:
    processor_count = Path("/proc/cpuinfo").read_text(encoding="utf-8").count("processor\t:") or 1
    allowed = f"0-{max(0, processor_count - 1)}"

cpus: list[int] = []
for part in allowed.split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(value) for value in part.split("-", 1)]
        cpus.extend(range(start, end + 1))
    else:
        cpus.append(int(part))
cpus = sorted(set(cpus))
if len(cpus) > reserve + groups:
    cpus = cpus[:-reserve]

def fmt(values: list[int]) -> str:
    ranges: list[str] = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append(f"{start}-{previous}" if start != previous else str(start))
        start = previous = value
    ranges.append(f"{start}-{previous}" if start != previous else str(start))
    return ",".join(ranges)

base = len(cpus) // groups
extra = len(cpus) % groups
offset = 0
for index in range(groups):
    size = base + (1 if index < extra else 0)
    chunk = cpus[offset : offset + size] if size > 0 else cpus
    offset += max(size, 0)
    print(fmt(chunk))
PY

echo "using extended capacity CPU sets:"
cat "${cpusets_file}"

git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"

push_capacity_commit() {
  branch="${CNB_BRANCH:-$(git branch --show-current 2>/dev/null || echo main)}"
  for attempt in 1 2 3; do
    if git push origin "HEAD:${branch}"; then
      return 0
    fi
    sleep $((attempt * 10))
  done
  git push origin "HEAD:${branch}"
}

extended_report_path() {
  suffix="$1"
  echo "docs/performance/reports/extended/performance-capacity-curve-extended-${suffix}.md"
}

commit_extended_report() {
  suffix="$1"
  report="$(extended_report_path "${suffix}")"
  results="perf/results/capacity-extended-${suffix}.json"
  env_report="perf/results/cnb-environment-extended-${suffix}.md"
  if [ ! -f "${report}" ]; then
    echo "extended capacity report not found for ${suffix}: ${report}"
    return 0
  fi
  git add perf/capacity.py perf/cnb_capacity.sh perf/cnb_extended_capacity_matrix.sh perf/k6/oauth.js perf/runner.py perf/seed.py
  git add "${report}"
  [ -f "${results}" ] && git add -f "${results}" || true
  [ -f "${env_report}" ] && git add -f "${env_report}" || true
  if git diff --cached --quiet; then
    echo "No extended capacity report changes to commit for ${suffix}."
    return 0
  fi
  git commit -m "Record CNB extended capacity ${suffix}"
  push_capacity_commit
}

run_extended_child() {
  scenario="$1"
  suffix="$2"
  rates="$3"
  cpu_set="$4"
  log_path="perf/results/cnb-extended-capacity-${suffix}.log"

  echo "starting extended capacity scenario ${scenario} rates=${rates} on CPUs ${cpu_set} -> ${log_path}"
  (
    export CAPACITY_SCENARIOS="${scenario}"
    export CAPACITY_REPORT_SUFFIX="extended-${suffix}"
    export CAPACITY_DURATION="${EXTENDED_CAPACITY_DURATION:-30m}"
    export CAPACITY_INSTANCES="${EXTENDED_CAPACITY_INSTANCES:-1,2,4}"
    export CAPACITY_RATES="${rates}"
    export PERF_CPUSET="${cpu_set}"
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export CNB_CAPACITY_COMMIT=0
    export CNB_BUILD_ID="${CNB_BUILD_ID:-extended-capacity}"
    ./perf/cnb_capacity.sh
  ) >"${log_path}" 2>&1 &
  echo "$! ${suffix} ${log_path}" >>"${children_file}"
}

run_extended_child mtls_client_credentials mtls-client-credentials "250,500,1000,1500,2000" "$(sed -n '1p' "${cpusets_file}")"
run_extended_child par_signed_request_object par-signed-request-object "250,500,1000,1500,2000" "$(sed -n '2p' "${cpusets_file}")"
run_extended_child introspect_opaque_refresh_token introspect-opaque-refresh-token "16,32,64,128,256" "$(sed -n '3p' "${cpusets_file}")"
run_extended_child authorize_par_session authorize-par-session "16,32,64,128,256" "$(sed -n '4p' "${cpusets_file}")"
run_extended_child revoke_refresh_token revoke-refresh-token "16,32,64,128,256" "$(sed -n '5p' "${cpusets_file}")"
run_extended_child metadata_jwks metadata-jwks "250,500,1000,1500,2000" "$(sed -n '6p' "${cpusets_file}")"
run_extended_child ciba_private_key_jwt_dpop_poll ciba-private-key-jwt-dpop-poll "16,32,64,128,256" "$(sed -n '7p' "${cpusets_file}")"
run_extended_child same_user_refresh_token_rotation same-user-refresh-token-rotation "8,16,32,64,128" "$(sed -n '8p' "${cpusets_file}")"
run_extended_child same_user_introspect_opaque_refresh_token same-user-introspect-opaque-refresh-token "8,16,32,64,128" "$(sed -n '9p' "${cpusets_file}")"
run_extended_child same_user_authorize_par_session same-user-authorize-par-session "8,16,32,64,128" "$(sed -n '10p' "${cpusets_file}")"

report_child_logs() {
  interval_seconds="${CAPACITY_LOG_INTERVAL_SECONDS:-60}"
  tail_lines="${CAPACITY_LOG_TAIL_LINES:-20}"
  while :; do
    running=0
    echo "extended capacity heartbeat $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    while read -r pid suffix log_path; do
      [ -n "${pid}" ] || continue
      state="exited"
      if kill -0 "${pid}" 2>/dev/null; then
        state="running"
        running=1
      fi
      log_lines="$(wc -l <"${log_path}" 2>/dev/null || echo 0)"
      echo "[${suffix}] pid=${pid} state=${state} log_lines=${log_lines} log=${log_path}"
      if [ -s "${log_path}" ]; then
        tail -n "${tail_lines}" "${log_path}" | sed "s/^/[${suffix}] /" || true
      fi
    done <"${children_file}"
    [ "${running}" -eq 1 ] || break
    sleep "${interval_seconds}"
  done
}

report_child_logs &
reporter_pid="$!"

status=0
while read -r pid suffix log_path; do
  [ -n "${pid}" ] || continue
  if wait "${pid}"; then
    echo "extended capacity scenario ${suffix} completed"
    commit_extended_report "${suffix}"
  else
    child_status=$?
    status=1
    echo "extended capacity scenario ${suffix} failed with exit code ${child_status}"
    tail -n 120 "${log_path}" || true
    commit_extended_report "${suffix}"
  fi
done <"${children_file}"

kill "${reporter_pid}" 2>/dev/null || true
wait "${reporter_pid}" 2>/dev/null || true

if find docs/performance/reports/extended -maxdepth 1 -name 'performance-capacity-curve-extended-*.md' -print -quit | grep -q .; then
  git add perf/capacity.py perf/cnb_capacity.sh perf/cnb_extended_capacity_matrix.sh perf/k6/oauth.js perf/runner.py perf/seed.py docs/performance/reports/extended/performance-capacity-curve-extended-*.md
  if git diff --cached --quiet; then
    echo "No extended capacity changes to commit."
  else
    git commit -m "Record CNB extended capacity matrix"
    push_capacity_commit
  fi
else
  echo "No extended capacity reports were generated."
  status=1
fi

exit "${status}"
