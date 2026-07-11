#!/usr/bin/env sh
set -eu

echo "capacity matrix bootstrap started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "checking capacity matrix dependencies: coreutils git jq python3"
. ./perf/cnb_bootstrap.sh
install_capacity_dependencies
echo "dependency installation completed"
echo "docker compose version: $(docker compose version --short 2>/dev/null || docker compose version)"
docker compose version >/dev/null

mkdir -p docs/performance perf/results
children_file="perf/results/cnb-capacity-children.txt"
cpusets_file="perf/results/cnb-capacity-cpusets.txt"
: >"${children_file}"

python3 - "${PERF_CPU_RESERVE:-4}" >"${cpusets_file}" <<'PY'
import sys
from pathlib import Path

reserve = int(sys.argv[1])
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
if not cpus:
    raise SystemExit("no allowed CPUs detected")

if len(cpus) > reserve + 5:
    cpus = cpus[:-reserve]

groups = 5
base = len(cpus) // groups
extra = len(cpus) % groups
offset = 0

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

for index in range(groups):
    size = base + (1 if index < extra else 0)
    if size <= 0:
        chunk = cpus
    else:
        chunk = cpus[offset : offset + size]
        offset += size
    print(fmt(chunk))
PY

token_cpuset="$(sed -n '1p' "${cpusets_file}")"
oidc_cold_cpuset="$(sed -n '2p' "${cpusets_file}")"
oidc_logged_cpuset="$(sed -n '3p' "${cpusets_file}")"
oidc_refresh_cpuset="$(sed -n '4p' "${cpusets_file}")"
fapi2_logged_cpuset="$(sed -n '5p' "${cpusets_file}")"

echo "using capacity CPU sets derived from /proc/self/status:"
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

capacity_report_path() {
  suffix="$1"
  echo "docs/performance/reports/main/performance-capacity-curve-${suffix}.md"
}

commit_capacity_report() {
  suffix="$1"
  report="$(capacity_report_path "${suffix}")"
  results="perf/results/capacity-${suffix}.json"
  env_report="perf/results/cnb-environment-${suffix}.md"
  if [ ! -f "${report}" ]; then
    echo "capacity report not found for ${suffix}: ${report}"
    return 0
  fi
  git add "${report}"
  [ -f "${results}" ] && git add -f "${results}" || true
  [ -f "${env_report}" ] && git add -f "${env_report}" || true
  if git diff --cached --quiet; then
    echo "No capacity report changes to commit for ${suffix}."
    return 0
  fi
  git commit -m "Record CNB capacity curve ${suffix}"
  push_capacity_commit
}

remove_capacity_report_outputs() {
  suffix="$1"
  rm -f \
    "$(capacity_report_path "${suffix}")" \
    "perf/results/capacity-${suffix}.json" \
    "perf/results/cnb-environment-${suffix}.md"
}

run_capacity_child() {
  scenario="$1"
  suffix="$2"
  cpu_set="$3"
  duration="$4"
  rates="$5"
  instances="$6"
  log_path="perf/results/cnb-capacity-${suffix}.log"

  echo "starting capacity scenario ${scenario} duration=${duration} rates=${rates} instances=${instances} on CPUs ${cpu_set} -> ${log_path}"
  (
    export CAPACITY_SCENARIOS="${scenario}"
    export CAPACITY_REPORT_SUFFIX="${suffix}"
    export PERF_CPUSET="${cpu_set}"
    export CAPACITY_DURATION="${duration}"
    export CAPACITY_RATES="${rates}"
    export CAPACITY_INSTANCES="${instances}"
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export CNB_CAPACITY_COMMIT=0
    ./perf/cnb_capacity.sh
  ) >"${log_path}" 2>&1 &
  echo "$! ${suffix} ${log_path}" >>"${children_file}"
}

report_child_logs() {
  interval_seconds="${CAPACITY_LOG_INTERVAL_SECONDS:-60}"
  tail_lines="${CAPACITY_LOG_TAIL_LINES:-20}"
  while :; do
    running=0
    echo "capacity matrix heartbeat $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    while read -r pid suffix log_path; do
      if [ -z "${pid}" ]; then
        continue
      fi
      state="exited"
      if kill -0 "${pid}" 2>/dev/null; then
        state="running"
        running=1
      fi
      log_lines="$(wc -l <"${log_path}" 2>/dev/null || echo 0)"
      echo "[${suffix}] pid=${pid} state=${state} log_lines=${log_lines} log=${log_path}"
      if [ -s "${log_path}" ]; then
        echo "[${suffix}] last ${tail_lines} log lines:"
        tail -n "${tail_lines}" "${log_path}" | sed "s/^/[${suffix}] /" || true
      fi
    done <"${children_file}"
    if [ "${running}" -eq 0 ]; then
      break
    fi
    sleep "${interval_seconds}"
  done
}

wait_capacity_group() {
  group_name="$1"
  group_status=0

  report_child_logs &
  reporter_pid="$!"

  while read -r pid suffix log_path; do
    if [ -z "${pid}" ]; then
      continue
    fi
    if wait "${pid}"; then
      echo "capacity ${group_name} scenario ${suffix} completed"
      commit_capacity_report "${suffix}"
    else
      child_status=$?
      group_status=1
      echo "capacity ${group_name} scenario ${suffix} failed with exit code ${child_status}"
      echo "last log lines for ${suffix}:"
      tail -n 120 "${log_path}" || true
      remove_capacity_report_outputs "${suffix}"
    fi
  done <"${children_file}"

  kill "${reporter_pid}" 2>/dev/null || true
  wait "${reporter_pid}" 2>/dev/null || true
  return "${group_status}"
}

status=0

echo "starting short capacity group in parallel"
: >"${children_file}"
short_duration="${CAPACITY_SHORT_DURATION:-5m}"
short_instances="${CAPACITY_SHORT_INSTANCES:-1,2,4}"
run_capacity_child token_only_client_credentials token-only-short "${token_cpuset}" "${short_duration}" "${CAPACITY_SHORT_TOKEN_RATES:-1000,2500,5000}" "${short_instances}"
run_capacity_child oidc_cold_login_refresh oidc-cold-login-short "${oidc_cold_cpuset}" "${short_duration}" "${CAPACITY_SHORT_OIDC_COLD_RATES:-16,32,64}" "${short_instances}"
run_capacity_child oidc_logged_in_authorization_code oidc-logged-in-short "${oidc_logged_cpuset}" "${short_duration}" "${CAPACITY_SHORT_OIDC_LOGGED_RATES:-16,32,64}" "${short_instances}"
run_capacity_child oidc_refresh_only oidc-refresh-only-short "${oidc_refresh_cpuset}" "${short_duration}" "${CAPACITY_SHORT_REFRESH_RATES:-250,500,1000}" "${short_instances}"
run_capacity_child fapi2_logged_in_high_security fapi2-logged-in-high-security-short "${fapi2_logged_cpuset}" "${short_duration}" "${CAPACITY_SHORT_FAPI2_RATES:-16,32,64}" "${short_instances}"
if wait_capacity_group short; then
  echo "short capacity group completed"
else
  status=1
  echo "short capacity group had failures"
fi

echo "starting long capacity group in parallel"
: >"${children_file}"
long_duration="${CAPACITY_DURATION:-30m}"
long_instances="${CAPACITY_INSTANCES:-1,2,4}"
run_capacity_child token_only_client_credentials token-only "${token_cpuset}" "${long_duration}" "1000,2500,5000,7500,10000" "${long_instances}"
run_capacity_child oidc_logged_in_authorization_code oidc-logged-in "${oidc_logged_cpuset}" "${long_duration}" "16,32,64,128,256" "${long_instances}"
run_capacity_child oidc_refresh_only oidc-refresh-only "${oidc_refresh_cpuset}" "${long_duration}" "250,500,1000,1500,2000" "${long_instances}"
run_capacity_child fapi2_logged_in_high_security fapi2-logged-in-high-security "${fapi2_logged_cpuset}" "${long_duration}" "16,32,64,128,256" "${long_instances}"
if wait_capacity_group long; then
  echo "long capacity group completed"
else
  status=1
  echo "long capacity group had failures"
fi

if [ "${status}" -eq 0 ] && find docs/performance/reports/main -maxdepth 1 -name 'performance-capacity-curve-*.md' -print -quit | grep -q .; then
  git add docs/performance/reports/main/performance-capacity-curve-*.md
  if git diff --cached --quiet; then
    echo "No capacity report changes to commit."
  else
    git commit -m "Record CNB capacity curve matrix"

    push_capacity_commit
  fi
else
  if [ "${status}" -eq 0 ]; then
    echo "No capacity reports were generated."
    status=1
  else
    echo "Capacity matrix had failures; not committing aggregate reports."
  fi
fi

exit "${status}"
