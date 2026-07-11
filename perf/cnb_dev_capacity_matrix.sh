#!/usr/bin/env sh
set -eu

cd /workspace
mkdir -p docs/performance/archive/dev perf/results
children_file="perf/results/dev-capacity-children.txt"
cpusets_file="perf/results/dev-capacity-cpusets.txt"
: >"${children_file}"

printf 'dev capacity matrix started %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'commit: '
git rev-parse --short HEAD
printf 'docker: '
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
printf 'compose: '
docker compose version --short
printf 'nproc: '
nproc
printf 'memory: '
awk '/MemTotal/ { printf "%.2f GiB\n", $2 / 1024 / 1024 }' /proc/meminfo
printf 'disk: '
df -h /workspace | awk 'NR==2 { print $4 " available on " $6 }'

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
    cpuinfo = Path('/proc/cpuinfo').read_text(encoding='utf-8')
    processor_count = cpuinfo.count('processor') or 1
    allowed = "0-%d" % max(0, processor_count - 1)
cpus = []
for part in allowed.split(','):
    part = part.strip()
    if not part:
        continue
    if '-' in part:
        start, end = [int(value) for value in part.split('-', 1)]
        cpus.extend(range(start, end + 1))
    else:
        cpus.append(int(part))
cpus = sorted(set(cpus))
if len(cpus) > reserve + 5:
    cpus = cpus[:-reserve]

def fmt(values):
    ranges = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append(f"{start}-{previous}" if start != previous else str(start))
        start = previous = value
    ranges.append(f"{start}-{previous}" if start != previous else str(start))
    return ','.join(ranges)

groups = 5
base = len(cpus) // groups
extra = len(cpus) % groups
offset = 0
for index in range(groups):
    size = base + (1 if index < extra else 0)
    chunk = cpus[offset:offset + size] if size > 0 else cpus
    offset += max(size, 0)
    print(fmt(chunk))
PY

printf 'CPU sets:\n'
cat "${cpusets_file}"

run_child() {
  scenario="$1"
  suffix="$2"
  cpu_set="$3"
  log_path="perf/results/dev-capacity-${suffix}.log"
  printf 'starting %s on CPUs %s -> %s\n' "${scenario}" "${cpu_set}" "${log_path}"
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
  echo "$! ${suffix} ${log_path}" >>"${children_file}"
}

run_child token_only_client_credentials token-only "$(sed -n '1p' "${cpusets_file}")"
run_child oidc_cold_login_refresh oidc-cold-login "$(sed -n '2p' "${cpusets_file}")"
run_child oidc_logged_in_authorization_code oidc-logged-in "$(sed -n '3p' "${cpusets_file}")"
run_child oidc_refresh_only oidc-refresh-only "$(sed -n '4p' "${cpusets_file}")"
run_child fapi2_full_security fapi2-full-security "$(sed -n '5p' "${cpusets_file}")"

status=0
while :; do
  running=0
  printf 'heartbeat %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  while read -r pid suffix log_path; do
    [ -n "${pid}" ] || continue
    state=exited
    if kill -0 "${pid}" 2>/dev/null; then
      state=running
      running=1
    fi
    lines=$(wc -l <"${log_path}" 2>/dev/null || echo 0)
    printf '[%s] pid=%s state=%s lines=%s log=%s\n' "${suffix}" "${pid}" "${state}" "${lines}" "${log_path}"
    if [ -s "${log_path}" ]; then
      tail -n "${CAPACITY_LOG_TAIL_LINES:-15}" "${log_path}" | sed "s/^/[${suffix}] /" || true
    fi
  done <"${children_file}"
  [ "${running}" -eq 1 ] || break
  sleep "${CAPACITY_LOG_INTERVAL_SECONDS:-60}"
done

while read -r pid suffix log_path; do
  [ -n "${pid}" ] || continue
  if wait "${pid}"; then
    printf 'scenario %s completed\n' "${suffix}"
  else
    code=$?
    status=1
    printf 'scenario %s failed with exit code %s\n' "${suffix}" "${code}"
    tail -n 120 "${log_path}" || true
  fi
done <"${children_file}"

printf 'dev capacity matrix finished %s status=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${status}"
exit "${status}"
