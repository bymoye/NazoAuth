#!/usr/bin/env sh
set -eu

apk add --no-cache coreutils git jq python3 >/dev/null
docker compose version >/dev/null

mkdir -p docs perf/results
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
    allowed = f"0-{max(0, (Path('/proc/cpuinfo').read_text(encoding='utf-8').count('processor\t:') or 1) - 1)}"

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
fapi2_cpuset="$(sed -n '5p' "${cpusets_file}")"

echo "using capacity CPU sets:"
cat "${cpusets_file}"

run_capacity_child() {
  scenario="$1"
  suffix="$2"
  cpu_set="$3"
  log_path="perf/results/cnb-capacity-${suffix}.log"

  echo "starting capacity scenario ${scenario} on CPUs ${cpu_set} -> ${log_path}"
  (
    export CAPACITY_SCENARIOS="${scenario}"
    export CAPACITY_REPORT_SUFFIX="${suffix}"
    export PERF_CPUSET="${cpu_set}"
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export CNB_CAPACITY_COMMIT=0
    ./perf/cnb_capacity.sh
  ) >"${log_path}" 2>&1 &
  echo "$! ${suffix} ${log_path}" >>"${children_file}"
}

run_capacity_child token_only_client_credentials token-only "${token_cpuset}"
run_capacity_child oidc_cold_login_refresh oidc-cold-login "${oidc_cold_cpuset}"
run_capacity_child oidc_logged_in_authorization_code oidc-logged-in "${oidc_logged_cpuset}"
run_capacity_child oidc_refresh_only oidc-refresh-only "${oidc_refresh_cpuset}"
run_capacity_child fapi2_full_security fapi2-full-security "${fapi2_cpuset}"

status=0
while read -r pid suffix log_path; do
  if [ -z "${pid}" ]; then
    continue
  fi
  if wait "${pid}"; then
    echo "capacity scenario ${suffix} completed"
  else
    child_status=$?
    status=1
    echo "capacity scenario ${suffix} failed with exit code ${child_status}"
    echo "last log lines for ${suffix}:"
    tail -n 120 "${log_path}" || true
  fi
done <"${children_file}"

if find docs -maxdepth 1 -name 'performance-capacity-curve-*.md' -print -quit | grep -q .; then
  git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
  git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
  git add docs/performance-capacity-curve-*.md
  if git diff --cached --quiet; then
    echo "No capacity report changes to commit."
  else
    git commit -m "Record CNB capacity curve matrix"

    BRANCH="${CNB_BRANCH:-main}"
    for attempt in 1 2 3; do
      if git pull --rebase origin "${BRANCH}" && git push origin "HEAD:${BRANCH}"; then
        exit "${status}"
      fi
      sleep $((attempt * 10))
    done

    git push origin "HEAD:${BRANCH}"
  fi
else
  echo "No capacity reports were generated."
  status=1
fi

exit "${status}"
