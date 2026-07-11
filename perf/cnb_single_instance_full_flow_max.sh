#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

mkdir -p docs/performance perf/results

cpusets_file="perf/results/single-instance-full-flow-max-cpusets.txt"
python3 - "${SINGLE_INSTANCE_MAX_CPU_RESERVE:-0}" >"${cpusets_file}" <<'PY'
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
if len(cpus) < 2:
    raise SystemExit("single-instance max test requires at least two allowed CPUs")
if reserve > 0 and len(cpus) > reserve + 2:
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

split_at = max(1, len(cpus) // 2)
app = cpus[:split_at]
infra = cpus[split_at:]
if not infra:
    raise SystemExit("single-instance max test requires a non-empty infra CPU set")
print(fmt(app))
print(fmt(infra))
PY

app_cpuset="$(sed -n '1p' "${cpusets_file}")"
infra_cpuset="$(sed -n '2p' "${cpusets_file}")"

scenario="${SINGLE_INSTANCE_MAX_SCENARIO:-oidc_cold_login_refresh}"
rates="${SINGLE_INSTANCE_MAX_RATES:-16,32,64,96,128,192,256,384,512}"
duration="${SINGLE_INSTANCE_MAX_DURATION:-2m}"
max_vus="${SINGLE_INSTANCE_MAX_MAX_VUS:-4096}"
suffix="${SINGLE_INSTANCE_MAX_SUFFIX:-single-instance-full-flow-max}"

export CAPACITY_SCENARIOS="${scenario}"
export CAPACITY_RATES="${rates}"
export CAPACITY_DURATION="${duration}"
export CAPACITY_INSTANCES="1"
export CAPACITY_MAX_VUS="${max_vus}"
export CAPACITY_REPORT_SUFFIX="${suffix}"
export PERF_APP_CPUSET="${app_cpuset}"
export PERF_APP_TASKSET="${app_cpuset}"
export PERF_INFRA_CPUSET="${infra_cpuset}"
export CNB_CAPACITY_COMMIT="${SINGLE_INSTANCE_MAX_COMMIT:-0}"

echo "single-instance full-flow max capacity test"
echo "scenario=${scenario}"
echo "rates=${rates}"
echo "duration=${duration}"
echo "instances=1"
echo "max_vus=${max_vus}"
echo "app_cpuset=${PERF_APP_CPUSET}"
echo "infra_cpuset=${PERF_INFRA_CPUSET}"
echo "report=docs/performance/reports/special/performance-capacity-curve-${suffix}.md"
echo "results=perf/results/capacity-${suffix}.json"

./perf/cnb_capacity.sh
