#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

SCENARIOS="${CAPACITY_SCENARIOS:-token_only_client_credentials,oidc_cold_login_refresh,oidc_logged_in_authorization_code,oidc_refresh_only,fapi2_full_security}"
REPORT_SUFFIX="${CAPACITY_REPORT_SUFFIX:-full}"
DURATION="${CAPACITY_DURATION:-30m}"
INSTANCES="${CAPACITY_INSTANCES:-1,2,4}"
RATES="${CAPACITY_RATES:-}"
MAX_VUS="${CAPACITY_MAX_VUS:-512}"
case "${REPORT_SUFFIX}" in
  dev-*) REPORT="docs/performance/archive/dev/performance-capacity-curve-${REPORT_SUFFIX}.md" ;;
  extended-*) REPORT="docs/performance/reports/extended/performance-capacity-curve-${REPORT_SUFFIX}.md" ;;
  app-cpu-*|single-instance-*) REPORT="docs/performance/reports/special/performance-capacity-curve-${REPORT_SUFFIX}.md" ;;
  *) REPORT="docs/performance/reports/main/performance-capacity-curve-${REPORT_SUFFIX}.md" ;;
esac
ENV_REPORT="perf/results/cnb-environment-${REPORT_SUFFIX}.md"
export CAPACITY_ENV_REPORT_PATH="${ENV_REPORT}"
if [ "${CNB_CAPACITY_COMMIT:-1}" = "0" ]; then
  export CAPACITY_CHECKPOINT_COMMIT="${CAPACITY_CHECKPOINT_COMMIT:-0}"
else
  export CAPACITY_CHECKPOINT_COMMIT="${CAPACITY_CHECKPOINT_COMMIT:-1}"
fi
COMPOSE_PROJECT_NAME="$(printf 'nazoauth-%s-%s' "${CNB_BUILD_ID:-local}" "${REPORT_SUFFIX}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-' | cut -c1-63)"
export COMPOSE_PROJECT_NAME

mkdir -p "$(dirname "${REPORT}")" perf/results

LEGACY_CPUSET="${PERF_CPUSET:-}"
APP_CPUSET="${PERF_APP_CPUSET:-${LEGACY_CPUSET}}"
INFRA_CPUSET="${PERF_INFRA_CPUSET:-${LEGACY_CPUSET}}"
APP_CPUS="${PERF_APP_CPUS:-}"
APP_TASKSET="${PERF_APP_TASKSET:-}"

write_service_override() {
  service="$1"
  cpuset="$2"
  cpus="$3"
  taskset_cpu="$4"
  echo "  ${service}:"
  if [ -n "${cpuset}" ]; then
    echo "    cpuset: \"${cpuset}\""
  fi
  if [ -n "${cpus}" ]; then
    echo "    cpus: \"${cpus}\""
  fi
  if [ "${service}" = "nazoauth" ] && [ -n "${taskset_cpu}" ]; then
    echo "    command: [\"taskset\", \"-c\", \"${taskset_cpu}\", \"nazo-oauth-server\"]"
  fi
}

if [ -n "${LEGACY_CPUSET}" ] || [ -n "${APP_CPUSET}" ] || [ -n "${INFRA_CPUSET}" ] || [ -n "${APP_CPUS}" ] || [ -n "${APP_TASKSET}" ]; then
  PERF_COMPOSE_OVERRIDE="perf/results/docker-compose.cpuset-${REPORT_SUFFIX}.yml"
  export PERF_COMPOSE_OVERRIDE
  {
    echo "services:"
    write_service_override postgres "${INFRA_CPUSET}" "" ""
    write_service_override valkey "${INFRA_CPUSET}" "" ""
    write_service_override nazoauth "${APP_CPUSET}" "${APP_CPUS}" "${APP_TASKSET}"
    write_service_override keyset "${INFRA_CPUSET}" "" ""
    write_service_override migrate "${INFRA_CPUSET}" "" ""
    write_service_override perf "${INFRA_CPUSET}" "" ""
  } >"${PERF_COMPOSE_OVERRIDE}"
fi

cpuset_count() {
  python3 - "$1" <<'PY'
import sys

value = sys.argv[1]
if not value:
    print("unrestricted")
    raise SystemExit

count = 0
for part in value.split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(item) for item in part.split("-", 1)]
        count += end - start + 1
    else:
        count += 1
print(count)
PY
}

if [ -n "${LEGACY_CPUSET}" ]; then
  CPUSET_VALUE="${LEGACY_CPUSET}"
  CPUSET_CORES="$(cpuset_count "${LEGACY_CPUSET}")"
else
  CPUSET_VALUE="${APP_CPUSET:+app=${APP_CPUSET}; }${INFRA_CPUSET:+infra=${INFRA_CPUSET}}"
  CPUSET_VALUE="${CPUSET_VALUE:-unrestricted}"
  CPUSET_CORES="app=$(cpuset_count "${APP_CPUSET}"), infra=$(cpuset_count "${INFRA_CPUSET}")"
fi

APP_CPUSET_VALUE="${APP_CPUSET:-unrestricted}"
APP_CPUSET_CORES="$(cpuset_count "${APP_CPUSET}")"
INFRA_CPUSET_VALUE="${INFRA_CPUSET:-unrestricted}"
INFRA_CPUSET_CORES="$(cpuset_count "${INFRA_CPUSET}")"
APP_CPUS_VALUE="${APP_CPUS:-unlimited}"
APP_TASKSET_VALUE="${APP_TASKSET:-disabled}"

if [ -n "${PERF_COMPOSE_OVERRIDE:-}" ]; then
  COMPOSE_FILES_VALUE="docker-compose.perf.yml + ${PERF_COMPOSE_OVERRIDE}"
else
  COMPOSE_FILES_VALUE="docker-compose.perf.yml"
fi

LEGACY_PIN_TEXT="postgres, valkey, keyset, migrate, nazoauth, perf"
if [ -n "${LEGACY_CPUSET}" ]; then
  PIN_TEXT="${LEGACY_PIN_TEXT}"
else
  PIN_TEXT="nazoauth:${APP_CPUSET_VALUE} quota=${APP_CPUS_VALUE} taskset=${APP_TASKSET_VALUE}; postgres,valkey,keyset,migrate,perf:${INFRA_CPUSET_VALUE}"
fi

if [ -n "${APP_TASKSET}" ]; then
  CPU_MODEL_TEXT="NazoAuth is started through taskset on CPU ${APP_TASKSET}. Docker cpus/cpuset fields are still recorded, but process CPU affinity is the effective app CPU limiter in CNB nested Docker."
elif [ -n "${APP_CPUS}" ]; then
  CPU_MODEL_TEXT="NazoAuth has a Docker CPU quota of ${APP_CPUS} CPU(s). PostgreSQL, Valkey, keyset, migrate, and perf use the infra CPU set and are not CPU-quota limited by this override."
elif [ -n "${LEGACY_CPUSET}" ]; then
  CPU_MODEL_TEXT="Docker cpuset isolation; no CPU quota. Each service container may run on the listed CPU set. NazoAuth is additionally scaled by the stage instance count."
else
  CPU_MODEL_TEXT="Docker cpuset isolation where configured; no CPU quota unless App CPU quota is set. NazoAuth is additionally scaled by the stage instance count."
fi

{
  echo "## Test Environment and Topology"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| Source commit | ${CNB_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)} |"
  echo "| Runner tag | cnb:arch:amd64 |"
  echo "| Requested runner CPUs | 64 |"
  echo "| Observed logical CPUs | $(nproc --all 2>/dev/null || echo unknown) |"
  echo "| Process allowed CPUs | $(awk -F':\t' '/Cpus_allowed_list/ { print $2; exit }' /proc/self/status 2>/dev/null || echo unknown) |"
  echo "| Observed CPU model | $(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null | sed 's/|/-/g' || echo unknown) |"
  echo "| Cgroup CPU max | $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown) |"
  echo "| Memory total | $(awk '/MemTotal/ { printf \"%.2f GiB\", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || echo unknown) |"
  echo "| Cgroup memory max | $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown) |"
  echo "| Workspace disk available | $(df -h . 2>/dev/null | awk 'NR==2 { print $4 " on " $6 }' || echo unknown) |"
  echo "| Kernel | $(uname -a | sed 's/|/-/g') |"
  echo "| Docker server | $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown) |"
  echo "| Docker compose | $(docker compose version --short 2>/dev/null || echo unknown) |"
  echo "| Compose project | ${COMPOSE_PROJECT_NAME} |"
  echo "| Compose files | ${COMPOSE_FILES_VALUE} |"
  echo "| CPU set | ${CPUSET_VALUE} |"
  echo "| CPU set size | ${CPUSET_CORES} |"
  echo "| App CPU set | ${APP_CPUSET_VALUE} |"
  echo "| App CPU set size | ${APP_CPUSET_CORES} |"
  echo "| App CPU quota | ${APP_CPUS_VALUE} |"
  echo "| App process taskset | ${APP_TASKSET_VALUE} |"
  echo "| Infra CPU set | ${INFRA_CPUSET_VALUE} |"
  echo "| Infra CPU set size | ${INFRA_CPUSET_CORES} |"
  echo "| Services pinned to CPU set | ${PIN_TEXT} |"
  echo "| Per-container CPU model | ${CPU_MODEL_TEXT} |"
  echo "| Capacity scenarios | ${SCENARIOS} |"
  echo "| Duration per point | ${DURATION} |"
  echo "| App instance stages | ${INSTANCES} NazoAuth replica(s) |"
  echo "| Explicit rates | ${RATES:-scenario defaults} |"
  echo "| k6 max VUs | ${MAX_VUS} |"
  echo "| Load executor | k6 constant-arrival-rate, time unit 1s |"
  echo "| Token-only target rates | 1000, 2500, 5000, 7500, 10000 flow/s |"
  echo "| OIDC cold/login and logged-in target rates | 16, 32, 64, 128, 256 flow/s |"
  echo "| OIDC refresh-only target rates | 250, 500, 1000, 1500, 2000 flow/s |"
  echo "| FAPI2 full-security target rates | 16, 32, 64, 128, 256 flow/s |"
  echo "| Network topology | Single Docker bridge network; perf runner reaches NazoAuth at http://nazoauth:8000; NazoAuth reaches PostgreSQL and Valkey inside the same network. |"
  echo "| PostgreSQL container | docker.io/library/postgres:18-alpine; pg_stat_statements enabled; track_io_timing enabled; ephemeral Docker volume. |"
  echo "| Valkey container | docker.io/valkey/valkey:8-alpine; RDB save disabled; AOF disabled; warning log level; ephemeral state for benchmark isolation. |"
  echo "| NazoAuth container | Built from local Containerfile target runtime; PERF_METRICS_ENABLED=true; runtime key volume shared with keyset/migrate. |"
  echo "| Key material setup | keyset service generates runtime RS256 and PS256 keys before migration and benchmark traffic. |"
  echo "| Migration setup | migrate service runs nazo-oauth-migrate before the NazoAuth service is considered ready for benchmark traffic. |"
  echo "| Perf runner | Built from perf/runner/Containerfile; mounts Docker socket for container stats; writes Markdown reports under docs/performance/reports/ and runtime JSON/logs to ignored perf/results/. |"
  echo "| Metrics sources | k6 HTTP metrics; Docker stats CPU/memory samples; PostgreSQL pg_stat_statements; NazoAuth DB pool metrics; Valkey INFO counters. |"
  echo
} >"${ENV_REPORT}"

set +e
if [ -n "${RATES}" ]; then
  python3 perf/capacity.py \
    --duration "${DURATION}" \
    --instances "${INSTANCES}" \
    --scenarios "${SCENARIOS}" \
    --rates "${RATES}" \
    --max-vus "${MAX_VUS}" \
    --report-path "${REPORT}" \
    --results-path "perf/results/capacity-${REPORT_SUFFIX}.json"
else
  python3 perf/capacity.py \
    --duration "${DURATION}" \
    --instances "${INSTANCES}" \
    --scenarios "${SCENARIOS}" \
    --max-vus "${MAX_VUS}" \
    --report-path "${REPORT}" \
    --results-path "perf/results/capacity-${REPORT_SUFFIX}.json"
fi
status=$?
set -e

python3 - "${ENV_REPORT}" "${REPORT}" "${status}" <<'PY'
import sys
import re
import os
from pathlib import Path

env_path = Path(sys.argv[1])
target_path = Path(sys.argv[2])
status = int(sys.argv[3])

env_source = env_path.read_text(encoding="utf-8")
fields = {}
for line in env_source.splitlines():
    if not line.startswith("| ") or line.startswith("| ---"):
        continue
    cells = [cell.strip() for cell in line.strip("|").split("|")]
    if len(cells) == 2:
        fields[cells[0]] = cells[1]

suffix = env_path.stem.removeprefix("cnb-environment-")
results_path = Path("perf") / "results" / f"capacity-{suffix}.json"
report_dir = target_path.parent
env_link = Path(os.path.relpath(env_path, report_dir)).as_posix()
results_link = Path(os.path.relpath(results_path, report_dir)).as_posix()
evidence_rows = [
    ("Source commit", fields.get("Source commit", "unknown")),
    ("Scenario(s)", fields.get("Capacity scenarios", "unknown")),
    ("Duration", fields.get("Duration per point", "unknown")),
    ("App instance stages", fields.get("App instance stages", "unknown")),
    ("Target rates", fields.get("Explicit rates", "scenario defaults")),
    ("CPU set", fields.get("CPU set", "unknown")),
    ("Environment capture", f"[{env_link}]({env_link})"),
    ("Results JSON", f"[{results_link}]({results_link})"),
]
evidence = "\n".join([
    "## Evidence",
    "",
    "| Field | Value |",
    "| --- | --- |",
    *[f"| {field} | {value} |" for field, value in evidence_rows],
    "",
])

if target_path.exists():
    source = target_path.read_text(encoding="utf-8")
else:
    source = "\n".join([
        "# NazoAuth Capacity Curve Benchmarks",
        "",
        "No successful capacity point completed before the run failed.",
        "",
    ])
source = re.sub(
    r"\n## Test Environment(?: and Topology)?\n\n\| Field \| Value \|\n\| --- \| --- \|\n(?:\| .* \| .* \|\n)+\n",
    "\n",
    source,
)
source = re.sub(r"\n## Notes\n\n(?:- .*\n)+", "\n", source)
marker = "\n## Run Configuration\n"
if marker in source:
    if "\n## Evidence\n" in source:
        source = re.sub(r"\n## Evidence\n\n\| Field \| Value \|\n\| --- \| --- \|\n(?:\| .* \| .* \|\n)+\n", "\n" + evidence, source, count=1)
    else:
        source = source.replace(marker, "\n" + evidence + "## Run Configuration\n", 1)
else:
    source = source.rstrip() + "\n\n" + evidence
if status != 0:
    source = source.rstrip() + "\n\n## Run Status\n\n"
    source += f"- CNB capacity run failed with exit code `{status}` before completing the full matrix.\n"
    source += "- This report may contain only successful points completed before the failure.\n"
target_path.write_text(source, encoding="utf-8", newline="\n")
PY

if [ "${CNB_CAPACITY_COMMIT:-1}" = "0" ]; then
  exit "${status}"
fi

git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
git add "${REPORT}"
if git diff --cached --quiet; then
  echo "No capacity report changes to commit."
  exit "${status}"
fi

git commit -m "Record CNB capacity curve ${REPORT_SUFFIX}"

BRANCH="${CNB_BRANCH:-main}"
for attempt in 1 2 3; do
  if git pull --rebase origin "${BRANCH}" && git push origin "HEAD:${BRANCH}"; then
    exit "${status}"
  fi
  sleep $((attempt * 10))
done

git push origin "HEAD:${BRANCH}"
exit "${status}"
