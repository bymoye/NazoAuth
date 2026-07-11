#!/usr/bin/env sh
set -eu

if [ "${CNB_CAPACITY_SKIP_BOOTSTRAP:-0}" != "1" ]; then
  . ./perf/cnb_bootstrap.sh
  install_capacity_dependencies
  docker compose version >/dev/null
fi

scenario="${APP_CPU_CAPACITY_SCENARIO:-token_only_client_credentials}"
rates="${APP_CPU_CAPACITY_RATES:-1000,2000}"
duration="${APP_CPU_CAPACITY_DURATION:-2m}"
instances="${APP_CPU_CAPACITY_INSTANCES:-1}"
app_cpus="${APP_CPU_CAPACITY_APP_CPUS:-1}"
suffix="${APP_CPU_CAPACITY_SUFFIX:-app-cpu-${app_cpus}vcpu-smoke}"
max_vus="${APP_CPU_CAPACITY_MAX_VUS:-512}"

export CAPACITY_SCENARIOS="${scenario}"
export CAPACITY_RATES="${rates}"
export CAPACITY_DURATION="${duration}"
export CAPACITY_INSTANCES="${instances}"
export CAPACITY_REPORT_SUFFIX="${suffix}"
export PERF_APP_CPUS="${app_cpus}"
export CNB_CAPACITY_COMMIT="${CNB_CAPACITY_COMMIT:-0}"
export CAPACITY_MAX_VUS="${max_vus}"

if [ -n "${APP_CPU_CAPACITY_INFRA_CPUSET:-}" ]; then
  export PERF_INFRA_CPUSET="${APP_CPU_CAPACITY_INFRA_CPUSET}"
fi

if [ -n "${APP_CPU_CAPACITY_APP_CPUSET:-}" ]; then
  export PERF_APP_CPUSET="${APP_CPU_CAPACITY_APP_CPUSET}"
fi

if [ -n "${APP_CPU_CAPACITY_APP_TASKSET:-}" ]; then
  export PERF_APP_TASKSET="${APP_CPU_CAPACITY_APP_TASKSET}"
fi

echo "app CPU capacity smoke"
echo "scenario=${scenario}"
echo "rates=${rates}"
echo "duration=${duration}"
echo "instances=${instances}"
echo "app_cpus=${app_cpus}"
echo "max_vus=${max_vus}"
echo "app_cpuset=${PERF_APP_CPUSET:-unrestricted}"
echo "infra_cpuset=${PERF_INFRA_CPUSET:-unrestricted}"
echo "app_taskset=${PERF_APP_TASKSET:-disabled}"

./perf/cnb_capacity.sh
