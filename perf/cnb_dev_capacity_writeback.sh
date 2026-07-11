#!/usr/bin/env sh
set -eu
cd /workspace
LOG=perf/results/dev-capacity-writeback.log
MAIN_PID_FILE=perf/results/dev-capacity-matrix.pid
REPAIR_LOG=perf/results/dev-capacity-repair.log
REPAIR_PID_FILE=perf/results/dev-capacity-repair.pid
{
  echo "writeback watcher restarted for repair $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  main_pid=""
  if [ -s "$MAIN_PID_FILE" ]; then
    main_pid=$(cat "$MAIN_PID_FILE")
    echo "matrix pid: $main_pid"
  fi
  if [ -n "$main_pid" ]; then
    while kill -0 "$main_pid" 2>/dev/null; do
      sleep 60
    done
  fi
  repair_pid=""
  if [ -s "$REPAIR_PID_FILE" ]; then
    repair_pid=$(cat "$REPAIR_PID_FILE")
    echo "repair pid: $repair_pid"
  fi
  if [ -n "$repair_pid" ]; then
    while kill -0 "$repair_pid" 2>/dev/null; do
      sleep 60
    done
  fi
  final_repair_line=$(grep 'dev capacity repair finished' "$REPAIR_LOG" | tail -n 1 || true)
  echo "repair final line: $final_repair_line"
  case "$final_repair_line" in
    *'status=0'*) ;;
    *) echo "repair did not finish successfully; skip writeback"; exit 1 ;;
  esac
  echo "finalizing repaired capacity Markdown reports $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  python3 perf/finalize_capacity_reports.py
  git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
  git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
  git add perf/README.md perf/capacity.py perf/cnb_capacity.sh perf/cnb_extended_capacity_matrix.sh perf/finalize_capacity_reports.py perf/k6/oauth.js perf/runner.py perf/seed.py docs/performance/archive/dev/performance-capacity-curve-dev-*.md
  if git diff --cached --quiet; then
    echo "No capacity report changes to commit."
    echo "writeback pushed $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    exit 0
  fi
  git commit -m "Record CNB dev capacity curve matrix"
  branch=$(git branch --show-current 2>/dev/null || echo main)
  for attempt in 1 2 3; do
    echo "push attempt $attempt to $branch"
    if git pull --rebase origin "$branch" && git push origin "HEAD:$branch"; then
      echo "writeback pushed $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      exit 0
    fi
    sleep $((attempt * 10))
  done
  git push origin "HEAD:$branch"
  echo "writeback pushed after final attempt $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >>"$LOG" 2>&1
