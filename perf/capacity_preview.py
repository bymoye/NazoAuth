#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(os.environ.get('CAPACITY_PREVIEW_ROOT', os.getcwd())).resolve()
RESULTS = ROOT / 'perf' / 'results'
PORT = int(os.environ.get('CAPACITY_PREVIEW_PORT', '18080'))
START_TS = os.environ.get('CAPACITY_PREVIEW_STARTED_AT', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
MAIN_SCENARIOS = {
    'token-only-short': '短测：Token-only client_credentials',
    'token-only': 'Token-only：client_credentials',
    'oidc-cold-login-short': 'OIDC：冷登录短测 + 刷新',
    'oidc-logged-in-short': '短测：OIDC 已登录授权码',
    'oidc-logged-in': 'OIDC：已登录授权码',
    'oidc-refresh-only-short': '短测：OIDC 仅刷新令牌轮换',
    'oidc-refresh-only': 'OIDC：仅刷新令牌轮换',
    'fapi2-logged-in-high-security-short': '短测：FAPI2 已登录高安全完整流',
    'fapi2-logged-in-high-security': 'FAPI2：已登录高安全完整流',
}
MAIN_SCENARIO_IDS = {
    'token-only-short': 'token_only_client_credentials',
    'token-only': 'token_only_client_credentials',
    'oidc-cold-login-short': 'oidc_cold_login_refresh',
    'oidc-logged-in-short': 'oidc_logged_in_authorization_code',
    'oidc-logged-in': 'oidc_logged_in_authorization_code',
    'oidc-refresh-only-short': 'oidc_refresh_only',
    'oidc-refresh-only': 'oidc_refresh_only',
    'fapi2-logged-in-high-security-short': 'fapi2_logged_in_high_security',
    'fapi2-logged-in-high-security': 'fapi2_logged_in_high_security',
}
MAIN_DEFAULT_RATES = {
    'token-only-short': [1000, 2500, 5000],
    'token-only': [1000, 2500, 5000, 7500, 10000],
    'oidc-cold-login-short': [16, 32, 64],
    'oidc-logged-in-short': [16, 32, 64],
    'oidc-logged-in': [16, 32, 64, 128, 256],
    'oidc-refresh-only-short': [250, 500, 1000],
    'oidc-refresh-only': [250, 500, 1000, 1500, 2000],
    'fapi2-logged-in-high-security-short': [16, 32, 64],
    'fapi2-logged-in-high-security': [16, 32, 64, 128, 256],
}
EXTENDED_SCENARIOS = {
    'mtls-client-credentials': 'mTLS：client_credentials',
    'par-signed-request-object': 'PAR：签名请求对象',
    'introspect-opaque-refresh-token': 'Introspection：不透明刷新令牌',
    'authorize-par-session': 'Authorize：已登录会话 + PAR',
    'revoke-refresh-token': 'Revocation：刷新令牌撤销',
    'metadata-jwks': 'Discovery / JWKS',
    'ciba-private-key-jwt-dpop-poll': 'CIBA：private_key_jwt + DPoP poll',
    'same-user-refresh-token-rotation': '同用户：刷新令牌轮换',
    'same-user-introspect-opaque-refresh-token': '同用户：Introspection',
    'same-user-authorize-par-session': '同用户：Authorize + PAR',
}
EXTENDED_SCENARIO_IDS = {
    'mtls-client-credentials': 'mtls_client_credentials',
    'par-signed-request-object': 'par_signed_request_object',
    'introspect-opaque-refresh-token': 'introspect_opaque_refresh_token',
    'authorize-par-session': 'authorize_par_session',
    'revoke-refresh-token': 'revoke_refresh_token',
    'metadata-jwks': 'metadata_jwks',
    'ciba-private-key-jwt-dpop-poll': 'ciba_private_key_jwt_dpop_poll',
    'same-user-refresh-token-rotation': 'same_user_refresh_token_rotation',
    'same-user-introspect-opaque-refresh-token': 'same_user_introspect_opaque_refresh_token',
    'same-user-authorize-par-session': 'same_user_authorize_par_session',
}
EXTENDED_DEFAULT_RATES = {
    'mtls-client-credentials': [250, 500, 1000, 1500, 2000],
    'par-signed-request-object': [250, 500, 1000, 1500, 2000],
    'introspect-opaque-refresh-token': [16, 32, 64, 128, 256],
    'authorize-par-session': [16, 32, 64, 128, 256],
    'revoke-refresh-token': [16, 32, 64, 128, 256],
    'metadata-jwks': [250, 500, 1000, 1500, 2000],
    'ciba-private-key-jwt-dpop-poll': [16, 32, 64, 128, 256],
    'same-user-refresh-token-rotation': [8, 16, 32, 64, 128],
    'same-user-introspect-opaque-refresh-token': [8, 16, 32, 64, 128],
    'same-user-authorize-par-session': [8, 16, 32, 64, 128],
}
INSTANCES = [1, 2, 4]


def preview_mode() -> str:
    explicit = os.environ.get('CAPACITY_PREVIEW_MODE', '').strip().lower()
    if explicit in ('dev', 'main', 'extended'):
        return 'extended' if explicit == 'extended' else 'main'
    if (RESULTS / 'cnb-extended-capacity-children.txt').exists():
        return 'extended'
    if any(RESULTS.glob('capacity-extended-*.json')) or any(RESULTS.glob('cnb-extended-capacity-*.log')):
        return 'extended'
    return 'main'


MODE = preview_mode()
SCENARIOS = EXTENDED_SCENARIOS if MODE == 'extended' else MAIN_SCENARIOS
SCENARIO_IDS = EXTENDED_SCENARIO_IDS if MODE == 'extended' else MAIN_SCENARIO_IDS
DEFAULT_RATES = EXTENDED_DEFAULT_RATES if MODE == 'extended' else MAIN_DEFAULT_RATES
EXPECTED_POINTS = {key: len(INSTANCES) * len(DEFAULT_RATES[key]) for key in SCENARIOS}
LOG_PREFIX = 'cnb-extended-capacity' if MODE == 'extended' else 'cnb-capacity'
RESULT_PREFIX = 'capacity-extended' if MODE == 'extended' else 'capacity'
REPORT_PREFIX = 'performance-capacity-curve-extended' if MODE == 'extended' else 'performance-capacity-curve'
MATRIX_LOG = RESULTS / ('extended-capacity-matrix.log' if MODE == 'extended' else 'cnb-capacity-main-rerun.log')
WRITEBACK_LOG = RESULTS / ('extended-capacity-writeback.log' if MODE == 'extended' else 'cnb-capacity-main-rerun.log')
CHILDREN_FILE = RESULTS / ('cnb-extended-capacity-children.txt' if MODE == 'extended' else 'cnb-capacity-children.txt')


def run(args: list[str], timeout: float = 4.0) -> str:
    try:
        completed = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    except Exception as exc:
        return f'{type(exc).__name__}: {exc}'
    out = completed.stdout.strip()
    err = completed.stderr.strip()
    if completed.returncode != 0 and err:
        return (out + '\n' + err).strip()
    return out


def read_tail(path: Path, lines: int = 80) -> str:
    if not path.exists():
        return ''
    try:
        data = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception as exc:
        return f'failed to read {path}: {exc}'
    return '\n'.join(data[-lines:])


def json_file(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def fmt_num(value: object, digits: int = 3) -> str:
    if value is None or value == '':
        return '-'
    try:
        return f'{float(value):.{digits}f}'
    except Exception:
        return str(value)


def fmt_pct(value: object) -> str:
    if value is None or value == '':
        return '-'
    try:
        return f'{float(value) * 100:.3f}%'
    except Exception:
        return str(value)


def file_lines(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return sum(1 for _ in path.open('rb'))
    except Exception:
        return 0


def sanitize_log(text: str) -> str:
    hidden = (
        'Error response from daemon: No such container:',
        ' Error while Stopping',
        'GoError: oidc PAR failed: 400',
        'GoError: fapi PAR failed: 401',
        'PAR request rejected http_status=400',
        'PAR request rejected http_status=401',
        'client_assertion_rejected reason=decode_expired',
    )
    return '\n'.join(line for line in text.splitlines() if not any(marker in line for marker in hidden))


def docker_container_exists(name: str) -> bool:
    output = run(['docker', 'ps', '-a', '--format', '{{.Names}}'], 5)
    return name in set(output.splitlines())


def perf_container_name(key: str) -> str:
    if MODE == 'extended':
        return f'nazoauth-extended-capacity-{key}-perf-1'
    return f'nazoauth-local-{key}-perf-1'


def scenario_result_items() -> list[dict]:
    items: list[dict] = []
    for path in sorted(RESULTS.glob('capacity*.json')) + sorted(RESULTS.glob('capacity-*.summary.json')):
        data = json_file(path)
        if data is None:
            continue
        records = data if isinstance(data, list) else [data]
        for record in records:
            scenario = record.get('scenario')
            result = record.get('result', record)
            if not scenario or not isinstance(result, dict):
                continue
            k6 = result.get('k6', {})
            if not k6:
                continue
            items.append({
                'path': path,
                'mtime': path.stat().st_mtime,
                'scenario': scenario,
                'duration': record.get('duration', result.get('duration', '')),
                'rps': k6.get('rps', 0),
                'errors': k6.get('error_rate', 0),
                'requests': k6.get('http_reqs', 0),
                'p95': k6.get('latency_ms', {}).get('p95', 0),
            })
    return items


def latest_scenario_summary(key: str) -> str:
    scenario_id = SCENARIO_IDS[key]
    matches = [item for item in scenario_result_items() if item['scenario'] == scenario_id]
    if not matches:
        return ''
    item = max(matches, key=lambda value: value['mtime'])
    rel = item['path'].relative_to(ROOT)
    return (
        f"最近验证结果：{item['scenario']}\n"
        f"来源：{rel}\n"
        f"duration={item['duration']} | http_reqs={item['requests']} | "
        f"rps={float(item['rps']):.3f} | p95={float(item['p95']):.3f}ms | "
        f"error_rate={float(item['errors']):.6f}"
    )


def scenario_log_fallback(key: str, lines: int = 50) -> str:
    summary = latest_scenario_summary(key)
    if summary:
        return (
            '当前没有运行中的 perf 容器；容量矩阵未在执行。\n'
            '下方显示最近一次可解析结果，避免把旧失败日志误认为实时状态。\n\n'
            + summary
        )
    log = RESULTS / f'{LOG_PREFIX}-{key}.log'
    tail = sanitize_log(read_tail(log, lines * 3))
    tail = '\n'.join(tail.splitlines()[-lines:])
    if tail:
        return '当前没有运行中的 perf 容器；容量矩阵未在执行。\n\n最近持久化日志尾部：\n' + tail
    return '当前没有运行中的 perf 容器，也尚未找到该场景的持久化日志。'


def docker_perf_logs(key: str, lines: int = 50) -> str:
    name = perf_container_name(key)
    if not docker_container_exists(name):
        return scenario_log_fallback(key, lines)
    try:
        completed = subprocess.run(
            ['docker', 'logs', '--tail', str(lines), name],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except Exception as exc:
        return f'读取 k6 容器日志失败：{type(exc).__name__}: {exc}'
    output = '\n'.join(part for part in (completed.stdout, completed.stderr) if part).strip().replace('\r', '')
    if output:
        return output
    top = run(['docker', 'top', name, '-eo', 'pid,ppid,stat,rss,etime,args'], 5)
    env = run(['docker', 'exec', name, 'sh', '-lc', "env | sort | grep -E 'PERF_SCENARIO|PERF_RATE|PERF_DURATION|PERF_VUS|PERF_PRE_ALLOCATED_VUS|PERF_MAX_VUS|PERF_USER_COUNT|PERF_VECTOR_COUNT'"], 5)
    if 'k6 run' not in top:
        return 'k6 尚未启动；当前 perf 容器仍在 Python runner 准备阶段（通常是 seed / 预生成测试向量）。\n\n容器内进程：\n' + top + '\n\n压测参数：\n' + env
    return 'k6 进程已启动，但 Docker 日志暂为空。\n\n容器内进程：\n' + top + '\n\n压测参数：\n' + env


def sse_payload(line: str) -> bytes:
    return f"data: {json.dumps(line, ensure_ascii=False)}\n\n".encode('utf-8')


def log_path_for_stream(key: str) -> Path | None:
    if key == 'matrix':
        return MATRIX_LOG
    if key == 'writeback':
        return WRITEBACK_LOG
    if key in SCENARIOS:
        return RESULTS / f'{LOG_PREFIX}-{key}.log'
    return None


def write_sse_line(handler: BaseHTTPRequestHandler, line: str) -> bool:
    try:
        handler.wfile.write(sse_payload(line))
        handler.wfile.flush()
        return True
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        return False


def deleted_log_writer_message(path: Path) -> str:
    proc = Path('/proc')
    if not proc.exists():
        return ''
    target = f'{path} (deleted)'
    rows = []
    for item in proc.iterdir():
        if not item.name.isdigit():
            continue
        for fd in ('1', '2'):
            fd_path = item / 'fd' / fd
            try:
                if os.readlink(fd_path) != target:
                    continue
                cmdline = (item / 'cmdline').read_text(encoding='utf-8', errors='replace').replace('\0', ' ').strip()
                rows.append(f"pid={item.name} fd={fd} {cmdline[:180]}")
            except Exception:
                continue
    if not rows:
        return ''
    return (
        '日志路径当前不存在，但仍有运行进程写入已删除的旧日志 inode。\n'
        '这通常发生在运行中对工作区执行 git 更新或清理后；当前压测不受影响，但该主日志路径要等下一阶段重新创建后才能继续流式读取。\n'
        + '\n'.join(rows[:10])
    )


def stream_file_log(handler: BaseHTTPRequestHandler, path: Path, lines: int = 80) -> None:
    if path.exists():
        for line in sanitize_log(read_tail(path, lines)).splitlines():
            if not write_sse_line(handler, line):
                return
        try:
            position = path.stat().st_size
        except OSError:
            position = 0
    else:
        try:
            rel_path = path.relative_to(ROOT)
        except ValueError:
            rel_path = path
        message = deleted_log_writer_message(path) or f'等待日志文件生成：{rel_path}'
        if not write_sse_line(handler, message):
            return
        position = 0
    while True:
        try:
            if not path.exists():
                time.sleep(1)
                continue
            size = path.stat().st_size
            if size < position:
                position = 0
            with path.open('r', encoding='utf-8', errors='replace') as handle:
                handle.seek(position)
                chunk = handle.read()
                position = handle.tell()
            if chunk:
                for line in sanitize_log(chunk).splitlines():
                    if not write_sse_line(handler, line):
                        return
            else:
                if not write_sse_line(handler, ''):
                    return
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:
            if not write_sse_line(handler, f'日志流读取失败：{type(exc).__name__}: {exc}'):
                return
            time.sleep(2)


def stream_docker_or_file_log(handler: BaseHTTPRequestHandler, key: str) -> None:
    name = perf_container_name(key)
    if docker_container_exists(name):
        snapshot = docker_perf_logs(key, 80)
        for line in sanitize_log(snapshot).splitlines():
            if not write_sse_line(handler, line):
                return
        process = subprocess.Popen(
            ['docker', 'logs', '--tail', '0', '-f', name],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line = raw_line.rstrip('\r\n')
                if not write_sse_line(handler, line):
                    return
            write_sse_line(handler, '容器日志流已结束；切换到持久化日志文件。')
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
    path = log_path_for_stream(key)
    if path is None:
        write_sse_line(handler, '未知日志流。')
        return
    stream_file_log(handler, path)


def interesting_lines(path: Path, lines: int = 18) -> list[str]:
    return interesting_lines_from_text(sanitize_log(read_tail(path, 2000)), lines)


def interesting_lines_from_text(text: str, lines: int = 18) -> list[str]:
    patterns = re.compile(r'capacity point:|running \(|THRESHOLDS|TOTAL RESULTS|rps=|RuntimeError|command failed|exited with code [1-9]|OOM|Killed|panic|ERROR', re.I)
    return [line for line in text.splitlines() if patterns.search(line)][-lines:]


def planned_points(key: str) -> list[dict]:
    points = []
    index = 1
    for instances in INSTANCES:
        for rate in DEFAULT_RATES[key]:
            points.append({'index': index, 'instances': instances, 'rate': rate})
            index += 1
    return points


def result_records(path: Path) -> list[dict]:
    data = json_file(path)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def record_metrics(record: dict) -> dict:
    result = record.get('result', {}) if isinstance(record.get('result'), dict) else {}
    k6 = result.get('k6', {}) if isinstance(result.get('k6'), dict) else {}
    latency = k6.get('latency_ms', {}) if isinstance(k6.get('latency_ms'), dict) else {}
    containers = result.get('containers', {}) if isinstance(result.get('containers'), dict) else {}
    by_service = containers.get('by_service', {}) if isinstance(containers.get('by_service'), dict) else {}
    nazoauth = by_service.get('nazoauth', {}) if isinstance(by_service.get('nazoauth'), dict) else {}
    postgres_service = by_service.get('postgres', {}) if isinstance(by_service.get('postgres'), dict) else {}
    valkey_service = by_service.get('valkey', {}) if isinstance(by_service.get('valkey'), dict) else {}
    postgres = result.get('postgres', {}) if isinstance(result.get('postgres'), dict) else {}
    db_pool = result.get('db_pool', {}) if isinstance(result.get('db_pool'), dict) else {}
    valkey = result.get('valkey', {}) if isinstance(result.get('valkey'), dict) else {}
    hits = valkey.get('keyspace_hits')
    misses = valkey.get('keyspace_misses')
    hit_rate = None
    try:
        total = float(hits or 0) + float(misses or 0)
        hit_rate = float(hits or 0) / total if total else None
    except Exception:
        hit_rate = None
    app_cpu = nazoauth.get('cpu_percent_avg')
    app_cores = None
    try:
        app_cores = float(app_cpu) / 100.0
    except Exception:
        app_cores = None
    return {
        'instances': record.get('instances'),
        'target_rate': record.get('target_rate'),
        'http_rps': k6.get('rps'),
        'p50': latency.get('p50'),
        'p95': latency.get('p95'),
        'p99': latency.get('p99'),
        'error_rate': k6.get('error_rate'),
        'app_cores': app_cores,
        'pg_cpu': postgres_service.get('cpu_percent_avg'),
        'valkey_cpu': valkey_service.get('cpu_percent_avg'),
        'db_wait_avg': db_pool.get('wait_ms_avg'),
        'db_stmt_per_req': postgres.get('statements_per_http_request'),
        'valkey_hit_rate': hit_rate,
        'http_reqs': k6.get('http_reqs'),
    }


def completed_stage_rows(key: str, records: list[dict]) -> list[dict]:
    rows = []
    plan = planned_points(key)
    for offset, record in enumerate(records):
        planned = plan[offset] if offset < len(plan) else {'index': offset + 1, 'instances': record.get('instances'), 'rate': record.get('target_rate')}
        rows.append({'stage': planned['index'], **record_metrics(record)})
    return rows


def matrix_runtime_status() -> dict:
    processes = run(['sh', '-lc', "ps -eo pid,ppid,stat,pcpu,pmem,etime,cmd --sort=pid | grep -E 'dev_capacity_matrix|extended_capacity_matrix|cnb_capacity|capacity.py' | grep -v grep || true"], 3)
    tail = read_tail(MATRIX_LOG, 120)
    final_line = ''
    for line in tail.splitlines():
        if 'dev capacity matrix finished' in line:
            final_line = line
    if processes.strip():
        label = '矩阵运行中'
        complete = False
    elif 'status=0' in final_line:
        label = '完整完成'
        complete = True
    elif final_line:
        label = '失败或中断'
        complete = False
    else:
        label = '等待启动'
        complete = False
    writeback_log = read_tail(WRITEBACK_LOG, 80)
    if 'writeback pushed' in writeback_log:
        writeback = '已回写'
    elif 'matrix did not finish successfully' in writeback_log:
        writeback = '未回写（矩阵失败）'
    elif processes.strip():
        writeback = '等待矩阵完成'
    else:
        writeback = '等待回写确认'
    return {
        'label': label,
        'complete': complete,
        'processes': processes,
        'matrix_tail': tail,
        'writeback': writeback,
        'writeback_tail': writeback_log,
    }


def parse_k6_status(text: str) -> dict:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    status = {}
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        if 'iters/s' not in line:
            continue
        rate = re.search(r'([0-9]+(?:\.[0-9]+)?)\s+iters/s', line)
        progress = re.search(r'\[\s*([0-9]+)%\s*\]', line)
        vus = re.search(r'([0-9]+)/([0-9]+)\s+VUs', line)
        elapsed = re.search(r'([0-9]{2}m[0-9]{2}(?:\.[0-9]+)?s)/([0-9]+m[0-9]+s)', line)
        status.update({
            'rate': rate.group(1) if rate else '',
            'progress': progress.group(1) if progress else '',
            'vus': f"{vus.group(1)}/{vus.group(2)}" if vus else '',
            'elapsed': f"{elapsed.group(1)}/{elapsed.group(2)}" if elapsed else '',
        })
        if index > 0:
            prev = lines[index - 1]
            completed = re.search(r'([0-9]+)\s+complete', prev)
            interrupted = re.search(r'([0-9]+)\s+interrupted', prev)
            if completed:
                status['completed_iterations'] = completed.group(1)
            if interrupted:
                status['interrupted_iterations'] = interrupted.group(1)
        break
    return status


def scenario_process_running(key: str, matrix: dict) -> bool:
    processes = matrix.get('processes', '')
    return f'{RESULT_PREFIX}-{key}.json' in processes or f'{LOG_PREFIX}-{key}.log' in processes


def scenario_state(key: str, completed_points: int, k6_tail: str, matrix: dict, scenario_running: bool) -> dict:
    expected = EXPECTED_POINTS.get(key, 15)
    plan = planned_points(key)
    complete = completed_points >= expected
    if complete:
        scenario_status = '完整完成'
        result_label = f'完整完成 {completed_points}/{expected}'
        report_label = '完整报告，等待回写' if matrix['writeback'] != '已回写' else '完整报告，已回写'
        point_label = '全部压测点已完成'
        current_plan = None
    elif completed_points > 0:
        scenario_status = '场景运行中' if scenario_running else '等待后续阶段'
        result_label = f'阶段性结果 {completed_points}/{expected}'
        report_label = f'阶段性报告 {completed_points}/{expected}'
        next_point = min(completed_points + 1, expected)
        current_plan = plan[next_point - 1] if next_point - 1 < len(plan) else None
        if current_plan and scenario_running:
            point_label = f"当前第 {next_point}/{expected} 阶段：{current_plan['instances']} 实例 / {current_plan['rate']} flow/s"
        elif current_plan:
            point_label = f"等待第 {next_point}/{expected} 阶段：{current_plan['instances']} 实例 / {current_plan['rate']} flow/s"
        else:
            point_label = f'当前第 {next_point}/{expected} 阶段'
    else:
        scenario_status = '场景运行中' if scenario_running else '等待所属阶段'
        result_label = '等待首个结果'
        report_label = '等待首个报告'
        current_plan = plan[0] if plan else None
        if scenario_running and current_plan:
            point_label = f"当前第 1/{expected} 阶段：{current_plan['instances']} 实例 / {current_plan['rate']} flow/s"
        else:
            point_label = '等待所属阶段启动'
    k6_status = parse_k6_status(k6_tail)
    return {
        'scenario_status': scenario_status,
        'result_label': result_label,
        'report_label': report_label,
        'point_label': point_label,
        'current_plan': current_plan,
        'k6_status': k6_status,
    }


def collect() -> dict:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    matrix = matrix_runtime_status()
    scenarios = []
    total_completed = 0
    total_expected = sum(EXPECTED_POINTS.values())
    report_count = 0
    for key, label in SCENARIOS.items():
        log = RESULTS / f'{LOG_PREFIX}-{key}.log'
        result = RESULTS / f'{RESULT_PREFIX}-{key}.json'
        report = ROOT / 'docs' / f'{REPORT_PREFIX}-{key}.md'
        records = result_records(result)
        completed_points = len(records)
        total_completed += completed_points
        if report.exists():
            report_count += 1
        container_running = docker_container_exists(perf_container_name(key))
        live_log = docker_perf_logs(key, 120) if container_running else ''
        log_tail_for_status = sanitize_log(live_log or read_tail(log, 120))
        state = scenario_state(
            key,
            completed_points,
            log_tail_for_status,
            matrix,
            container_running or scenario_process_running(key, matrix),
        )
        scenarios.append({
            'key': key,
            'label': label,
            'log': str(log.relative_to(ROOT)),
            'lines': file_lines(log),
            'interesting': interesting_lines_from_text(log_tail_for_status) if live_log else interesting_lines(log),
            'result_exists': result.exists(),
            'result_size': result.stat().st_size if result.exists() else 0,
            'report_exists': report.exists(),
            'completed_points': completed_points,
            'expected_points': EXPECTED_POINTS.get(key, 15),
            'completed_rows': completed_stage_rows(key, records),
            **state,
        })
    matrix_status = matrix['label']
    writeback_status = matrix['writeback']
    if not matrix['processes'].strip() and total_completed >= total_expected:
        matrix_status = '完整完成'
        if MODE == 'extended':
            writeback_status = '已生成报告，等待或已完成脚本内回写' if report_count else '等待回写确认'
    return {
        'now': now,
        'start': START_TS,
        'commit': run(['git', 'rev-parse', '--short', 'HEAD'], 2),
        'branch': run(['git', 'branch', '--show-current'], 2),
        'matrix_status': matrix_status,
        'writeback_status': writeback_status,
        'writeback_tail': matrix['writeback_tail'],
        'total_completed': total_completed,
        'total_expected': total_expected,
        'processes': matrix['processes'],
        'matrix_tail': matrix['matrix_tail'],
        'scenarios': scenarios,
        'docker_stats': run(['docker', 'stats', '--no-stream', '--format', 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'], 8),
        'docker_ps': run(['sh', '-lc', "docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E '^nazoauth-(local|extended-capacity)-' | head -120 || true"], 5),
        'disk': run(['df', '-h', '/workspace', '/'], 3),
        'load': run(['sh', '-lc', "uptime; free -h | sed -n '1,2p'"], 3),
    }


def render_stage_table(rows: list[dict]) -> str:
    if not rows:
        return "<div class='subtle'>尚无已完成阶段。</div>"
    rendered = ["<div class='table-scroll' tabindex='0'><table class='metrics'><thead><tr><th>阶段</th><th>实例</th><th>目标</th><th>HTTP RPS</th><th>p95</th><th>p99</th><th>错误率</th><th>App CPU</th><th>PG CPU</th><th>Valkey 命中</th><th>DB 等待</th></tr></thead><tbody>"]
    for row in rows[-6:]:
        rendered.append(
            '<tr>'
            f"<td>{esc(row.get('stage'))}</td>"
            f"<td>{esc(row.get('instances'))}</td>"
            f"<td>{esc(row.get('target_rate'))}</td>"
            f"<td>{esc(fmt_num(row.get('http_rps')))}</td>"
            f"<td>{esc(fmt_num(row.get('p95')))} ms</td>"
            f"<td>{esc(fmt_num(row.get('p99')))} ms</td>"
            f"<td>{esc(fmt_pct(row.get('error_rate')))}</td>"
            f"<td>{esc(fmt_num(row.get('app_cores')))} core</td>"
            f"<td>{esc(fmt_num(row.get('pg_cpu')))}%</td>"
            f"<td>{esc(fmt_pct(row.get('valkey_hit_rate')))}</td>"
            f"<td>{esc(fmt_num(row.get('db_wait_avg')))} ms</td>"
            '</tr>'
        )
    rendered.append('</tbody></table></div>')
    if len(rows) > 6:
        rendered.append(f"<div class='subtle'>仅显示最近 6 个已完成阶段；该场景已完成 {len(rows)} 个阶段。</div>")
    return ''.join(rendered)


def render_cards(data: dict) -> str:
    cards = []
    for item in data['scenarios']:
        k6 = item.get('k6_status') or {}
        rate = f"{k6.get('rate')} flow/s" if k6.get('rate') else '等待实时输出'
        progress = f"{k6.get('progress')}%" if k6.get('progress') else '-'
        elapsed = k6.get('elapsed') or '-'
        iterations = k6.get('completed_iterations') or '-'
        interrupted = k6.get('interrupted_iterations') or '0'
        cards.append(f"""
<section class='card'>
  <div class='card-head'><h2>{esc(item['label'])}</h2><span>{esc(item['completed_points'])}/{esc(item['expected_points'])} 阶段 | {esc(item['lines'])} 行主日志</span></div>
  <div class='status-grid' aria-label='场景状态'>
    <div><span>场景</span><b>{esc(item['scenario_status'])}</b></div>
    <div><span>结果</span><b>{esc(item['result_label'])}</b></div>
    <div><span>报告</span><b>{esc(item['report_label'])}</b></div>
    <div><span>回写</span><b>{esc(data['writeback_status'])}</b></div>
  </div>
  <div class='current-grid' aria-label='当前压测阶段'>
    <div class='wide-cell'><span>当前阶段</span><b>{esc(item.get('point_label') or '等待实时 k6 输出')}</b></div>
    <div><span>当前速率</span><b>{esc(rate)}</b></div>
    <div><span>阶段进度</span><b>{esc(progress)}</b></div>
    <div><span>耗时</span><b>{esc(elapsed)}</b></div>
    <div><span>迭代</span><b>{esc(iterations)}</b></div>
    <div><span>中断</span><b>{esc(interrupted)}</b></div>
  </div>
  <div class='log-link'><a href='/log/{esc(item['key'])}'>查看完整日志尾部</a></div>
  <div class='stage-title'>已完成阶段指标</div>
  {render_stage_table(item['completed_rows'])}
  <details class='lazy-log' data-log-key='{esc(item['key'])}'><summary>按需加载 k6 实时日志尾部</summary><pre>展开后建立 SSE 日志流...</pre></details>
</section>
""")
    return ''.join(cards)


def render_dashboard(data: dict) -> str:
    total_pct = (data['total_completed'] / data['total_expected'] * 100.0) if data['total_expected'] else 0.0
    return f"""
<div class='summary' id='summary'>
  <div class='cell'><span class='subtle'>矩阵状态</span><b>{esc(data['matrix_status'])}</b></div>
  <div class='cell'><span class='subtle'>全局阶段</span><b>{esc(data['total_completed'])}/{esc(data['total_expected'])}（{esc(fmt_num(total_pct, 1))}%）</b></div>
  <div class='cell'><span class='subtle'>阶段定义</span><b>{esc(len(SCENARIOS))} 场景 × 15 阶段</b></div>
  <div class='cell'><span class='subtle'>回写状态</span><b>{esc(data['writeback_status'])}</b></div>
</div>
<div class='grid' id='scenario-grid'>{render_cards(data)}</div>
<section class='card wide'><h2>Docker 资源占用</h2><pre>{esc(data['docker_stats'])}</pre></section>
<section class='card wide'><h2>Docker 容器状态</h2><pre>{esc(data['docker_ps'])}</pre></section>
<section class='card wide'><h2>矩阵进程</h2><pre>{esc(data['processes'])}</pre></section>
<section class='card wide'><h2>主机负载 / 磁盘</h2><pre>{esc(data['load'])}
{esc(data['disk'])}</pre></section>
<section class='card wide'><h2>矩阵主日志尾部</h2><details class='lazy-log' data-log-key='matrix'><summary>按需加载矩阵主日志尾部</summary><pre>展开后建立 SSE 日志流...</pre></details></section>
<section class='card wide'><h2>回写状态日志</h2><details class='lazy-log' data-log-key='writeback'><summary>按需加载回写状态日志</summary><pre>展开后建立 SSE 日志流...</pre></details></section>
"""


def render_page(data: dict) -> bytes:
    page_css = """
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0b0f14; color:#dbe3ee; }
* { box-sizing:border-box; }
html { min-width:0; }
body { margin:0; padding:clamp(12px,2.5vw,24px); overflow-x:hidden; }
a { color:#7dd3fc; text-decoration:none; }
.header { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; margin-bottom:18px; min-width:0; }
h1 { margin:0 0 8px; font-size:clamp(20px,4.8vw,24px); font-weight:700; letter-spacing:0; line-height:1.2; }
h2 { margin:0; font-size:clamp(15px,3.8vw,16px); line-height:1.25; overflow-wrap:anywhere; }
.badge { border:1px solid #334155; background:#111827; color:#cbd5e1; padding:6px 10px; border-radius:6px; white-space:nowrap; flex:0 0 auto; }
.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr)); gap:10px; margin:0 0 14px; }
.summary .cell { border:1px solid #233044; background:#0f1720; border-radius:8px; padding:10px; min-width:0; }
.summary b { display:block; font-size:clamp(16px,4vw,18px); line-height:1.25; margin-top:4px; overflow-wrap:anywhere; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,620px),1fr)); gap:14px; min-width:0; }
.card { border:1px solid #233044; background:#111821; border-radius:8px; padding:14px; min-width:0; overflow:hidden; }
.card-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; margin-bottom:8px; min-width:0; }
.card-head span,.meta,.subtle { color:#9ca3af; font-size:13px; line-height:1.45; overflow-wrap:anywhere; }
.card-head span { text-align:right; flex:0 0 auto; max-width:45%; }
.status-grid,.current-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(128px,1fr)); gap:8px; margin:10px 0; }
.status-grid div,.current-grid div { border:1px solid #253246; background:#0b121c; border-radius:6px; padding:8px 9px; min-width:0; }
.status-grid span,.current-grid span { display:block; color:#8ea0b5; font-size:11px; line-height:1.25; margin-bottom:4px; }
.status-grid b,.current-grid b { display:block; color:#dbe3ee; font-size:13px; line-height:1.3; font-weight:650; overflow-wrap:anywhere; }
.current-grid .wide-cell { grid-column:1 / -1; }
.log-link { margin:2px 0 10px; font-size:13px; }
.stage-title { color:#cbd5e1; font-size:13px; font-weight:600; margin:12px 0 6px; }
.table-scroll { width:100%; overflow-x:auto; overflow-y:hidden; border:1px solid #253246; border-radius:6px; background:#0b121c; -webkit-overflow-scrolling:touch; }
.table-scroll:focus { outline:2px solid #38bdf8; outline-offset:2px; }
.metrics { width:100%; min-width:820px; border-collapse:collapse; font-size:12px; }
.metrics th,.metrics td { border-bottom:1px solid #253246; padding:7px 8px; text-align:right; white-space:nowrap; }
.metrics th:first-child,.metrics td:first-child { text-align:left; position:sticky; left:0; background:#0b121c; z-index:1; }
.metrics th { color:#93a4b8; font-weight:600; background:#0b121c; }
pre { margin:10px 0 0; padding:12px; background:#05080d; border:1px solid #1f2937; border-radius:6px; overflow:auto; max-height:min(320px,55vh); font:12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space:pre-wrap; word-break:break-word; }
details.lazy-log pre { max-height:min(500px,62vh); }
details { margin-top:10px; }
summary { cursor:pointer; color:#7dd3fc; font-size:13px; line-height:1.45; min-height:36px; display:flex; align-items:center; }
.wide { margin-top:14px; }
@media (max-width: 720px) {
  body { padding:10px; }
  .header { flex-direction:column; gap:10px; margin-bottom:12px; }
  .badge { white-space:normal; width:100%; text-align:center; }
  .summary { grid-template-columns:1fr 1fr; gap:8px; }
  .summary .cell { padding:9px; }
  .grid { grid-template-columns:1fr; gap:10px; }
  .card { padding:12px; border-radius:8px; }
  .card-head { flex-direction:column; gap:4px; }
  .card-head span { max-width:none; text-align:left; }
  .meta,.subtle { font-size:12px; }
  .status-grid,.current-grid { grid-template-columns:1fr 1fr; gap:7px; }
  .status-grid div,.current-grid div { padding:8px; }
  .status-grid b,.current-grid b { font-size:12px; }
  .metrics { min-width:760px; font-size:11px; }
  .metrics th,.metrics td { padding:6px; }
  pre { max-height:48vh; font-size:11px; }
}
@media (max-width: 420px) {
  .summary { grid-template-columns:1fr; }
  .card { padding:10px; }
  .status-grid,.current-grid { grid-template-columns:1fr; }
  .table-scroll { margin-left:-2px; margin-right:-2px; width:calc(100% + 4px); }
}
"""
    page_js = """
const LOG_LINE_LIMIT = 500;
const logStreams = new Map();

function eventDataLine(event) {
  try { return JSON.parse(event.data); }
  catch { return event.data; }
}

function getLogState(key) {
  let state = logStreams.get(key);
  if (!state) {
    state = { source: null, lines: [], sticky: true, errorLineVisible: false, closed: false };
    logStreams.set(key, state);
  }
  return state;
}

function currentLogView(key) {
  const details = document.querySelector(`details.lazy-log[data-log-key="${CSS.escape(key)}"]`);
  if (!details || !details.open) return null;
  return details.querySelector('pre');
}

function bindLogScroll(key, pre) {
  const state = logStreams.get(key);
  if (!state || !pre || pre.__boundLogKey === key) return;
  pre.__boundLogKey = key;
  pre.addEventListener('scroll', () => {
    state.sticky = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
  }, { passive: true });
}

function renderLogState(key) {
  const state = logStreams.get(key);
  const pre = currentLogView(key);
  if (!state || !pre) return;
  bindLogScroll(key, pre);
  const pinnedToBottom = state.sticky;
  pre.textContent = state.lines.join('\\n');
  if (pinnedToBottom) pre.scrollTop = pre.scrollHeight;
}

function appendLogLine(key, line) {
  if (!key || line === '') return;
  const state = logStreams.get(key);
  if (!state || state.closed) return;
  if (line === '日志流连接中断，浏览器将自动重连。') {
    if (state.errorLineVisible) return;
    state.errorLineVisible = true;
  } else {
    state.errorLineVisible = false;
  }
  const pre = currentLogView(key);
  if (pre) {
    state.sticky = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24 || state.sticky;
  }
  const lines = state.lines;
  lines.push(line);
  if (lines.length > LOG_LINE_LIMIT) {
    lines.splice(0, lines.length - LOG_LINE_LIMIT);
  }
  renderLogState(key);
}

function startLogStream(key) {
  if (!key) return;
  const state = getLogState(key);
  state.closed = false;
  if (state.source && state.source.readyState !== EventSource.CLOSED) {
    renderLogState(key);
    return;
  }
  state.lines = [];
  state.sticky = true;
  state.errorLineVisible = false;
  renderLogState(key);
  appendLogLine(key, '正在连接日志流...');
  const source = new EventSource(`/log-stream/${encodeURIComponent(key)}`);
  state.source = source;
  source.onmessage = (event) => {
    const current = logStreams.get(key);
    if (!current || current.closed || current.source !== source) return;
    appendLogLine(key, eventDataLine(event));
  };
  source.onerror = () => {
    const current = logStreams.get(key);
    if (!current || current.closed || current.source !== source) return;
    appendLogLine(key, '日志流连接中断，浏览器将自动重连。');
  };
}

function stopLogStream(key) {
  const state = logStreams.get(key);
  if (!state) return;
  state.closed = true;
  if (state.source) {
    state.source.onmessage = null;
    state.source.onerror = null;
    state.source.close();
  }
  logStreams.delete(key);
}

function bindOpenLogViews() {
  for (const [key] of logStreams) {
    const details = document.querySelector(`details.lazy-log[data-log-key="${CSS.escape(key)}"]`);
    if (!details) continue;
    details.open = true;
    renderLogState(key);
  }
}

async function refreshDashboard() {
  const dashboard = document.getElementById('dashboard');
  if (!dashboard) return;
  try {
    const response = await fetch('/fragment', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    dashboard.innerHTML = await response.text();
    bindOpenLogViews();
  } catch (error) {
    console.warn('capacity preview refresh failed', error);
  }
}

document.addEventListener('toggle', (event) => {
  const details = event.target;
  if (!details.classList || !details.classList.contains('lazy-log')) return;
  if (!details.isConnected) return;
  const key = details.dataset.logKey;
  if (details.open) {
    startLogStream(key);
  } else {
    stopLogStream(key);
  }
}, true);

window.addEventListener('DOMContentLoaded', () => {
  setInterval(refreshDashboard, 5000);
});

window.addEventListener('beforeunload', () => {
  for (const key of Array.from(logStreams.keys())) stopLogStream(key);
});
"""
    body = f"""<!doctype html>
<html lang='zh-CN'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>NazoAuth 容量曲线进度</title>
<style>{page_css}</style>
<script>{page_js}</script>
</head>
<body>
<div class='header'>
  <div>
    <h1>NazoAuth 容量曲线矩阵进度</h1>
    <div class='subtle'>开始时间 {esc(data['start'])} | 当前时间 {esc(data['now'])} | 分支 {esc(data['branch'])} | 提交 {esc(data['commit'])}</div>
  </div>
  <div class='badge'>每 5 秒自动刷新 | 只读</div>
</div>
<main id='dashboard'>{render_dashboard(data)}</main>
</body></html>"""
    return body.encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    server_version = 'NazoAuthCapacityPreview/1.0'

    def log_message(self, fmt, *args):
        return

    def do_HEAD(self):
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/healthz':
            payload = b'ok\n'
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path == '/data.json':
            payload = json.dumps(collect(), ensure_ascii=False, indent=2).encode('utf-8')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path == '/fragment':
            payload = render_dashboard(collect()).encode('utf-8')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path.startswith('/log-stream/'):
            key = unquote(parsed.path.rsplit('/', 1)[-1])
            if key not in SCENARIOS and key not in ('matrix', 'writeback'):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            self.end_headers()
            stream_docker_or_file_log(self, key)
            return
        if parsed.path.startswith('/log/'):
            key = unquote(parsed.path.rsplit('/', 1)[-1])
            if key == 'matrix':
                log_path = MATRIX_LOG
            elif key == 'writeback':
                log_path = WRITEBACK_LOG
            elif key in SCENARIOS:
                payload = docker_perf_logs(key, 300).encode('utf-8', errors='replace')
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            payload = read_tail(log_path, 300).encode('utf-8', errors='replace')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path not in ('/', '/index.html'):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        payload = render_page(collect())
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    print(f'capacity preview listening on 0.0.0.0:{PORT}', flush=True)
    server.serve_forever()
