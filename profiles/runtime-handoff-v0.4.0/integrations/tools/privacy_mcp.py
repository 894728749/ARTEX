"""Bounded Windows configuration and public-observer privacy MCP for ARTEX."""
import json
import os
import re
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from mcp.server.fastmcp import FastMCP

ROOT = Path(os.environ['ARTEX_INTEGRATIONS_ROOT'])
EVIDENCE = ROOT / 'workspace/evidence'
REPORTS = ROOT / 'workspace/reports/privacy'
SNAPSHOTS = REPORTS / 'observations'
LAST_SNAPSHOT = None
PS = os.environ['ARTEX_POWERSHELL']
COLLECTOR = os.environ['ARTEX_PRIVACY_COLLECTOR']
mcp = FastMCP('artex-privacy-local')
ReportStatus = Literal['unknown','risk','no_markers_in_checked_file','observed_with_limits','partial','no_leak_observed']
CheckItem = Literal['windows_network_configuration','ipv4_egress','ipv6_egress','dns_path','proxy_bypass','webrtc','evidence_private_markers','test_process_scope']

def safe_file(relative_file):
    raw = Path(relative_file)
    if raw.is_absolute() or '..' in raw.parts or not raw.parts:
        raise ValueError('Only approved relative evidence paths are allowed')
    current = EVIDENCE
    for part in raw.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('Symlink evidence is not allowed')
    file = current.resolve(strict=True)
    if not file.is_relative_to(EVIDENCE.resolve()) or not file.is_file():
        raise ValueError('Evidence must be a regular file in the approved evidence directory')
    if file.stat().st_size > 2_000_000:
        raise ValueError('Evidence exceeds the 2 MB check limit')
    return file

def configuration_snapshot() -> dict:
    try:
        result = subprocess.run([PS,'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',COLLECTOR],capture_output=True,timeout=40,check=False)
        if result.returncode:
            return {'status':'unknown','collection_status':'unavailable','platform':'windows','reason':'collector_unavailable','external_probe_performed':False}
        data = json.loads(result.stdout.decode('utf-8-sig').strip())
        allowed = {'platform','evidence_type','external_probe_performed','ipv4_default_route_count','ipv6_default_route_count','dns_address_count','user_proxy_configured','proxy_credentials_in_configuration','observation_status','limitations','unavailable_checks'}
        summary = {key:data[key] for key in allowed if key in data}
        summary['collection_status'] = 'partial' if data.get('unavailable_checks') else 'ok'
        summary['snapshot_reference'] = uuid.uuid4().hex
        summary['collected_at'] = datetime.now(timezone.utc).isoformat()
        return summary
    except (OSError,ValueError,subprocess.TimeoutExpired):
        return {'status':'unknown','collection_status':'unavailable','platform':'windows','reason':'collector_unavailable','external_probe_performed':False}


def current_summary(snapshot):
    """A compact factual summary derived from collector records, not model prose."""
    task = snapshot.get('task_observation', {})
    active = snapshot.get('active_checks', {})
    observed = active.get('observations', {})
    risks = list(dict.fromkeys(active.get('risk_flags', []) + task.get('risk_flags', [])))
    identity = f"任务 {task['task_id']}" if task.get('task_id') else '本次检查'
    routes = task.get('route_counts', {})
    local_hops = routes.get('task_local_proxy_hop', 0) + routes.get('task_local_service_connection', 0)
    route_text = (f"采到 {local_hops} 条连接到任务内本地服务、{routes.get('global_proxy_connection', 0)} 条连接到配置的全局代理。"
                  if local_hops or routes.get('global_proxy_connection') else '连接路径按原始分类保留，未识别的路径不算已确认经代理。')
    if task.get('task_scope_checked'):
        task_text = (f"{identity}已做被动观测：发现 {task.get('process_count', 0)} 个关联进程，"
                     f"采到 {task.get('connection_count', 0)} 条网络套接字记录。")
        if task.get('status') == 'no_live_process':
            task_text = f'{identity}本次采样未发现关联的运行进程，已完成范围检查；新任务尚未启动工具时可能出现此结果。'
        elif task.get('status') == 'no_socket_observed':
            task_text += '采样窗口未捕获连接，不表示检查失败或无泄漏。'
    else:
        task_text = {'selection_required': '有多个运行任务，需要明确任务编号才能关联进程。',
                     'no_running_task': '当前没有运行中的任务，本次保留项目出口检查结果。'}.get(
                         task.get('status'), '任务关联观测未完成，具体原因已记录。')
    exits = []
    for family in ('ipv4', 'ipv6'):
        item = observed.get('project_' + family, {})
        if item.get('status') == 'observed' and item.get('ip'):
            exits.append(f"{family.upper()} {item['ip']}")
    browsers = [observed.get(key, {}) for key in ('artex_browser', 'windows_edge')]
    rtc_clean = all(b.get('assessment', {}).get('webrtc_status') == 'no_ip_candidate_exposed_in_probe' for b in browsers)
    controls_failed = [k for k in ('windows_system_ipv4', 'windows_system_ipv6') if observed.get(k, {}).get('status') == 'failed']
    has_runtime_evidence = bool(exits) or task.get('status') == 'observed_with_limits'
    return {'headline': ('发现待核实风险' if risks else '本次已完成的检查未发现明确泄漏证据'
                         if has_runtime_evidence else '本次数据不足以判断泄漏情况'),
            'task': task_text,
            'task_state': '仍在运行' if task.get('task_status') == 'running' else task.get('task_status', '未关联任务'),
            'task_routes': route_text,
            'project_exit': '；'.join(exits) if exits else '本次未测得项目代理的公共出口',
            'exit_scope': '出口 IP 来自固定观测请求，不代表任务每条目标连接的源 IP。',
            'webrtc': '两个隔离浏览器均未暴露 ICE 地址' if rtc_clean else 'WebRTC 结果见原始状态，未完成的探测不算通过',
            'risk_flags': risks,
            'next_step': '先核对已标出的风险连接或探测异常；现有任务继续运行。' if risks else '现有任务继续运行；新任务沿用自动关联和被动检查。',
            'main_limit': ('Windows 系统出口对照未成功；' if controls_failed else '') +
                          '任务连接观测只覆盖采样窗口和成功归属的进程，未采到的短连接、共享进程与远端实际源 IP 不作全覆盖保证。'}


@mcp.tool()
def network_snapshot(active: bool = True, task_id: int | None = None) -> dict:
    """Check task-specific live process sockets plus Windows configuration and fixed IPv4/IPv6/DNS/WebRTC observers. Pass the task ID from the user or trigger. If omitted, auto-select only a single running task; never guess among multiple tasks. Task observation is passive and does not pause/restart/inject into processes. active=false skips external probes but retains passive task observation. Returns current_summary before detailed evidence; public observer IPs are allowed, credentials/private host addresses/target payloads are not."""
    global LAST_SNAPSHOT
    summary = configuration_snapshot()
    summary['snapshot_reference'] = uuid.uuid4().hex
    summary['collected_at'] = datetime.now(timezone.utc).isoformat()
    with ThreadPoolExecutor(max_workers=1) as pool:
        from privacy_task_observer import observe_task
        task_future = pool.submit(observe_task, task_id)
        if active:
            from privacy_active_probe import run_active_checks
            try:
                summary['active_checks'] = run_active_checks()
            except Exception as error:
                summary['active_checks'] = {'status':'probe_failed','reason':type(error).__name__,
                                            'external_probe_performed':None}
            summary['external_probe_performed'] = summary['active_checks'].get('external_probe_performed', False)
            summary['observation_status'] = summary['active_checks']['status']
            summary['limitations'] = summary['active_checks'].get('limitations', ['Active probe could not complete'])
        try:
            summary['task_observation'] = task_future.result()
        except Exception as error:
            summary['task_observation'] = {'task_id':task_id, 'status':'unavailable',
                                           'task_scope_checked':False, 'reason':type(error).__name__}
    if summary['task_observation'].get('risk_flags'):
        summary['observation_status'] = 'risk'
    elif summary['task_observation'].get('task_scope_checked') and summary.get('observation_status') in (None, 'unknown'):
        summary['observation_status'] = 'observed_with_limits'
    summary['current_summary'] = current_summary(summary)
    # The platform truncates large tool outputs. Keep the user-facing conclusion
    # first even when another collector grows, and summarize repeated sockets.
    summary = {'current_summary': summary.pop('current_summary'), **summary}
    summary['completed_at'] = datetime.now(timezone.utc).isoformat()
    SNAPSHOTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = SNAPSHOTS / (summary['snapshot_reference'] + '.json')
    with destination.open('x', encoding='utf-8') as output:
        json.dump(summary, output, ensure_ascii=False, indent=2)
    destination.chmod(0o600)
    LAST_SNAPSHOT = summary['snapshot_reference']
    return summary

@mcp.tool()
def scan_evidence(relative_file: str) -> dict:
    """Locally scan one approved evidence file for private markers. Returns category counts only; never file contents, matches, credentials, paths or addresses."""
    try:
        data = safe_file(relative_file).read_text(encoding='utf-8',errors='replace')
    except (OSError,ValueError):
        return {'status':'unknown','reason':'evidence_not_available_or_outside_scope'}
    patterns = {
        'credential_assignment':r'(?im)\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*["\x27]?[^\s"\x27,;]{4,}',
        'authorization':r'(?im)\bAuthorization\s*:\s*\S+\s+\S+',
        'cookie':r'(?im)^\s*(?:Set-)?Cookie\s*:\s*[^\r\n]+',
        'private_key':r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----',
        'ipv4_literal':r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'email':r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        'windows_personal_path':r'(?i)\b[A-Z]:\\Users\\[^\\\s]+',
    }
    counts = {category:len(re.findall(pattern,data)) for category,pattern in patterns.items()}
    return {'reference':uuid.uuid4().hex,'status':'risk' if any(counts.values()) else 'no_markers_in_checked_file',
            'evidence_type':'file_content_pattern_check','counts':counts,'raw_values_returned':False,
            'limitations':['Pattern detection may miss private data','Address presence does not by itself prove an egress leak']}

@mcp.tool()
def write_privacy_report(overall_status: ReportStatus, checked_items: list[CheckItem], uncovered_items: list[CheckItem], snapshot_reference: str | None = None) -> dict:
    """Save an enumerated summary plus the tool-generated observation snapshot. Uses the current session's latest snapshot if reference is omitted. Actual observation data and risk flags are copied from the local tool record, never accepted as model-written prose."""
    statuses = {'unknown','risk','no_markers_in_checked_file','observed_with_limits','partial','no_leak_observed'}
    items = {'windows_network_configuration','ipv4_egress','ipv6_egress','dns_path','proxy_bypass','webrtc','evidence_private_markers','test_process_scope'}
    observed_items = {'windows_network_configuration','evidence_private_markers'}
    observation = None
    reference = snapshot_reference or LAST_SNAPSHOT
    if reference:
        if not re.fullmatch(r'[0-9a-f]{32}', reference):
            return {'saved':False,'reason':'invalid_snapshot_reference'}
        source = SNAPSHOTS / (reference + '.json')
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 262144:
            return {'saved':False,'reason':'snapshot_unavailable'}
        observation = json.loads(source.read_text(encoding='utf-8'))
        active = observation.get('active_checks', {})
        task = observation.get('task_observation', {})
        if task.get('task_scope_checked'):
            observed_items.add('test_process_scope')
            checked_items = sorted(set(checked_items) | {'test_process_scope'})
            uncovered_items = sorted(set(uncovered_items) - {'test_process_scope'})
            if overall_status in ('unknown','no_leak_observed','no_markers_in_checked_file'):
                overall_status = 'observed_with_limits'
        if task.get('risk_flags'):
            overall_status = 'risk'
        if active.get('observations'):
            observed_items.update(set(active.get('attempted_items', [])) & {'ipv4_egress','ipv6_egress','dns_path','webrtc','proxy_bypass'})
            # Snapshot is authoritative; a model cannot hide a detected risk.
            if active.get('risk_flags'):
                overall_status = 'risk'
            elif overall_status in ('unknown','no_leak_observed','no_markers_in_checked_file'):
                overall_status = 'observed_with_limits'
            if observation.get('collection_status') == 'unavailable':
                observed_items.discard('windows_network_configuration')
            checked_items = sorted(set(checked_items) | (observed_items - {'evidence_private_markers'}))
            uncovered_items = sorted((items - set(checked_items)) | set(uncovered_items) - set(checked_items))
    if overall_status not in statuses or not set(checked_items)<=observed_items or not set(uncovered_items)<=items or set(checked_items)&set(uncovered_items) or len(checked_items+uncovered_items)>32:
        return {'saved':False,'reason':'invalid_summary_schema'}
    REPORTS.mkdir(parents=True,exist_ok=True)
    ident = uuid.uuid4().hex
    destination = REPORTS / (ident+'.json')
    with destination.open('x',encoding='utf-8') as file:
        json.dump({'overall_status':overall_status,'checked_items':checked_items,'uncovered_items':uncovered_items,
                   **({'current_summary': observation['current_summary']} if observation and 'current_summary' in observation else {}),
                   'external_probe_performed':observation.get('external_probe_performed') if observation else False,
                   **({'observation':observation} if observation else {})},file,ensure_ascii=False,indent=2)
    destination.chmod(0o600)
    return {'saved':True,'report_reference':ident,'relative_report':'privacy/'+ident+'.json',
            'overall_status':overall_status,'snapshot_reference':reference}

if __name__ == '__main__':
    mcp.run(transport='stdio')
