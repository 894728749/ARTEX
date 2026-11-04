"""Bounded, read-only Linux /proc observer for one ARTEX task workspace.

This module intentionally reports socket classifications and sanitized proxy
metadata only. It never reads argv, task files, or network payloads.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from artex_api import RUNTIME, request

def _is_loopback(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False

PROC = Path('/proc')
MAX_PROCESSES = 128
MAX_CONNECTIONS = 256
MAX_OUTPUT_BYTES = 256 * 1024
MAX_WINDOW = 6.0
SAMPLE_INTERVAL = 0.5


def _task_id(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError('task_id must be a positive integer')
    return value


def _safe_task_root(task_id, runtime=RUNTIME):
    base = Path(runtime) / 'data' / 'tasks'
    # Reject symlinked path components, then ensure the resolved directory stays
    # beneath the fixed task-data root.
    cur = Path(runtime)
    for part in ('data', 'tasks', str(task_id)):
        cur = cur / part
        try:
            if cur.is_symlink():
                return None
        except OSError:
            return None
    try:
        root = cur.resolve(strict=True)
        base_real = base.resolve(strict=True)
        if not root.is_dir() or root.parent != base_real:
            return None
        return root
    except OSError:
        return None


def _read(path, limit=65536):
    try:
        with open(path, 'rb') as f:
            return f.read(limit)
    except (OSError, ValueError):
        return b''


def _start_ticks(pid, proc=PROC):
    raw = _read(Path(proc) / str(pid) / 'stat', 8192).decode('ascii', 'replace')
    # comm may contain spaces and parentheses; fields after the final ')' start
    # at stat field 3. starttime is field 22 (index 19 in this suffix).
    end = raw.rfind(')')
    if end < 0:
        return None
    fields = raw[end + 1:].split()
    try:
        return int(fields[19])
    except (IndexError, ValueError):
        return None


def _uid(pid, proc=PROC):
    try:
        for line in (Path(proc) / str(pid) / 'status').read_text(errors='replace').splitlines():
            if line.startswith('Uid:'):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _cwd(pid, proc=PROC):
    try:
        return (Path(proc) / str(pid) / 'cwd').resolve(strict=True)
    except OSError:
        return None


def _within(path, root):
    if path is None:
        return False
    try:
        return path == root or root in path.parents
    except (TypeError, OSError):
        return False


def _env_proxy(pid, proc=PROC):
    """Read only proxy variables; return sanitized endpoint labels."""
    raw = _read(Path(proc) / str(pid) / 'environ', 65536)
    found = {}
    no_proxy_count = 0
    for item in raw.split(b'\0'):
        if b'=' not in item:
            continue
        key, value = item.split(b'=', 1)
        try:
            name = key.decode('ascii').upper()
            val = value.decode('utf-8', 'replace').strip()
        except UnicodeError:
            continue
        if name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY') and val:
            endpoint = _proxy_endpoint(val)
            if endpoint:
                found[name.lower()] = endpoint
        elif name == 'NO_PROXY' and val:
            no_proxy_count = len([x for x in val.split(',') if x.strip()])
    return found, no_proxy_count


def _proxy_endpoint(value):
    try:
        parsed = urlsplit(value if '://' in value else 'http://' + value)
        if not parsed.hostname or parsed.port is None:
            return None
        host = parsed.hostname
        try:
            ip = ipaddress.ip_address(host)
            # Loopback is necessary to match a local forwarder; other addresses
            # are intentionally reduced to address type, never actual address.
            if ip.is_loopback:
                host_label = 'loopback'
            elif ip.is_global:
                host_label = f'public_ipv{ip.version}'
            elif ip.is_private or ip.is_link_local:
                host_label = f'private_ipv{ip.version}'
            else:
                host_label = f'ipv{ip.version}'
        except ValueError:
            host_label = 'hostname'
        if parsed.scheme.lower() not in ('http', 'https', 'socks5', 'socks5h', 'socks4'):
            return None
        return {'scheme': parsed.scheme.lower(), 'host_type': host_label, 'port': parsed.port}
    except (ValueError, UnicodeError):
        return None


def _proxy_keys(pid, proc=PROC):
    """Exact endpoints stay in memory and are never serialized."""
    keys = set()
    for entry in _read(Path(proc) / str(pid) / 'environ').split(b'\0'):
        name, sep, value = entry.partition(b'=')
        if sep and name.upper() in (b'HTTP_PROXY', b'HTTPS_PROXY', b'ALL_PROXY'):
            key = _proxy_key(value.decode('utf-8', 'replace'))
            if key:
                keys.add(key)
    return keys


def _proxy_key(value):
    if not isinstance(value, str) or not _proxy_endpoint(value):
        return None
    try:
        parsed = urlsplit(value if '://' in value else 'http://' + value)
        host = parsed.hostname.lower()
        return ('localhost' if host == 'localhost' else _normal_ip(ipaddress.ip_address(host)), parsed.port)
    except ValueError:
        return None  # Do not issue DNS requests to attribute proxy hostnames.


def _normal_ip(ip):
    return str(ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip)


def _endpoint_matches(key, ip, port):
    if not key or key[1] != port:
        return False
    return ipaddress.ip_address(ip).is_loopback if key[0] == 'localhost' else key[0] == ip


def _namespace(pid, proc=PROC):
    try:
        return os.readlink(Path(proc) / str(pid) / 'ns/net')
    except OSError:
        return None


def _decode_proc_ip(raw, family):
    data = bytes.fromhex(raw)
    if family == 4:
        return ipaddress.IPv4Address(data[::-1])
    # Linux proc tcp6 uses four native-endian 32-bit words.
    words = [data[i:i+4][::-1] for i in range(0, 16, 4)]
    return ipaddress.IPv6Address(b''.join(words))


def _parse_addr(value, family):
    raw_ip, raw_port = value.split(':')
    return _decode_proc_ip(raw_ip, family), int(raw_port, 16)


def _socket_tables(proc=PROC):
    tables = {}
    for family, name in ((4, 'tcp'), (6, 'tcp6'), (4, 'udp'), (6, 'udp6')):
        proto = name.rstrip('6')
        path = Path(proc) / 'self' / 'net' / name
        # /proc/<pid>/net is process network namespace, not process-owned sockets.
        # Read each pid's own net view during attribution below.
        tables[(proto, family)] = name
    return tables


def _classify_sockets(pid, proc=PROC):
    fd_dir = Path(proc) / str(pid) / 'fd'
    inodes = set()
    try:
        for fd in fd_dir.iterdir():
            try:
                target = os.readlink(fd)
                match = re.fullmatch(r'socket:\[(\d+)\]', target)
                if match:
                    inodes.add(match.group(1))
            except OSError:
                continue
    except OSError:
        return []
    if not inodes:
        return []
    rows = []
    table_data = {}
    listening_ports = set()
    for family, name in ((4, 'tcp'), (6, 'tcp6'), (4, 'udp'), (6, 'udp6')):
        proto = name.rstrip('6')
        data = _read(Path(proc) / str(pid) / 'net' / name, 262144).decode('ascii', 'replace')
        table_data[(proto, family)] = data
        if proto == 'tcp':
            for line in data.splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 10 and cols[9] in inodes and cols[3] == '0A':
                    try:
                        listening_ports.add(_parse_addr(cols[1], family)[1])
                    except (ValueError, IndexError):
                        pass
    for family, name in ((4, 'tcp'), (6, 'tcp6'), (4, 'udp'), (6, 'udp6')):
        proto = name.rstrip('6')
        data = table_data[(proto, family)]
        for line in data.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10 or cols[9] not in inodes:
                continue
            try:
                local_ip, local_port = _parse_addr(cols[1], family)
                peer_ip, peer_port = _parse_addr(cols[2], family)
                state_hex = cols[3]
            except (ValueError, IndexError):
                continue
            if proto == 'tcp' and state_hex == '0A':
                kind, state = 'listener', 'listen'
            elif proto == 'tcp' and local_port in listening_ports:
                kind, state = 'server_accepted', _tcp_state(state_hex)
            elif peer_port == 0 and peer_ip.is_unspecified:
                kind, state = ('udp_bound', 'bound') if proto == 'udp' else ('unconnected', 'unconnected')
            elif local_ip.is_loopback and peer_ip.is_loopback:
                kind, state = 'loopback_peer', _tcp_state(state_hex) if proto == 'tcp' else 'connected'
            elif peer_ip.is_loopback:
                kind, state = 'loopback_peer', _tcp_state(state_hex) if proto == 'tcp' else 'connected'
            else:
                kind, state = 'peer', _tcp_state(state_hex) if proto == 'tcp' else 'connected'
            rows.append({'protocol': proto, 'family': family, 'state': state,
                         'socket_kind': kind, 'local_port': local_port,
                         'peer_port': peer_port,
                         'peer_class': 'loopback' if peer_ip.is_loopback else
                                       'unspecified' if peer_ip.is_unspecified else
                                       'public' if peer_ip.is_global else 'private',
                         '_local_ip': _normal_ip(local_ip), '_peer_ip': _normal_ip(peer_ip),
                         '_inode': cols[9], '_netns': _namespace(pid, proc)})
    return rows


def _tcp_state(value):
    return {'01': 'established', '02': 'connecting', '03': 'connecting',
            '04': 'closing', '05': 'closing', '06': 'closing',
            '07': 'closed', '08': 'closing', '09': 'closing', '0B': 'closing'}.get(value, 'unknown')


def _running_tasks():
    data = request('/api/tasks')
    items = data.get('tasks', []) if isinstance(data, dict) else data
    return [t for t in items if isinstance(t, dict) and t.get('status') == 'running'
            and str(t.get('id', '')).isdecimal()]


def _select_task(task_id):
    if task_id is not None:
        task_id = _task_id(task_id)
        item = request(f'/api/tasks/{task_id}')
        task = item.get('task', item) if isinstance(item, dict) else {}
        if not task or str(task.get('id')) != str(task_id):
            raise ValueError('task_not_found')
        return task_id, task
    running = _running_tasks()
    if len(running) != 1:
        return None, {'selection_required': bool(running),
                      'task_ids': [int(t['id']) for t in running]}
    task_id = int(running[0]['id'])
    item = request(f'/api/tasks/{task_id}')
    task = item.get('task', item) if isinstance(item, dict) else {}
    if not task or str(task.get('id')) != str(task_id):
        raise ValueError('task_not_found')
    return task_id, task


def _candidate_processes(task_id, root, proc=PROC):
    uid = os.getuid() if hasattr(os, 'getuid') else None
    candidates = {}
    try:
        pids = sorted((int(p.name) for p in Path(proc).iterdir() if p.name.isdecimal()))
    except OSError:
        return candidates
    for pid in pids[:4096]:
        if uid is not None and _uid(pid, proc) != uid:
            continue
        cwd = _cwd(pid, proc)
        if not _within(cwd, root):
            continue
        ticks = _start_ticks(pid, proc)
        if ticks is None:
            continue
        candidates[pid] = {'pid': pid, 'start_ticks': ticks, 'cwd': cwd}
        if len(candidates) >= MAX_PROCESSES:
            break
    # Recheck identity after collection to avoid PID reuse between reads.
    return {pid: row for pid, row in candidates.items()
            if _start_ticks(pid, proc) == row['start_ticks'] and _within(_cwd(pid, proc), root)}


def _route(processes, global_proxy=None):
    # Match full addresses, ports, protocol and namespace BEFORE redaction.
    # A shared port or an arbitrary listener alone never proves a proxy path.
    all_sockets, listeners, routes = [], [], []
    for row in processes:
        for sock in row['sockets']:
            item = dict(sock, pid=row['pid'])
            all_sockets.append(item)
            if sock['socket_kind'] == 'listener':
                listeners.append(item)
    bypasses = 0
    for row in processes:
        declared = row.get('_proxy_keys', set())
        for sock in row['sockets']:
            if sock['socket_kind'] in ('listener', 'server_accepted', 'udp_bound', 'unconnected'):
                continue
            peer_ip = sock.get('_peer_ip')
            matched = bool(peer_ip and any(_endpoint_matches(k, peer_ip, sock['peer_port']) for k in declared))
            forwarders = []
            cls = 'unclassified'
            if sock['peer_class'] == 'loopback':
                for listener in listeners:
                    if (listener.get('_netns') and listener['_netns'] == sock.get('_netns') and
                        listener['protocol'] == sock['protocol'] and listener['local_port'] == sock['peer_port'] and
                        (listener.get('_local_ip') == peer_ip or listener.get('_local_ip') == '::' or _is_loopback(listener.get('_local_ip')))):
                        forwarders.append(listener['pid'])
                if forwarders:
                    cls = 'task_local_proxy_hop' if matched else 'task_local_service_connection'
                elif matched:
                    cls = 'declared_local_proxy'
            elif matched:
                cls = 'global_proxy_connection' if _endpoint_matches(global_proxy, peer_ip, sock['peer_port']) else 'declared_proxy_upstream'
            elif sock['peer_class'] == 'public' and declared:
                cls = 'potential_proxy_bypass'
                bypasses += 1
            routes.append({'pid': row['pid'], 'start_ticks': row.get('start_ticks'),
                           'protocol': sock['protocol'], 'family': sock['family'],
                           'state': sock['state'], 'peer_class': sock['peer_class'],
                           'route_class': cls, 'declared_proxy_match': matched,
                           'local_forwarder_pids': sorted(set(forwarders))})
    return all_sockets, routes, bypasses


def observe_task(task_id: int | None = None, window_seconds=6, *, _proc=PROC,
                 _runtime=RUNTIME, _sleep=time.sleep, _clock=time.monotonic):
    """Observe task-scoped process sockets; no target requests or mutations."""
    if task_id is not None:
        task_id = _task_id(task_id)
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)) or not 0 <= window_seconds <= MAX_WINDOW:
        raise ValueError('window_seconds must be between 0 and 6')
    collected_at = datetime.now(timezone.utc).isoformat()
    try:
        selected_id, task = _select_task(task_id)
    except Exception as exc:
        return _empty_result('unavailable', task_id, reason=type(exc).__name__)
    if selected_id is None:
        result = _empty_result('selection_required' if task['task_ids'] else 'no_running_task', None)
        result['task_ids'] = task['task_ids']
        return result
    root = _safe_task_root(selected_id, _runtime)
    if root is None:
        # A newly created task may not have a workspace yet. A symlink/escape
        # is not treated as that benign lifecycle state.
        expected = Path(_runtime) / 'data/tasks' / str(selected_id)
        parents = (Path(_runtime)/'data', Path(_runtime)/'data/tasks', expected)
        if not expected.exists() and not any(p.is_symlink() for p in parents):
            result = _empty_result('no_live_process', selected_id, task_status=task.get('status', 'unknown'),
                                   reason='task_workspace_not_created_yet')
            result['task_scope_checked'] = True
            return result
        return _empty_result('unavailable', selected_id, task_status=task.get('status', 'unknown'),
                             reason='task_workspace_unavailable_or_unsafe')
    try:
        global_key = _proxy_key(request('/api/settings').get('global_proxy'))
    except Exception:
        global_key = None
    try:
        next(Path(_proc).iterdir(), None)
    except OSError:
        return _empty_result('unavailable', selected_id, task_status=task.get('status', 'unknown'), reason='proc_unreadable')
    start, seen, samples = _clock(), {}, 0
    route_records, socket_keys = {}, set()
    truncated = False
    while True:
        current = _candidate_processes(selected_id, root, _proc)
        if len(current) >= MAX_PROCESSES:
            truncated = True
        samples += 1
        rows = []
        for pid, row in current.items():
            key = (pid, row['start_ticks'])
            row['env_proxy'], row['no_proxy_count'] = _env_proxy(pid, _proc)
            row['_proxy_keys'] = _proxy_keys(pid, _proc)
            row['sockets'] = _classify_sockets(pid, _proc)
            # Avoid mixing an exited/reused PID with a replacement's sockets.
            if _start_ticks(pid, _proc) != row['start_ticks'] or not _within(_cwd(pid, _proc), root):
                continue
            if key not in seen and len(seen) >= MAX_PROCESSES:
                truncated = True
                continue
            seen[key] = row
            rows.append(row)
        data, routes, _ = _route(rows, global_key)
        # Preserve connections actually seen in EARLIER samples, including
        # processes which finish normally before the observation window ends.
        by_pid = {r['pid']: r for r in rows}
        outbound = [r for r in data if r['socket_kind'] not in ('listener','server_accepted','udp_bound','unconnected')]
        for sock in data:
            if len(socket_keys) < MAX_CONNECTIONS:
                socket_keys.add((sock['pid'], by_pid[sock['pid']]['start_ticks'], sock['_inode'], sock['protocol'], sock['_local_ip'], sock['_peer_ip'], sock['peer_port']))
            else:
                truncated = True
        for sock, route in zip(outbound, routes):
            key = (sock['pid'], by_pid[sock['pid']]['start_ticks'], sock['_inode'], sock['protocol'], sock['_local_ip'], sock['_peer_ip'], sock['peer_port'])
            if key in route_records or len(route_records) < MAX_CONNECTIONS:
                route_records[key] = route
            else:
                truncated = True
        elapsed = _clock() - start
        if elapsed >= window_seconds:
            break
        _sleep(min(SAMPLE_INTERVAL, max(0, window_seconds - elapsed)))
    processes, routes = list(seen.values()), list(route_records.values())
    route_counts = {}
    for route in routes:
        route_counts[route['route_class']] = route_counts.get(route['route_class'], 0) + 1
    groups = {}
    for route in routes:
        key = json.dumps(route, sort_keys=True)
        if key not in groups:
            groups[key] = dict(route, socket_count=0)
        groups[key]['socket_count'] += 1
    output_processes = []
    for row in processes:
        output_processes.append({'pid': row['pid'], 'start_ticks': row['start_ticks'],
             'association': 'same_uid_task_workspace_cwd',
             'proxy_name': 'task_local_proxy' if any(ep['host_type']=='loopback' for ep in row['env_proxy'].values()) else 'declared_proxy' if row['env_proxy'] else 'none_or_unknown',
             'proxy_endpoints': row['env_proxy'], 'no_proxy_present': row['no_proxy_count'] > 0,
             'no_proxy_value_count': row['no_proxy_count'],
             'proxy_matches_global': bool(global_key and global_key in row['_proxy_keys'])})
    result = {'task_id': selected_id, 'task_status': task.get('status', 'unknown'),
        'status': 'observed_with_limits' if routes else 'no_socket_observed' if processes else 'no_live_process',
        'task_scope_checked': True, 'process_count': len(processes), 'connection_count': len(routes),
        'route_counts': route_counts, 'risk_flags': ['potential_proxy_bypass'] if route_counts.get('potential_proxy_bypass') else [],
        'sample_count': samples, 'collected_at': collected_at,
        'completed_at': datetime.now(timezone.utc).isoformat(),
        'scope': 'same-uid processes with resolved cwd inside the selected task workspace',
        'window_seconds': round(_clock()-start, 3), 'processes': output_processes[:8],
        'socket_count': len(socket_keys), 'routes': list(groups.values())[:12], 'truncated': truncated,
        'detail_summarized': len(output_processes)>8 or len(groups)>12 or len(routes)>len(groups),
        'process_detail_count': min(8,len(output_processes)), 'route_group_count': len(groups),
        'limitations': ['Cwd-based attribution excludes shared MCP processes and descendants that leave the task workspace',
            'Socket records prove sampled first hops, not payload transfer, destination-observed public IP or every short-lived flow',
            'Unconnected UDP sockets and listeners do not prove a DNS or WebRTC leak',
            'Unknown proxy hostnames are not resolved; unidentified peers remain unclassified',
            'Counts cover the sampled records; process details are capped at 8 and grouped connection details at 12 to avoid platform truncation',
            'NO_PROXY may intentionally bypass a declared proxy; a bypass flag requires review, not an automatic leak verdict']}
    assert len(json.dumps(result).encode()) < MAX_OUTPUT_BYTES
    return result


def _empty_result(status, task_id, *, task_status='unknown', reason=None):
    now = datetime.now(timezone.utc).isoformat()
    result = {'task_id': task_id, 'task_status': task_status, 'status': status,
              'task_scope_checked': False, 'process_count': 0, 'connection_count': 0,
              'route_counts': {}, 'risk_flags': [], 'sample_count': 0,
              'collected_at': now, 'completed_at': now, 'limitations': []}
    if reason:
        result['reason'] = reason
    return result
