"""Synthetic /proc tests for the task privacy observer; no live API or network."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_task_observer as observer


def proc_stat(pid, ticks):
    suffix = ['S'] + ['0'] * 18 + [str(ticks)]
    return f'{pid} (synthetic process) ' + ' '.join(suffix)


def proc_socket_row(local, peer, state, inode):
    return f'  0: {local} {peer} {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode}'


class FakeProc:
    def __init__(self, root, runtime, pid=501, task_id=5, ticks=111):
        self.root = Path(root)
        self.runtime = Path(runtime)
        self.pid = pid
        self.task_id = task_id
        self.ticks = ticks
        self.task_root = self.runtime / 'data' / 'tasks' / str(task_id)
        self.task_root.mkdir(parents=True)
        self.proc_root = self.root / 'proc'
        self.proc_root.mkdir(parents=True)
        p = self.proc_root / str(pid)
        (p / 'fd').mkdir(parents=True)
        (p / 'net').mkdir()
        (p / 'stat').write_text(proc_stat(pid, ticks))
        (p / 'status').write_text(f'Name:\ttest\nUid:\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\n')
        (p / 'environ').write_bytes(b'HTTP_PROXY=http://user:secret@127.0.0.1:36300\0NO_PROXY=localhost,.local\0')
        (p / 'cwd').symlink_to(self.task_root, target_is_directory=True)
        (p / 'fd' / '3').symlink_to('socket:[12345]')
        header = ' sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
        (p / 'net' / 'tcp').write_text(header + proc_socket_row('0100007F:9D84', '0100007F:8DFC', '01', '12345') + '\n')
        for name in ('tcp6', 'udp', 'udp6'):
            (p / 'net' / name).write_text(header)
        self.p = p


class TaskObserverTests(unittest.TestCase):
    def test_vanished_or_inaccessible_process_cwd_is_not_attributed(self):
        self.assertFalse(observer._within(None, Path('/fixed/task')))

    def test_task_cwd_attribution_excludes_other_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            other = f.proc_root / '502'
            other.mkdir()
            (other / 'status').write_text(f'Uid:\t{os.getuid()}\n')
            (other / 'stat').write_text(proc_stat(502, 222))
            outside = Path(d) / 'outside'
            outside.mkdir()
            (other / 'cwd').symlink_to(outside, target_is_directory=True)
            found = observer._candidate_processes(5, f.task_root, f.proc_root)
            self.assertEqual(set(found), {501})

    def test_pid_reuse_recheck_rejects_changed_start_ticks(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            with patch.object(observer, '_start_ticks', side_effect=[111, 999]):
                self.assertEqual(observer._candidate_processes(5, f.task_root, f.proc_root), {})

    def test_socket_classification_distinguishes_listener_udp_and_peer(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            for fd, inode in ((4, '22222'), (5, '33333'), (6, '44444')):
                (f.p / 'fd' / str(fd)).symlink_to(f'socket:[{inode}]')
            tcp = ('hdr\n' + proc_socket_row('0100007F:9D84', '00000000:0000', '0A', '22222') + '\n' +
                   proc_socket_row('0100007F:9D84', '0100007F:8DFC', '01', '33333') + '\n' +
                   proc_socket_row('0100007F:9D85', '0100007F:8DFC', '01', '12345') + '\n')
            (f.p / 'net' / 'tcp').write_text(tcp)
            (f.p / 'net' / 'udp').write_text('hdr\n' + proc_socket_row('00000000:0035', '00000000:0000', '07', '44444') + '\n')
            rows = observer._classify_sockets(501, f.proc_root)
            kinds = {row['socket_kind'] for row in rows}
            self.assertEqual(kinds, {'listener', 'server_accepted', 'loopback_peer', 'udp_bound'})
            self.assertTrue(all(row['state'] != 'connected' for row in rows if row['socket_kind'] in ('listener', 'server_accepted', 'udp_bound')))
            # Raw endpoints are private intermediate values. Public routes must
            # redact them AFTER exact endpoint matching.
            _, routes, _ = observer._route([{'pid': 501, 'sockets': rows, '_proxy_keys': set()}])
            self.assertNotIn('127.0.0.1', json.dumps(routes))

    def test_matching_port_is_not_matching_proxy_and_listener_cannot_hide_bypass(self):
        direct = {'pid': 1, '_proxy_keys': {('1.1.1.1', 443)},
                  'sockets': [{'socket_kind': 'peer', 'peer_class': 'public', 'peer_port': 443,
                               '_peer_ip': '8.8.8.8',
                               'protocol': 'tcp', 'family': 4, 'state': 'established'}]}
        service = {'pid': 2, '_proxy_keys': direct['_proxy_keys'],
                   'sockets': [{'socket_kind': 'listener', 'local_port': 7777},
                               {'socket_kind': 'peer', 'peer_class': 'public', 'peer_port': 443,
                                '_peer_ip': '1.1.1.1',
                                'protocol': 'tcp', 'family': 4, 'state': 'established'}]}
        _, routes, risks = observer._route([direct, service], ('1.1.1.1', 443))
        self.assertEqual(risks, 1)
        self.assertIn('potential_proxy_bypass', [r['route_class'] for r in routes])
        self.assertIn('global_proxy_connection', [r['route_class'] for r in routes])
        service['sockets'][1]['_peer_ip'] = '8.8.8.8'
        self.assertEqual(observer._route([direct, service])[2], 2)

    def test_local_forwarder_requires_exact_proxy_and_namespace(self):
        client = {'pid': 1, '_proxy_keys': {('127.0.0.1', 1234)}, 'sockets': [
            {'socket_kind': 'loopback_peer', '_peer_ip':'127.0.0.1', '_netns':'net:[1]',
             'peer_class':'loopback', 'peer_port':1234, 'protocol':'tcp', 'family':4, 'state':'established'}]}
        forwarder = {'pid': 2, '_proxy_keys':set(), 'sockets':[
            {'socket_kind':'listener','local_port':1234,'_local_ip':'127.0.0.1','_netns':'net:[2]','protocol':'tcp'}]}
        self.assertEqual(observer._route([client,forwarder])[1][0]['route_class'], 'declared_local_proxy')
        forwarder['sockets'][0]['_netns'] = 'net:[1]'
        route = observer._route([client,forwarder])[1][0]
        self.assertEqual(route['route_class'], 'task_local_proxy_hop')
        self.assertEqual(route['local_forwarder_pids'], [2])

    def test_complete_snapshot_redacts_and_keeps_early_connections(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            samples = [0]
            def advance(_):
                samples[0] += 1
                (f.p / 'net/tcp').write_text('header\n')
            with patch.object(observer, '_select_task', return_value=(5, {'id':'5','status':'running'})), \
                 patch.object(observer, 'request', return_value={'global_proxy':'http://127.0.0.1:36348'}):
                result = observer.observe_task(5, 0.5, _proc=f.proc_root, _runtime=f.runtime,
                    _sleep=advance, _clock=lambda: samples[0] * 0.5)
            self.assertEqual(result['connection_count'], 1)
            text = json.dumps(result)
            for private in ('127.0.0.1', 'secret', 'HTTP_PROXY', str(f.task_root)):
                self.assertNotIn(private, text)

    def test_new_task_without_workspace_is_checked_lifecycle_state(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(observer, '_select_task', return_value=(99, {'id':'99','status':'running'})):
            result = observer.observe_task(99, 0, _runtime=Path(d))
            self.assertEqual(result['status'], 'no_live_process')
            self.assertTrue(result['task_scope_checked'])

    def test_symlink_task_workspace_not_treated_as_idle(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(observer, '_select_task', return_value=(99, {'id':'99','status':'running'})):
            runtime = Path(d)/'runtime'
            (runtime/'data/tasks').mkdir(parents=True)
            (runtime/'data/tasks/99').symlink_to(Path(d))
            result = observer.observe_task(99, 0, _runtime=runtime)
            self.assertEqual(result['status'], 'unavailable')
            self.assertFalse(result['task_scope_checked'])

    def test_automatic_selection_uses_real_id_and_checks_api_identity(self):
        with patch.object(observer, '_running_tasks', return_value=[{'id':'37'}]), \
             patch.object(observer, 'request', return_value={'id':'37','status':'running'}) as api:
            self.assertEqual(observer._select_task(None)[0], 37)
            api.assert_called_once_with('/api/tasks/37')
        with patch.object(observer, 'request', return_value={'id':'38','status':'running'}):
            with self.assertRaises(ValueError):
                observer._select_task(37)

    def test_invalid_task_ids_reject_bool_and_path(self):
        for value in (True, 0, -1, '5', '../5'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                observer._task_id(value)

    def test_ipv6_proc_word_order_decodes_loopback(self):
        ip, port = observer._parse_addr('00000000000000000000000001000000:01BB', 6)
        self.assertEqual(str(ip), '::1')
        self.assertEqual(port, 443)

    def test_proxy_endpoint_drops_credentials_and_address(self):
        value = observer._proxy_endpoint('http://alice:private@example.test:7897')
        self.assertEqual(value, {'scheme': 'http', 'host_type': 'hostname', 'port': 7897})
        self.assertNotIn('alice', json.dumps(value))
        self.assertNotIn('example.test', json.dumps(value))

    def test_idle_task_is_observed_as_no_socket_not_failure(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            with patch.object(observer, '_select_task', return_value=(5, {'status': 'running'})), \
                 patch.object(observer, 'request', return_value={'global_proxy': ''}), \
                 patch.object(observer, '_classify_sockets', return_value=[]):
                result = observer.observe_task(5, 0, _proc=f.proc_root, _runtime=f.runtime,
                                               _clock=lambda: 0.0)
            self.assertEqual(result['status'], 'no_socket_observed')
            self.assertTrue(result['task_scope_checked'])
            self.assertEqual(result['connection_count'], 0)

    def test_selection_required_returns_only_running_ids(self):
        with patch.object(observer, '_running_tasks', return_value=[{'id': '5'}, {'id': '6'}]):
            result = observer._select_task(None)
        self.assertEqual(result, (None, {'selection_required': True, 'task_ids': [5, 6]}))

    def test_observer_never_serializes_env_values(self):
        with tempfile.TemporaryDirectory() as d:
            f = FakeProc(Path(d) / 'fixture', Path(d) / 'runtime')
            env, count = observer._env_proxy(501, f.proc_root)
            payload = json.dumps({'env': env, 'no_proxy_count': count})
            self.assertNotIn('secret', payload)
            self.assertNotIn('user', payload)
            self.assertNotIn('127.0.0.1', payload)
            self.assertEqual(count, 2)


if __name__ == '__main__':
    unittest.main()
