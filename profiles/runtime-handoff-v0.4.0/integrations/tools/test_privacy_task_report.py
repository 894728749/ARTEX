"""Task evidence, failure semantics and authoritative report regression checks."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_mcp as server


class TaskReportTests(unittest.TestCase):
    def save_snapshot(self, snapshot, status='observed_with_limits', checked=None, uncovered=None):
        with tempfile.TemporaryDirectory(prefix='artex-task-report-') as folder:
            root = Path(folder)
            observations = root / 'observations'
            observations.mkdir()
            ref = 'b' * 32
            snapshot['current_summary'] = server.current_summary(snapshot)
            (observations / (ref + '.json')).write_text(json.dumps(snapshot))
            with patch.object(server, 'REPORTS', root), patch.object(server, 'SNAPSHOTS', observations), patch.object(server, 'LAST_SNAPSHOT', ref):
                receipt = server.write_privacy_report(status, checked or [], uncovered or [])
            return receipt, (json.loads((root / (receipt['report_reference'] + '.json')).read_text()) if receipt.get('saved') else None)

    def test_checked_task_cannot_be_forced_uncovered_by_model(self):
        observation = {'task_observation': {'task_id': 37, 'task_scope_checked': True,
                       'status': 'observed_with_limits', 'process_count': 2, 'connection_count': 1}}
        receipt, report = self.save_snapshot(observation, uncovered=['test_process_scope'])
        self.assertTrue(receipt['saved'])
        self.assertIn('test_process_scope', report['checked_items'])
        self.assertNotIn('test_process_scope', report['uncovered_items'])
        self.assertEqual(report['observation'], observation)
        self.assertIn('任务 37', report['current_summary']['task'])

    def test_model_cannot_claim_unobserved_task_checked(self):
        receipt, _ = self.save_snapshot({'task_observation': {'task_scope_checked': False}}, checked=['test_process_scope'])
        self.assertFalse(receipt['saved'])

    def test_task_risk_cannot_be_hidden_by_model(self):
        _, report = self.save_snapshot({'task_observation': {'task_scope_checked': True,
                                      'risk_flags': ['potential_proxy_bypass']}}, status='no_leak_observed')
        self.assertEqual(report['overall_status'], 'risk')
        self.assertEqual(report['current_summary']['headline'], '发现待核实风险')

    def test_new_task_no_process_is_not_failure_or_clean_claim(self):
        _, report = self.save_snapshot({'task_observation': {'task_id': 38,
                       'task_scope_checked': True, 'status': 'no_live_process'}})
        self.assertIn('尚未启动', report['current_summary']['task'])
        self.assertEqual(report['current_summary']['headline'], '本次数据不足以判断泄漏情况')
        self.assertIn('test_process_scope', report['checked_items'])

    def test_configured_non_tor_is_not_a_risk(self):
        summary = server.current_summary({'active_checks': {'risk_flags': [], 'observations': {
            'project_ipv4': {'status': 'observed', 'ip': '1.1.1.1'},
            'project_tor': {'status': 'observed', 'is_tor': False}}}})
        self.assertEqual(summary['risk_flags'], [])
        self.assertIn('1.1.1.1', summary['project_exit'])
        self.assertIn('不代表任务每条', summary['exit_scope'])


if __name__ == '__main__':
    unittest.main()
