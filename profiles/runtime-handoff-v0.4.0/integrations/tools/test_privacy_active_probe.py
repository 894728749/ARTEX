"""Synthetic boundary and verdict tests; no live network requests."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_active_probe as probe
import privacy_mcp as server


class PrivacyProbeTests(unittest.TestCase):
    def test_only_fixed_observers(self):
        for url in ['http://api.ipify.org', 'https://api.ipify.org.evil.test',
                    'https://localhost/admin', 'https://bash.ws/dnsleak/test/../../x?json']:
            with self.assertRaises(ValueError):
                probe.checked_url(url)

    def test_webrtc_private_addresses_not_returned(self):
        data = probe.sanitize_webrtc({'status':'complete', 'candidates':[
            {'address':'192.168.1.4','type':'host','protocol':'udp'},
            {'address':'hidden.local','type':'host','protocol':'udp'},
            {'address':'1.1.1.1','type':'srflx','protocol':'udp'}]})
        self.assertEqual(data['private_address_candidate_count'], 1)
        self.assertEqual(data['mdns_candidate_count'], 1)
        self.assertNotIn('192.168.1.4', json.dumps(data))
        self.assertNotIn('hidden.local', json.dumps(data))

    def test_dns_overlap_is_risk_not_confirmed_leak(self):
        browser = {'dns':{'resolvers':[{'ip':'1.1.1.1'}]},
                   'webrtc':{'status':'complete','public_candidates':[]}}
        result = probe.classify_browser(browser, {'resolvers':[{'ip':'1.1.1.1'}]}, True)
        self.assertEqual(result['dns_status'], 'system_resolver_overlap_risk')

    def test_dns_observer_retry_keeps_query_and_fetch_results_distinct(self):
        success = {'status':'observed','body':json.dumps([{'type':'dns','ip':'1.1.1.1'}])}
        with patch.object(probe, 'curl', side_effect=[{'status':'failed','error_code':'curl_28'}, success]) as call:
            result = probe.dns_result('http://127.0.0.1:18118', 'abc123456', 6)
            self.assertEqual(call.call_count, 2)
            self.assertEqual(result['status'], 'observed')
            self.assertEqual(result['attempted'], 6)
            self.assertEqual(result['observer_fetch_errors'], ['curl_28'])
        with patch.object(probe, 'curl', return_value={'status':'failed','error_code':'curl_28'}) as call:
            result = probe.dns_result('http://127.0.0.1:18118', 'abc123456', 6)
            self.assertEqual(call.call_count, 2)
            self.assertEqual(result['status'], 'service_unavailable')
            self.assertEqual(result['error_phase'], 'authoritative_observer_result_fetch')

    def test_stun_error_not_clean_result(self):
        browser = {'dns':{'resolvers':[]}, 'webrtc':{
            'status':'complete','errors':[701],'public_candidates':[]}}
        self.assertEqual(probe.classify_browser(browser, {}, True)['webrtc_status'],
                         'stun_unreachable_or_incomplete')

    def test_tor_udp_candidate_is_distinct_path(self):
        browser = {'dns':{'resolvers':[]}, 'ipv4':{'ip':'9.9.9.9'}, 'webrtc':{
            'status':'complete','public_candidates':[{'ip':'1.1.1.1','type':'srflx','protocol':'udp'}]}}
        self.assertEqual(probe.classify_browser(browser, {}, True)['webrtc_status'],
                         'udp_outside_tor_observed')

    def test_report_uses_tool_evidence_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory(prefix='artex-privacy-test-') as folder:
            root = Path(folder)
            snapshots = root / 'observations'
            snapshots.mkdir()
            ref = 'a' * 32
            record = {'collection_status':'ok','external_probe_performed':True,
                      'active_checks':{'observations':{'synthetic':True},'risk_flags':['synthetic_risk'],
                                       'attempted_items':['ipv4_egress']}}
            (snapshots / (ref + '.json')).write_text(json.dumps(record))
            with patch.object(server, 'REPORTS', root), patch.object(server, 'SNAPSHOTS', snapshots), patch.object(server, 'LAST_SNAPSHOT', ref):
                result = server.write_privacy_report('no_leak_observed', [], [])
                report = json.loads((root / (result['report_reference'] + '.json')).read_text())
                self.assertEqual(report['overall_status'], 'risk')
                self.assertEqual(report['observation'], record)
                self.assertIn('webrtc', report['uncovered_items'])
                self.assertFalse(server.write_privacy_report('unknown', [], [], '../outside')['saved'])


if __name__ == '__main__':
    unittest.main()
