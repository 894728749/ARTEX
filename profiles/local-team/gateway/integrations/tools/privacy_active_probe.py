"""Bounded public-observer probes. No task lifecycle or network configuration writes."""
import concurrent.futures
import ipaddress
import json
import os
import re
import subprocess
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from artex_api import request

ROOT = Path(os.environ['ARTEX_INTEGRATIONS_ROOT'])
WIN_ROOT = os.environ['ARTEX_WINDOWS_INTEGRATIONS_ROOT']
PS = os.environ['ARTEX_POWERSHELL']
WIN_CURL = os.environ['ARTEX_WINDOWS_CURL']
WIN_NODE = os.environ['ARTEX_WINDOWS_NODE']
ENDPOINTS = {'ipv4': 'https://api.ipify.org?format=json',
             'ipv6': 'https://api6.ipify.org?format=json',
             'tor': 'https://check.torproject.org/api/ip'}


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return str(address) if address.is_global else None
    except (ValueError, TypeError):
        return None


def checked_url(url):
    if url in ENDPOINTS.values():
        return url
    if re.fullmatch(r'https://bash\.ws/id\?privacy_nonce=[0-9a-f]{32}', url):
        return url
    if re.fullmatch(r'https://bash\.ws/dnsleak/test/[a-z0-9]{6,64}\?json', url):
        return url
    raise ValueError('observer_not_allowed')


def curl(url, proxy, *, windows=False, family=None):
    checked_url(url)
    command = [WIN_CURL if windows else shutil.which('curl') or 'curl', '--silent', '--show-error',
               '--fail', '--max-time', '18', '--connect-timeout', '10',
               '--proto', '=https', '--max-filesize', '65536']
    if proxy is None:
        command += ['--noproxy', '*']
    else:
        command += ['--proxy', proxy, '--noproxy', '']
    if family:
        command += ['-4' if family == 4 else '-6']
    command.append(url)
    try:
        result = subprocess.run(command, capture_output=True, timeout=21)
        if result.returncode:
            return {'status': 'failed', 'error_code': 'curl_' + str(result.returncode)}
        return {'status': 'observed', 'body': result.stdout.decode('utf-8-sig').strip()}
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return {'status': 'failed', 'error_code': 'observer_timeout_or_unavailable'}


def ip_result(result):
    if result.get('status') != 'observed':
        return {k: result[k] for k in ('status', 'error_code') if k in result}
    try:
        data = result.get('data')
        if data is None:
            data = json.loads(result['body'])
        address = public_ip(data.get('IP', data.get('ip')))
        if not address:
            raise ValueError('invalid_public_address')
        out = {'status': 'observed', 'ip': address,
               'family': ipaddress.ip_address(address).version}
        if isinstance(data.get('IsTor'), bool):
            out['is_tor'] = data['IsTor']
        return out
    except (KeyError, TypeError, ValueError):
        return {'status': 'failed', 'error_code': 'invalid_observer_response'}


def new_dns_id(proxy):
    result = curl('https://bash.ws/id?privacy_nonce=' + uuid.uuid4().hex, proxy)
    value = result.get('body', '')
    return value if re.fullmatch(r'[a-z0-9]{6,64}', value) else None


def dns_result(proxy, ident, attempted):
    if not ident:
        return {'status': 'service_unavailable', 'attempted': 0, 'resolvers': []}
    url = 'https://bash.ws/dnsleak/test/' + ident + '?json'
    fetch_errors = []
    # A timeout fetching the observer result does not mean the DNS query failed.
    # One fresh HTTPS connection may recover a transient Tor/observer failure.
    for fetch_attempt in range(1, 3):
        result = curl(url, proxy)
        if result.get('status') == 'observed':
            break
        error_code = result.get('error_code', 'observer_unavailable')
        fetch_errors.append(error_code)
        if error_code not in {'curl_6','curl_7','curl_28','curl_35','curl_52','curl_56'}:
            break
    fetch_meta = {'observer_fetch_status': result.get('status', 'failed'),
                  'observer_fetch_attempts': fetch_attempt, 'observer_fetch_errors': fetch_errors}
    resolvers = []
    try:
        records = json.loads(result.get('body', 'null'))
        if not isinstance(records, list):
            raise ValueError('invalid_dns_response')
        for entry in records[:128]:
            address = public_ip(entry.get('ip'))
            if entry.get('type') != 'dns' or not address:
                continue
            asn = re.match(r'^AS([0-9]{1,12})(?:\s|$)', str(entry.get('asn', '')))
            country = str(entry.get('country', '')).upper()
            resolvers.append({'ip': address, 'asn': int(asn[1]) if asn else None,
                              'country': country if re.fullmatch(r'[A-Z]{2}', country) else None})
        resolvers = list({x['ip']: x for x in resolvers}.values())
        return {'status': 'observed' if resolvers else 'no_resolver_observed',
                'attempted': attempted, 'resolvers': resolvers,
                'method': 'unique_names_authoritative_observation', 'test_id': ident, **fetch_meta}
    except (TypeError, ValueError, AttributeError):
        return {'status': 'service_unavailable', 'attempted': attempted,
                'resolvers': [], 'error_code': result.get('error_code', 'invalid_dns_response'),
                'error_phase': 'authoritative_observer_result_fetch', **fetch_meta}


def windows_dns(proxy):
    ident = new_dns_id(proxy)
    if not ident:
        return dns_result(proxy, None, 0)
    try:
        result = subprocess.run([PS, '-NoLogo', '-NoProfile', '-NonInteractive',
                                 '-ExecutionPolicy', 'Bypass', '-File',
                                 WIN_ROOT + r'\tools\windows_dns_probe.ps1', '-TestId', ident],
                                capture_output=True, timeout=35)
        control = json.loads(result.stdout.decode('utf-8-sig')) if result.returncode == 0 else {}
        out = dns_result(proxy, ident, control.get('attempted', 0))
        out['local_resolved_count'] = control.get('resolved', 0)
        out['scope'] = 'windows_system_dns_control'
        return out
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'status': 'local_probe_failed', 'attempted': 0, 'resolvers': []}


def sanitize_webrtc(data):
    public = []
    private_count = mdns_count = 0
    for candidate in data.get('candidates', [])[:64]:
        address = candidate.get('address')
        if isinstance(address, str) and address.endswith('.local'):
            mdns_count += 1
        elif public_ip(address):
            public.append({'ip': public_ip(address), 'type': candidate.get('type'),
                           'protocol': candidate.get('protocol')})
        else:
            try:
                if address and not ipaddress.ip_address(address).is_unspecified:
                    private_count += 1
            except ValueError:
                pass
    return {'status': data.get('status', 'unavailable'), 'public_candidates': public,
            'private_address_candidate_count': private_count, 'mdns_candidate_count': mdns_count,
            'errors': [n for n in data.get('errors', [])[:16] if isinstance(n, int)],
            'gathering_state': data.get('gathering_state'),
            'stun_server': 'stun.cloudflare.com:3478'}


def browser_probe(proxy, bypass, *, windows=False):
    scope = 'windows_edge_isolated_project_proxy' if windows else 'artex_browser_equivalent_isolated_wsl'
    ident = new_dns_id(proxy)
    module = ROOT / 'node/node_modules/playwright'
    if not module.exists():
        module = ROOT / 'node/node_modules/@playwright/mcp/node_modules/playwright'
    env = dict(os.environ)
    env['PLAYWRIGHT_BROWSERS_PATH'] = str(ROOT / 'browsers')
    libs = str(ROOT / 'toolchain/browser-libs/root/usr/lib/x86_64-linux-gnu')
    env['LD_LIBRARY_PATH'] = libs + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    launcher = ROOT / 'bin/mcp-launch.sh'
    guarded = '--executable-path "$i/tools/chromium_privacy_launcher.py"' in launcher.read_text()
    if guarded and not (ROOT / 'tools/chromium_privacy_launcher.py').is_file():
        raise ValueError('privacy_launcher_missing')
    config = {'scope': scope, 'proxy_server': proxy, 'proxy_bypass': [x.strip() for x in bypass.split(',') if x.strip()],
              'dns_test_id': ident, 'module_path': str(module),
              'executable_path': str(ROOT / 'browsers/chromium-1247/chrome-linux64/chrome')}
    if guarded:
        config['executable_path'] = str(ROOT / 'tools/chromium_privacy_launcher.py')
    if windows:
        if guarded:
            config['webrtc_policy'] = 'disable_non_proxied_udp'
        config['module_path'] = '\\\\wsl.localhost\\Ubuntu' + str(module).replace('/', '\\')
        config['executable_path'] = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
        cmd = [WIN_NODE, WIN_ROOT + r'\tools\privacy_browser_probe.cjs']
    else:
        cmd = [os.environ.get('ARTEX_NODE', 'node'), str(ROOT / 'tools/privacy_browser_probe.cjs')]
    try:
        result = subprocess.run(cmd, input=json.dumps(config).encode(), capture_output=True,
                                env=env, timeout=70)
        data = json.loads(result.stdout.decode('utf-8-sig'))
        if not isinstance(data, dict) or not data.get('browser_version'):
            raise ValueError('browser_launch_failed')
        out = {'scope': scope, 'browser_version': data['browser_version'],
               'ipv4': ip_result(data.get('ipv4', {})), 'ipv6': ip_result(data.get('ipv6', {})),
               'tor': ip_result(data.get('tor', {})), 'webrtc': sanitize_webrtc(data.get('webrtc', {})),
               'dns': dns_result(proxy, ident, data.get('dns', {}).get('attempted', 0)),
               'isolated_profile': True, 'existing_sessions_untouched': True,
               'webrtc_policy': {'source': 'project_browser_launcher',
                                 'configured': guarded, 'ip_handling_policy': 'disable_non_proxied_udp' if guarded else 'default'}}
        return out
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'scope': scope, 'status': 'browser_probe_failed',
                'error_code': 'isolated_browser_unavailable', 'dns': {'status': 'not_run', 'resolvers': []},
                'webrtc': {'status': 'unavailable', 'public_candidates': []}}


def classify_browser(browser, system_dns, expected_tor):
    dns = browser['dns']
    seen = {x['ip'] for x in dns.get('resolvers', [])}
    control = {x['ip'] for x in system_dns.get('resolvers', [])}
    overlap = sorted(seen & control)
    dns_status = ('system_resolver_overlap_risk' if overlap else
                  'no_system_resolver_overlap_observed' if seen and control else
                  'resolver_observed_no_comparison' if seen else dns.get('status', 'not_run'))
    # Resolver IP overlap is a warning, not proof: remote and local paths may use
    # the same public resolver. Country/ASN differences alone are not verdicts.
    rtc = browser['webrtc']
    public = rtc.get('public_candidates', [])
    http_ips = {browser.get(k, {}).get('ip') for k in ('ipv4', 'ipv6', 'tor')}
    mismatches = [x['ip'] for x in public if x['ip'] not in http_ips]
    if expected_tor and any(x.get('protocol') == 'udp' and x.get('type') == 'srflx' for x in public):
        rtc_status = 'udp_outside_tor_observed'
    elif mismatches:
        rtc_status = 'public_egress_mismatch_risk'
    elif public:
        rtc_status = 'public_address_exposed_matches_observed_http'
    elif rtc.get('private_address_candidate_count', 0):
        rtc_status = 'local_address_exposed'
    elif rtc.get('errors') or rtc.get('status') != 'complete':
        rtc_status = 'stun_unreachable_or_incomplete'
    else:
        rtc_status = 'no_ip_candidate_exposed_in_probe'
    return {'dns_status': dns_status, 'dns_overlap': overlap, 'webrtc_status': rtc_status,
            'webrtc_public_egress_mismatches': sorted(set(mismatches))}


def run_active_checks():
    settings = request('/api/settings')
    server = next(s for s in request('/api/mcp')['servers'] if s['name'] == 'browser')
    args = server.get('args') or []
    proxy = args[args.index('--proxy-server') + 1] if '--proxy-server' in args else None
    # Never turn a missing/malformed proxy into implicit direct traffic.
    parsed = urlsplit(proxy or '')
    if parsed.scheme not in ('http', 'https', 'socks5', 'socks5h') or not parsed.hostname or parsed.username:
        return {'status': 'configuration_error', 'reason': 'explicit_browser_proxy_required'}
    bypass = args[args.index('--proxy-bypass') + 1] if '--proxy-bypass' in args else ''
    expected_tor = proxy == 'http://localhost:18118'
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        jobs = {'project_' + name: pool.submit(lambda u=url: ip_result(curl(u, proxy)))
                for name, url in ENDPOINTS.items()}
        jobs['windows_system_ipv4'] = pool.submit(lambda: ip_result(curl(ENDPOINTS['ipv4'], None, windows=True, family=4)))
        jobs['windows_system_ipv6'] = pool.submit(lambda: ip_result(curl(ENDPOINTS['ipv6'], None, windows=True, family=6)))
        jobs['windows_system_dns'] = pool.submit(windows_dns, proxy)
        jobs['artex_browser'] = pool.submit(browser_probe, proxy, bypass)
        jobs['windows_edge'] = pool.submit(browser_probe, proxy, bypass, windows=True)
        results = {name: future.result() for name, future in jobs.items()}
    for key in ('artex_browser', 'windows_edge'):
        results[key]['assessment'] = classify_browser(results[key], results['windows_system_dns'], expected_tor)
    risks = []
    if expected_tor and results['project_tor'].get('is_tor') is False:
        risks.append('project_http_not_tor')
    for key in ('artex_browser', 'windows_edge'):
        browser = results[key]
        if expected_tor and browser.get('tor', {}).get('is_tor') is False:
            risks.append(key + ':http_not_tor')
        a = browser['assessment']
        if a['dns_status'] == 'system_resolver_overlap_risk':
            risks.append(key + ':dns_overlap_needs_review')
        if a['webrtc_status'] in ('udp_outside_tor_observed', 'public_egress_mismatch_risk', 'local_address_exposed'):
            risks.append(key + ':' + a['webrtc_status'])
    observed = sum(results[k].get('status') == 'observed' for k in ('project_ipv4', 'project_ipv6', 'project_tor'))
    attempted = ['ipv4_egress', 'ipv6_egress', 'proxy_bypass']
    if results['windows_system_dns'].get('attempted') or any(results[k]['dns'].get('attempted') for k in ('artex_browser', 'windows_edge')):
        attempted.append('dns_path')
    if any(results[k]['webrtc'].get('status') in ('complete', 'timeout') for k in ('artex_browser', 'windows_edge')):
        attempted.append('webrtc')
    return {'status': 'risk' if risks else 'observed_with_limits' if observed else 'probe_failed',
            'scope': 'Windows system controls and new isolated browsers using current ARTEX proxy',
            'proxy': proxy, 'proxy_matches_global_setting': proxy == settings.get('global_proxy'),
            'expected_tor': expected_tor, 'observations': results, 'risk_flags': risks,
            'attempted_items': attempted,
            'external_probe_performed': True, 'configuration_changed': False,
            'limitations': ['Isolated browser observations cover new probe instances; see task_observation separately for passive task process evidence',
                            'Windows system controls omit an application proxy but do not bypass an OS VPN or TUN',
                            'No overlap in a finite DNS sample does not prove every DNS request is protected',
                            'A failed or timed-out probe is not a clean leak result',
                            'Tor may use different exits for concurrent destinations and later connections']}


if __name__ == '__main__':
    print(json.dumps(run_active_checks(), ensure_ascii=False))
