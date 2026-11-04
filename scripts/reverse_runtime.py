#!/usr/bin/env python3
"""One owned Frida observation per process, on Linux, Windows or an Android lab.

The ARTEX parent supplies one JSON request on stdin and keeps stdin open. A
second {"cancel":true} line, EOF or termination requests cleanup. No shell is
used. This is process instrumentation, not an operating-system sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


def main():
    # MCP/control JSON is UTF-8 on every host, including Windows launched by
    # a WSL parent whose paths contain non-ASCII characters.
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8')
    request = json.loads(sys.stdin.readline())
    profile = request.get('profile', {})
    if profile.get('python_module_dir'):
        sys.path.insert(0, profile['python_module_dir'])
    import frida
    platform = profile['platform']
    if platform not in ('linux', 'windows', 'android'):
        raise ValueError('unsupported runtime platform')
    if platform != 'android' and (platform == 'windows') != (sys.platform == 'win32'):
        raise ValueError('runtime profile does not match the runner host')
    if request.get('operation') == 'doctor':
        if platform == 'android':
            if not profile.get('allow_package_install') or not profile.get('remote_is_lab'):
                raise ValueError('Android observation requires an explicitly configured lab')
            for field in ('adb', 'aapt'):
                if not Path(profile[field]).is_file(): raise ValueError('Android bridge tools are missing')
            state = subprocess.run([profile['adb'], '-P', str(profile.get('adb_port', 5037)), '-s', profile['adb_serial'], 'get-state'], capture_output=True, timeout=8, check=True)
            if state.stdout.strip() != b'device': raise ValueError('Android lab is not connected')
            remote = profile['remote']
            device = frida.get_device_manager().add_remote_device(remote['address'], **{k: v for k, v in remote.items() if k != 'address'})
            try: device.query_system_parameters()
            finally: frida.get_device_manager().remove_remote_device(profile['remote']['address'])
        print(json.dumps({'available': True, 'engine': 'frida', 'version': frida.__version__, 'host_platform': sys.platform, 'platform': platform}))
        return
    artifact = Path(request['artifact_path']).resolve(strict=True)
    digest = hashlib.file_digest(artifact.open('rb'), 'sha256').hexdigest()
    if digest != request['sha256']:
        raise ValueError('artifact SHA256 changed before runtime admission')
    source = request.get('script', '')
    if not source.strip() or len(source.encode()) > 128 * 1024:
        raise ValueError('provide a nonempty instrumentation script up to 128 KiB')
    duration = max(100, min(int(request.get('duration_ms', 3000)), 60000))
    cancelled = threading.Event()
    def control():
        for line in sys.stdin:
            try:
                if json.loads(line).get('cancel'): break
            except ValueError:
                break
        cancelled.set()
    threading.Thread(target=control, daemon=True).start()
    for name in ('SIGTERM', 'SIGINT', 'SIGBREAK'):
        if hasattr(signal, name): signal.signal(getattr(signal, name), lambda *_: cancelled.set())
    messages, output, errors = [], [], []
    lock = threading.Lock()
    captured = 0
    truncated = False
    def bounded(bucket, value):
        nonlocal captured, truncated
        text = json.dumps(value, ensure_ascii=False)
        with lock:
            if len(messages) + len(output) >= 1000 or captured + len(text.encode()) > 2 * 1024 * 1024:
                truncated = True
                return
            captured += len(text.encode())
            bucket.append(value)
    remote = profile.get('remote')
    if remote:
        if not profile.get('remote_is_lab'):
            raise ValueError('remote instrumentation requires an explicitly configured lab profile')
        device = frida.get_device_manager().add_remote_device(remote['address'], **{k: v for k, v in remote.items() if k != 'address'})
    else:
        device = frida.get_device(profile.get('device_id', 'local'), timeout=10)
    pid = session = script = None
    installed = False
    package = None
    cleanup = {'script_unloaded': False, 'session_detached': False, 'owned_process_terminated': False, 'package_removed': False, 'staging_removed': False}
    started = time.monotonic()
    def adb(*args):
        command = [profile['adb'], '-P', str(profile.get('adb_port', 5037)), '-s', profile['adb_serial'], *args]
        result = subprocess.run(command, capture_output=True, timeout=40, check=False)
        if result.returncode: raise RuntimeError('Android lab bridge operation failed')
        return result.stdout.decode('utf-8', 'replace')
    with tempfile.TemporaryDirectory(prefix='artex-observe-', dir=profile.get('workspace'), ignore_cleanup_errors=True) as stage:
        copied = Path(stage) / ('sample' + artifact.suffix)
        shutil.copyfile(artifact, copied)
        copied.chmod(0o700)
        try:
            if platform == 'android':
                if not profile.get('allow_package_install') or adb('shell', 'getprop', 'ro.kernel.qemu').strip() != '1':
                    raise ValueError('automatic APK observation requires an opted-in emulator profile')
                package = request.get('package_name', '')
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package):
                    raise ValueError('an exact Android package name is required')
                badging = subprocess.run([profile['aapt'], 'dump', 'badging', str(copied)], capture_output=True, timeout=20, check=True).stdout.decode()
                if not re.search(r"^package: name='" + re.escape(package) + r"'", badging, re.M):
                    raise ValueError('Android package does not match the uploaded artifact')
                if adb('shell', 'pm', 'list', 'packages', package).strip():
                    raise ValueError('package already exists in this lab; use a fresh emulator, no existing app is overwritten')
                adb('install', '--no-streaming', str(copied))
                installed = True
                if profile.get('java_interpreter'):
                    # A per-package setting, applied only to this newly installed
                    # sample. Avoids AOT inlining hiding Java method callbacks.
                    adb('shell', 'cmd', 'package', 'compile', '-m', 'verify', '-f', package)
                program = package
            else:
                program = str(copied)
            def on_output(observed_pid, fd, data):
                if observed_pid == pid and data:
                    bounded(output, {'fd': fd, 'text': bytes(data[:16384]).decode('utf-8', 'replace')})
            device.on('output', on_output)
            argv = request.get('argv', [])
            if argv is None: argv = []
            if not isinstance(argv, list) or not all(isinstance(x, str) and '\0' not in x for x in argv):
                raise ValueError('argv must be a string array')
            pid = device.spawn(program) if platform == 'android' else device.spawn([program, *argv], stdio='pipe')
            session = device.attach(pid)
            loaded_source = source
            if platform == 'android' and profile.get('java_bridge_module'):
                bridge = Path(profile['java_bridge_module']).resolve(strict=True)
                entry = Path(stage) / 'observation.js'
                entry.write_text('import Java from ' + json.dumps(str(bridge)) + ';\nglobalThis.Java = Java;\n' + source, encoding='utf-8')
                loaded_source = frida.Compiler().build(str(entry), project_root=stage)
            script = session.create_script(loaded_source)
            # Frida's default console handler writes to stdout and corrupts the
            # runner's single JSON response. Keep logs inside bounded evidence.
            script.set_log_handler(lambda level, text: bounded(messages, {
                'elapsed_ms': round((time.monotonic() - started) * 1000),
                'message': {'type': 'log', 'level': level, 'payload': text}}))
            def on_message(message, data):
                if message.get('type') == 'error': errors.append('instrumentation script reported an error')
                bounded(messages, {'elapsed_ms': round((time.monotonic() - started) * 1000), 'message': message,
                                   'data_sha256': hashlib.sha256(data).hexdigest() if data else None})
            script.on('message', on_message)
            script.load()
            device.resume(pid)
            end = time.monotonic() + duration / 1000
            while time.monotonic() < end and not cancelled.wait(.05):
                if session.is_detached: break
        except Exception as exc:
            errors.append('observation failed: ' + type(exc).__name__)
        finally:
            if script:
                try: script.unload(); cleanup['script_unloaded'] = True
                except frida.InvalidOperationError: cleanup['script_unloaded'] = True
                except Exception: errors.append('script cleanup failed')
            if session:
                try: session.detach(); cleanup['session_detached'] = True
                except frida.InvalidOperationError: cleanup['session_detached'] = True
                except Exception: errors.append('session cleanup failed')
            if pid:
                try: device.kill(pid); cleanup['owned_process_terminated'] = True
                except frida.ProcessNotFoundError: cleanup['owned_process_terminated'] = True
                except Exception: errors.append('owned process cleanup failed')
            if installed:
                try: adb('uninstall', package); cleanup['package_removed'] = True
                except Exception: errors.append('owned lab package cleanup failed')
            if remote:
                try: frida.get_device_manager().remove_remote_device(remote['address'])
                except Exception: errors.append('remote connection cleanup failed')
            # Windows process termination can return before the image mapping is
            # released. Only retry removal of this run's own staged image.
            if sys.platform == 'win32' and cleanup['owned_process_terminated']:
                for attempt in range(50):
                    try: copied.unlink(missing_ok=True); break
                    except PermissionError: time.sleep(.1)
    cleanup['staging_removed'] = not Path(stage).exists()
    if not cleanup['staging_removed']: errors.append('owned staging cleanup failed')
    result = {'engine': 'frida', 'version': frida.__version__, 'platform': platform, 'artifact_sha256': digest,
              'script_sha256': hashlib.sha256(source.encode()).hexdigest(), 'messages': messages, 'output': output,
              'duration_ms': round((time.monotonic() - started) * 1000), 'cancelled': cancelled.is_set(),
              'truncated': truncated, 'cleanup': cleanup, 'errors': errors,
              'limitations': ['Observations cover only this sample, instrumentation script and observation window.',
                              'The configured runtime uses the host permissions; process separation is not a sandbox.'],
              'runtime_settings': {'java_interpreter': bool(profile.get('java_interpreter'))}}
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        # Never reflect remote tokens, full process arguments or connection strings.
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc)[:300]}), flush=True)
        raise SystemExit(1)
