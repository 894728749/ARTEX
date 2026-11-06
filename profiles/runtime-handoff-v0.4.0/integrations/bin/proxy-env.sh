#!/usr/bin/env bash
# Source only into ARTEX or an installation process. Never changes system settings.
_artex_proxy_wait=${ARTEX_PROXY_WAIT_SECONDS:-90}
case "$_artex_proxy_wait" in
  ''|*[!0-9]*)
    printf 'ARTEX proxy: ARTEX_PROXY_WAIT_SECONDS must be an integer between 1 and 90\n' >&2
    unset _artex_proxy_wait
    return 1
    ;;
esac
if [ "${#_artex_proxy_wait}" -gt 3 ]; then
  printf 'ARTEX proxy: ARTEX_PROXY_WAIT_SECONDS must be between 1 and 90 seconds\n' >&2
  unset _artex_proxy_wait
  return 1
fi
if [ "$_artex_proxy_wait" -lt 1 ] || [ "$_artex_proxy_wait" -gt 90 ]; then
  printf 'ARTEX proxy: ARTEX_PROXY_WAIT_SECONDS must be between 1 and 90 seconds\n' >&2
  unset _artex_proxy_wait
  return 1
fi
_artex_proxy_wait=$((10#$_artex_proxy_wait))
_artex_proxy_url=$(ARTEX_PROXY_WAIT_SECONDS="$_artex_proxy_wait" python3 - <<'PY'
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time

try:
    wait = int(os.environ.get('ARTEX_PROXY_WAIT_SECONDS', '90'), 10)
except ValueError:
    print('ARTEX proxy: invalid wait override', file=sys.stderr)
    raise SystemExit(1)
if wait < 1 or wait > 90:
    print('ARTEX proxy: wait override must be between 1 and 90 seconds', file=sys.stderr)
    raise SystemExit(1)

proxy_port = int(os.environ.get('ARTEX_WINDOWS_PROXY_PORT', '7897'))
if not 1 <= proxy_port <= 65535: raise SystemExit('Invalid proxy port')
deadline = time.monotonic() + wait
attempt = 0
last_error = 'no WSL default gateway'

while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        break
    attempt += 1
    gateway = None

    # Refresh the default gateway on every attempt: WSL may replace it.
    try:
        raw = subprocess.check_output(
            ['ip', '-j', 'route', 'show', 'default'],
            stderr=subprocess.DEVNULL,
            timeout=max(0.2, min(3.0, remaining)),
        )
        routes = json.loads(raw.decode('utf-8', 'replace'))
        if not isinstance(routes, list):
            raise ValueError
        gateways = [
            route.get('gateway')
            for route in routes
            if isinstance(route, dict) and route.get('gateway')
        ]
        if not gateways:
            raise ValueError
        gateway = str(ipaddress.ip_address(gateways[0]))
    except (OSError, subprocess.SubprocessError, ValueError):
        last_error = 'could not determine the WSL default gateway'

    if gateway is not None:
        endpoint = 'http://%s:%s' % (gateway, proxy_port)
        print(
            'ARTEX proxy: waiting for Windows proxy %s (attempt %d)'
            % (endpoint, attempt),
            file=sys.stderr,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with socket.create_connection(
                (gateway, proxy_port), timeout=max(0.2, min(3.0, remaining))
            ):
                print(
                    'ARTEX proxy: ready at %s (attempt %d)' % (endpoint, attempt),
                    file=sys.stderr,
                )
                print(endpoint)
                raise SystemExit(0)
        except OSError:
            last_error = 'Windows configured proxy port is unavailable at %s' % endpoint

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        break
    time.sleep(min(2.0, remaining))

print(
    'ARTEX proxy: failed after %ss: %s; Windows proxy must be listening on '
    'the WSL configured gateway port; startup stopped (no direct fallback)'
    % (wait, last_error),
    file=sys.stderr,
)
raise SystemExit(1)
PY
) || {
  unset _artex_proxy_wait _artex_proxy_url
  return 1
}
export HTTP_PROXY="$_artex_proxy_url" HTTPS_PROXY="$_artex_proxy_url" ALL_PROXY="$_artex_proxy_url"
export http_proxy="$_artex_proxy_url" https_proxy="$_artex_proxy_url" all_proxy="$_artex_proxy_url"
export NO_PROXY='localhost,127.0.0.1,::1' no_proxy='localhost,127.0.0.1,::1'
unset _artex_proxy_wait _artex_proxy_url
