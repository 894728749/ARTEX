#!/usr/bin/env bash
# Source into the MCP child only. This file does not change system settings.
export ARTEX_INTEGRATIONS_ROOT="${ARTEX_INTEGRATIONS_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
export ARTEX_NODE="${ARTEX_NODE:-node}"
export ARTEX_API_BASE="${ARTEX_API_BASE:-http://localhost:8787}"
export ARTEX_POWERSHELL="${ARTEX_POWERSHELL:-/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe}"
export ARTEX_WINDOWS_CURL="${ARTEX_WINDOWS_CURL:-/mnt/c/Windows/System32/curl.exe}"
export ARTEX_WINDOWS_NODE="${ARTEX_WINDOWS_NODE:-/mnt/c/Program Files/nodejs/node.exe}"
export ARTEX_WSL_DISTRO="${ARTEX_WSL_DISTRO:-Ubuntu}"
export ARTEX_WINDOWS_PROXY_PORT="${ARTEX_WINDOWS_PROXY_PORT:-7897}"
if [ -z "${ARTEX_WINDOWS_INTEGRATIONS_ROOT:-}" ] && command -v wslpath >/dev/null 2>&1; then
  export ARTEX_WINDOWS_INTEGRATIONS_ROOT="$(wslpath -w "$ARTEX_INTEGRATIONS_ROOT")"
fi
if [ -n "${ARTEX_WINDOWS_INTEGRATIONS_ROOT:-}" ]; then
  export ARTEX_PRIVACY_COLLECTOR="${ARTEX_PRIVACY_COLLECTOR:-${ARTEX_WINDOWS_INTEGRATIONS_ROOT}\\tools\\windows_privacy.ps1}"
fi
export PLAYWRIGHT_BROWSERS_PATH="$ARTEX_INTEGRATIONS_ROOT/browsers"
if [ -z "${ARTEX_PRIVACY_CHROMIUM:-}" ]; then
  for playwright_module in "$ARTEX_INTEGRATIONS_ROOT/node/node_modules/playwright" "$ARTEX_INTEGRATIONS_ROOT/node/node_modules/@playwright/mcp/node_modules/playwright"; do
    if [ -d "$playwright_module" ]; then
      export ARTEX_PRIVACY_CHROMIUM="$("$ARTEX_NODE" -e 'console.log(require(process.argv[1]).chromium.executablePath())' "$playwright_module")"
      break
    fi
  done
  export ARTEX_PRIVACY_CHROMIUM="${ARTEX_PRIVACY_CHROMIUM:-$ARTEX_INTEGRATIONS_ROOT/browsers/chromium-1247/chrome-linux64/chrome}"
  unset playwright_module
fi
export PATH="$ARTEX_INTEGRATIONS_ROOT/venv312/bin:$PATH"
mkdir -p "$ARTEX_INTEGRATIONS_ROOT/workspace/evidence" "$ARTEX_INTEGRATIONS_ROOT/workspace/reports/browser"

