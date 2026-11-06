#!/usr/bin/env bash
set -euo pipefail
umask 077
i=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [ -f "$i/runtime.env" ]; then source "$i/runtime.env"; fi
source "$i/bin/runtime-env.sh"
root=${ARTEX_SOURCE_ROOT:?Set ARTEX_SOURCE_ROOT to the checked-out ARTEX source}
i="$ARTEX_INTEGRATIONS_ROOT"
py="$i/venv312/bin/python"
node="$ARTEX_NODE"
mode=${1:?MCP instance required}
shift
export PATH="$i/venv312/bin:$PATH"
export PLAYWRIGHT_BROWSERS_PATH="$i/browsers"
export SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
export DISABLE_THOUGHT_LOGGING=true
case "$mode" in
  planning) exec "$node" "$i/node/node_modules/@modelcontextprotocol/server-sequential-thinking/dist/index.js" "$@" ;;
  files-readonly) exec "$py" "$i/tools/mcp_gate.py" files-ro "$node" "$i/node/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js" "$root" "$i/workspace/evidence" "$i/workspace/reports" ;;
  files-workspace) exec "$py" "$i/tools/mcp_gate.py" files-rw "$node" "$i/node/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js" "$i/workspace" ;;
  git-readonly) export ARTEX_GIT_ROOT="$i/workspace"; exec "$py" "$i/tools/mcp_gate.py" git-ro "$py" -m mcp_server_git ;;
  privacy) exec "$py" "$i/tools/privacy_mcp.py" ;;
  semgrep) exec "$py" "$i/tools/semgrep_mcp.py" ;;
  browser)
    browser_libs="$i/toolchain/browser-libs/root/usr/lib/x86_64-linux-gnu"
    if [ -d "$browser_libs" ]; then
      export LD_LIBRARY_PATH="$browser_libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
    source "$i/bin/proxy-env.sh"
    source "$i/bin/target-proxy-env.sh"
    exec "$node" "$i/node/node_modules/@playwright/mcp/cli.js" --headless --browser chromium --isolated --output-dir "$i/workspace/reports/browser" "$@" --executable-path "$i/tools/chromium_privacy_launcher.py"
    ;;
  fetch) source "$i/bin/proxy-env.sh"; source "$i/bin/target-proxy-env.sh"; exec "$py" -m mcp_server_fetch "$@" ;;
  memory) export MEMORY_FILE_PATH="$i/workspace/knowledge.jsonl"; exec "$node" "$i/node/node_modules/@modelcontextprotocol/server-memory/dist/index.js" "$@" ;;
  burp) exec "${ARTEX_JAVA:-java}" -jar "${ARTEX_BURP_PROXY_JAR:-$i/vendor/burp/mcp-proxy-all.jar}" "$@" ;;
  *) printf 'Unknown project MCP instance\n' >&2; exit 2 ;;
esac
