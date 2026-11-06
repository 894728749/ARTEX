#!/usr/bin/env bash
# Explicit local dependency installation only; does not import profiles/start ARTEX.
set -euo pipefail
umask 077
i=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python_bin=${ARTEX_PYTHON_BOOTSTRAP:-python3.12}
command -v "$python_bin" >/dev/null
command -v node >/dev/null
command -v npm >/dev/null
"$python_bin" -c 'import sys; assert sys.version_info[:2] == (3,12), "Use Python 3.12"'
node -e 'if(Number(process.versions.node.split(".")[0])<20)process.exit(1)'
if [ ! -e "$i/venv312" ]; then "$python_bin" -m venv "$i/venv312"; fi
"$i/venv312/bin/python" -m pip install -r "$i/python-requirements.lock.txt"
(cd "$i/node" && npm ci)
export PLAYWRIGHT_BROWSERS_PATH="$i/browsers"
cli="$i/node/node_modules/playwright/cli.js"
if [ ! -f "$cli" ]; then cli="$i/node/node_modules/@playwright/mcp/node_modules/playwright/cli.js"; fi
node "$cli" install chromium
chmod +x "$i/bin/"*.sh "$i/tools/chromium_privacy_launcher.py"
printf '%s\n' 'Dependencies installed. No Agent/MCP/task was enabled or started.'
printf '%s\n' 'If Linux browser libraries are missing, review and run: node <the same playwright/cli.js> install-deps chromium'
printf '%s\n' 'Before running MCPs, copy runtime.env.example to runtime.env and fill in your own paths.'
