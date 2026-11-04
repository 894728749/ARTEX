#!/usr/bin/env bash
# Install the pinned REA static-analysis backend beside the ARTEX executable.
# Does not run REA setup or alter Codex/Claude/browser registrations.
set -euo pipefail
root="${1:?Usage: bash scripts/install-rea.sh /absolute/path/to/artex/tools}"
[[ "$root" = /* ]] || { echo 'Use an absolute installation directory' >&2; exit 2; }
mkdir -p "$root"
npm install --prefix "$root" --no-audit --no-fund node@24.22.1
export PATH="$root/node_modules/.bin:$PATH"
npm install --prefix "$root" --omit=optional --ignore-scripts --no-audit --no-fund rea-agents@6.8.0
node --version
rea --version
