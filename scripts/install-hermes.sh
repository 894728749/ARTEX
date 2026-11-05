#!/usr/bin/env bash
set -euo pipefail
root="${1:?Usage: bash scripts/install-hermes.sh /absolute/path/to/hermes-venv}"
[[ "$root" = /* && "$root" != / ]] || exit 2
python3 -m venv --without-pip "$root"
# The fixed wheel has no runtime dependencies. Installing its verified contents
# avoids requiring ensurepip or changing the system Python environment.
"$root/bin/python" - <<'PY'
import hashlib, io, pathlib, sysconfig, urllib.request, zipfile
url='https://files.pythonhosted.org/packages/79/46/4db716ac625ba3cf40c666fb83450c310b7c400e682ecc9b26b02eea0a32/hermes_dec-0.1.8-py3-none-any.whl'
with urllib.request.urlopen(url,timeout=60) as response:
    wheel=response.read(8*1024*1024)
assert hashlib.sha256(wheel).hexdigest()=='6be7858a11edc3bc27d37abad65c80a36b51683283eed6331cd5c7d3fb399a4c','Hermes wheel hash mismatch'
with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
    archive.extractall(pathlib.Path(sysconfig.get_path('purelib')))
PY
printf 'Set ARTEX_HERMES_PYTHON=%s/bin/python for the ARTEX process.\n' "$root"
