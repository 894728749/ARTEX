"""Project-local ARTEX maintenance API client; never prints or stores credentials."""
import base64
import os
import hashlib
import hmac
import json
import time
import urllib.request
from pathlib import Path

RUNTIME = Path(os.environ['ARTEX_RUNTIME_ROOT'])
BASE = os.environ.get('ARTEX_API_BASE', 'http://localhost:8787')

def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')

def request(path, payload=None, method=None, timeout=60):
    if not path.startswith('/api/') or '?' in path and 'token=' in path:
        raise ValueError('Only local maintenance API paths are allowed')
    now = int(time.time())
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    claims = _b64(json.dumps({'sub':'ARTEX','iat':now,'exp':now+600},separators=(',',':')).encode())
    unsigned = header + '.' + claims
    key = (RUNTIME / 'jwt.key').read_bytes().strip()
    signature = _b64(hmac.new(key,unsigned.encode(),hashlib.sha256).digest())
    headers = {'Authorization':'Bearer '+unsigned+'.'+signature}
    data = None if payload is None else json.dumps(payload,ensure_ascii=False).encode()
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE+path,data=data,headers=headers,method=method or ('GET' if data is None else 'POST'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as response:
        return json.load(response)

