"""Project-local stdio tool allowlist for upstream MCPs. No remote transport."""
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

RULES = {
    'files-ro': {'read_file','read_text_file','read_multiple_files','list_directory','list_directory_with_sizes','directory_tree','search_files','get_file_info','list_allowed_directories'},
    'files-rw': {'read_file','read_text_file','read_multiple_files','list_directory','list_directory_with_sizes','directory_tree','search_files','get_file_info','list_allowed_directories','write_file','edit_file','create_directory'},
    'git-ro': {'git_status','git_diff_unstaged','git_diff_staged','git_diff','git_log','git_show'},
    'semgrep-local': {'semgrep_scan_with_custom_rule'},
}

def main():
    mode = sys.argv[1]
    allowed = RULES[mode]
    command = sys.argv[2:]
    if not command:
        raise SystemExit('missing upstream command')
    child = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr,text=True,encoding='utf-8',bufsize=1)
    out_lock, in_lock = threading.Lock(), threading.Lock()
    pending = {}

    def output(message):
        with out_lock:
            print(json.dumps(message,separators=(',',':')),flush=True)

    def forward(message):
        with in_lock:
            child.stdin.write(json.dumps(message,separators=(',',':'))+'\n')
            child.stdin.flush()

    def upstream():
        for line in child.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get('method')=='roots/list':
                forward({'jsonrpc':'2.0','id':message['id'],'result':{'roots':[]}})
                continue
            method = pending.pop(str(message.get('id')),None)
            if method=='tools/list' and 'result' in message:
                message['result']['tools'] = [t for t in message['result'].get('tools',[]) if t['name'] in allowed]
            output(message)
        # EOF must reach the caller even when stdin is still waiting for a request.
        os._exit(child.wait())

    worker = threading.Thread(target=upstream,daemon=True)
    worker.start()
    try:
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            method = message.get('method')
            if method=='initialize':
                message.setdefault('params',{}).setdefault('capabilities',{}).pop('roots',None)
            if method=='notifications/roots/list_changed':
                continue
            if method=='tools/call':
                params = message.get('params',{})
                if params.get('name') not in allowed:
                    output({'jsonrpc':'2.0','id':message.get('id'),'error':{'code':-32601,'message':'Tool not permitted by this scoped MCP instance'}})
                    continue
                arguments = params.get('arguments',{})
                if mode=='git-ro':
                    scope = Path(os.environ['ARTEX_GIT_ROOT']).resolve()
                    raw = arguments.get('repo_path','')
                    repo = Path(raw).resolve() if raw else None
                    if repo is None or not repo.is_relative_to(scope):
                        output({'jsonrpc':'2.0','id':message.get('id'),'error':{'code':-32602,'message':'Repository outside approved scope'}})
                        continue
            if 'id' in message and method:
                pending[str(message['id'])] = method
            forward(message)
    finally:
        try:
            child.stdin.close()
            child.wait(timeout=5)
        except (OSError,subprocess.TimeoutExpired):
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()

if __name__=='__main__':
    main()
