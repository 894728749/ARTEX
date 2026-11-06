"""Offline Semgrep adapter. Scans supplied code with supplied local rules only."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
import yaml
from mcp.server.fastmcp import FastMCP

ROOT = Path(os.environ['ARTEX_INTEGRATIONS_ROOT'])
mcp = FastMCP('artex-semgrep-local')
LANGUAGES = {'python':'.py','javascript':'.js','typescript':'.ts','go':'.go','java':'.java','c':'.c','cpp':'.cpp','ruby':'.rb','php':'.php','generic':'.txt'}

@mcp.tool()
def semgrep_scan_with_custom_rule(code: str, rules_yaml: str, language: str) -> dict:
    """Scan supplied code offline using a self-contained Semgrep YAML rules document. No filesystem path, URL, registry config, account, API key, or cloud scan is accepted."""
    if language not in LANGUAGES or len(code)>500_000 or len(rules_yaml)>100_000:
        return {'status':'error','reason':'unsupported_language_or_input_limit'}
    try:
        rules=yaml.safe_load(rules_yaml)
        if not isinstance(rules,dict) or set(rules)!={'rules'} or not isinstance(rules['rules'],list) or not 1<=len(rules['rules'])<=20:
            raise ValueError()
        for rule in rules['rules']:
            if not isinstance(rule,dict) or rule.get('mode','search')!='search' or rule.get('languages')!=[language]:
                raise ValueError()
        serialized=json.dumps(rules)
        if any(term in serialized for term in ('validator','extract','http://','https://')):
            raise ValueError()
    except (ValueError,TypeError,yaml.YAMLError):
        return {'status':'error','reason':'invalid_self_contained_search_rules'}
    temporary=ROOT/'workspace/semgrep-tmp'
    temporary.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='scan-',dir=temporary) as folder:
        path=Path(folder)
        source=path/('input'+LANGUAGES[language])
        source.write_text(code,encoding='utf-8')
        config=path/'rules.yaml'
        config.write_text(yaml.safe_dump(rules),encoding='utf-8')
        env=dict(os.environ,SEMGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0')
        try:
            process=subprocess.run([str(ROOT/'venv312/bin/semgrep'),'scan','--config',str(config),'--metrics=off','--disable-version-check','--no-git-ignore','--json',str(source)],cwd=folder,env=env,capture_output=True,timeout=45)
            data=json.loads(process.stdout)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            return {'status':'error','reason':'local_scan_unavailable_or_timed_out'}
        if process.returncode!=0 or data.get('errors'):
            return {'status':'error','reason':'local_rule_or_scan_error','error_count':len(data.get('errors',[]))}
        return {'status':'completed','engine':'semgrep-local','cloud_scan':False,'findings':[{'rule_id':r['check_id'],'line':r['start']['line'],'end_line':r['end']['line'],'severity':r.get('extra',{}).get('severity')} for r in data.get('results',[])], 'limitations':['Pattern matches are candidate findings; impact is not independently validated']}

if __name__=='__main__':
    mcp.run(transport='stdio')
