#!/usr/bin/env python3
"""Export/apply an ARTEX local-team profile using psql and the runtime config.

Source export is always a read-only transaction. Apply requires an explicit
target database name different from the source database. No tasks are started.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECRET_KEY = re.compile(r'(pass(word)?|secret|token|api.?key|authorization|cookie|credential|private.?key)', re.I)
IPV4 = re.compile(r'(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])')
URL = re.compile(r'(?i)\b(https?://)([^/\s:@]+(?::[^/@\s]*)?@)?([^/\s?#]+)')
DOMAIN = re.compile(r'(?i)(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|local|internal|test|cn|uk|info|ai|xyz|me|site|cloud|tech|edu|gov|co)(?![\w])')
ABS_PATH = re.compile(r'(?i)(?:[A-Z]:\\[^\s"\']+|/(?:home|mnt|opt|var|tmp)/[^\s"\']+)')
TASK_ID = re.compile(r'(?i)(\btask\s*#?\s*|任务\s*#?\s*)\d+')


def load_config(config_arg=None):
    cfg = config_arg or os.environ.get('ARTEX_CONFIG')
    if not cfg:
        raise ValueError('set ARTEX_CONFIG to the runtime config file; its value is never written to the profile')
    p = Path(cfg)
    return json.loads(p.read_text(encoding='utf-8'))


def env_for(db, database=None, pg_lib=None):
    e = os.environ.copy()
    if pg_lib:
        e['LD_LIBRARY_PATH'] = str(pg_lib) + (':' + e['LD_LIBRARY_PATH'] if e.get('LD_LIBRARY_PATH') else '')
    e['PGHOST'] = str(db.get('host', 'localhost'))
    e['PGPORT'] = str(db.get('port', 5432))
    e['PGUSER'] = str(db.get('user', ''))
    e['PGPASSWORD'] = str(db.get('password', ''))
    e['PGDATABASE'] = database or str(db.get('dbname', ''))
    e['PGSSLMODE'] = str(db.get('sslmode', 'prefer'))
    e['PGCONNECT_TIMEOUT'] = '5'
    return e


def psql(sql, db, database=None, *, readonly=False, check=True, psql_bin=None, pg_lib=None):
    binary = psql_bin or os.environ.get('ARTEX_PROFILE_PSQL') or shutil.which('psql')
    if not binary:
        raise ValueError('provide --psql or put psql on PATH')
    args = [str(binary), '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1']
    if readonly:
        sql = 'BEGIN READ ONLY;\n' + sql + '\nROLLBACK;'
    r = subprocess.run(args, input=sql, text=True, capture_output=True,
                       env=env_for(db, database, pg_lib), cwd=ROOT)
    if check and r.returncode:
        # psql error text can contain connection details; never echo it.
        raise RuntimeError('psql failed; see local stderr with credential values redacted')
    return r.stdout.strip()


def scrub(value, key=''):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if SECRET_KEY.search(k) and isinstance(v, str) and v and not re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}', v):
                env_name = 'ARTEX_' + re.sub(r'[^A-Z0-9]+', '_', str(k).upper()).strip('_')
                out[k] = '${' + env_name + '}'
            else:
                out[k] = scrub(v, k)
        return out
    if isinstance(value, list):
        return [scrub(v, key) for v in value]
    if not isinstance(value, str):
        return value
    s = value
    if s.startswith('${') and s.endswith('}'):
        return s
    s = URL.sub(lambda m: m.group(1) + ('${ARTEX_PRIVATE_MCP_HOST}' if is_private_host(m.group(3)) else m.group(3)), s)
    s = IPV4.sub('${PRIVATE_IP}', s)
    s = ABS_PATH.sub('${ARTEX_INSTALL_PATH}', s)
    s = TASK_ID.sub(lambda m: m.group(1) + '${TASK_ID}', s)
    s = DOMAIN.sub('${PRIVATE_HOST}', s)
    # Secret-looking assignments in prompt/trigger prose are never retained.
    s = re.sub(r'(?i)\b(password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[^\s,;]+', r'\1=${ARTEX_SECRET}', s)
    s = re.sub(r'(?i)(["\'](?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)["\']\s*:\s*)["\'][^"\']*["\']', r'\1"${ARTEX_SECRET}"', s)
    return s


def is_private_ip(value):
    try:
        import ipaddress
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_private_host(host):
    h = host.rsplit(':', 1)[0].strip('[]').lower()
    if h in {'localhost'} or h.endswith(('.local', '.internal', '.lan', '.home')) or '.' not in h:
        return True
    return is_private_ip(h)


def prepare_profile(raw):
    # Give each secret/endpoint its own install-time variable so different
    # providers and MCP servers retain their independent values.
    for m in raw.get('mcps', []):
        slug = re.sub(r'[^A-Z0-9]+', '_', m['name'].upper()).strip('_')
        if m.get('url'):
            h = URL.search(m['url'])
            if h and is_private_host(h.group(3)):
                m['url'] = '${ARTEX_MCP_' + slug + '_URL}'
        if isinstance(m.get('env'), dict):
            for k, v in list(m['env'].items()):
                if SECRET_KEY.search(k) and v not in (None, ''):
                    m['env'][k] = '${ARTEX_MCP_' + slug + '_' + re.sub(r'[^A-Z0-9]+', '_', k.upper()).strip('_') + '}'
        if m.get('command'):
            m['command'] = scrub_command(m['command'], 'ARTEX_MCP_' + slug + '_COMMAND')
        m['args'] = scrub_args(m.get('args', []), 'ARTEX_MCP_' + slug + '_ARG')
    for l in raw.get('llm_profiles', []):
        slug = re.sub(r'[^A-Z0-9]+', '_', l['name'].upper()).strip('_')
        if l.get('api_key'):
            l['api_key'] = '${ARTEX_LLM_' + slug + '_API_KEY}'
        for k in ('base_url', 'proxy'):
            if l.get(k):
                l[k] = scrub(l[k])
                if '${PRIVATE_HOST}' in l[k] or '${ARTEX_PRIVATE_MCP_HOST}' in l[k]:
                    l[k] = '${ARTEX_LLM_' + slug + '_' + k.upper() + '}'
    return scrub(raw)


def scrub_command(value, env_name):
    if value.startswith('/') or re.match(r'(?i)^[A-Z]:\\', value):
        return '${' + env_name + '}'
    return scrub(value)


def scrub_args(value, env_prefix):
    if isinstance(value, list):
        return [('${' + env_prefix + '_' + str(i) + '}' if isinstance(v, str) and (v.startswith('/') or re.match(r'(?i)^[A-Z]:\\',v)) else scrub_args(v, env_prefix + '_' + str(i))) for i,v in enumerate(value)]
    if isinstance(value, dict):
        return {k: scrub_args(v, env_prefix + '_' + re.sub(r'[^A-Z0-9]+','_',k.upper())) for k,v in value.items()}
    return scrub(value)


EXPORT_SQL = r'''
SELECT json_build_object(
 'agents', (SELECT COALESCE(json_agg(x ORDER BY x->>'key'),'[]'::json) FROM (
   SELECT json_build_object('key',a.key,'name',a.name,'description',COALESCE(a.description,''),'role',a.role,'builtin',a.builtin,'enabled',a.enabled,
   'max_turns',a.max_turns,'run_seconds',a.run_seconds,'web_search',a.web_search,'interactive_shell',a.interactive_shell,
   'wrapup_prompt',a.wrapup_prompt,'wrapup_max_turns',a.wrapup_max_turns,'task_timeout_wrapup_prompt',a.task_timeout_wrapup_prompt,
   'task_timeout_wrapup_max_turns',a.task_timeout_wrapup_max_turns,'trigger_run_mode',a.trigger_run_mode,'trigger_merge_mode',a.trigger_merge_mode,
   'trigger_max_parallel',a.trigger_max_parallel,'llm_profile',lp.name,'prompt',COALESCE(p.template_text,''),
   'prompt_vars',(SELECT COALESCE(json_agg(json_build_object('name',v.var_name,'description',v.description,'example',v.example,'source',v.source) ORDER BY v.var_name),'[]'::json) FROM agent_prompt_vars v WHERE v.agent_id=a.id),
   'mcp_bindings',(SELECT COALESCE(json_agg(json_build_object('server',m.name,'tool',av.mcp_tool_name,'enabled',av.enabled) ORDER BY m.name,av.mcp_tool_name),'[]'::json) FROM agent_visibility av JOIN mcp_servers m ON m.id=av.resource_id WHERE av.agent_id=a.id),
   'skills',(SELECT COALESCE(json_agg(json_build_object('name',sv.skill_name,'enabled',sv.enabled) ORDER BY sv.skill_name),'[]'::json) FROM agent_skill_visibility sv WHERE sv.agent_id=a.id),
   'triggers',(SELECT COALESCE(json_agg(json_build_object('enabled',t.enabled,'interval_sec',t.interval_sec,'on_finding',t.on_finding,'on_goal_met',t.on_goal_met,'on_task_timeout',t.on_task_timeout,'on_tool_call',t.on_tool_call,'on_task_create',t.on_task_create,'interval_message',t.interval_message,'finding_message',t.finding_message,'goal_message',t.goal_message,'task_timeout_message',t.task_timeout_message,'tool_call_message',t.tool_call_message,'task_create_message',t.task_create_message,'tool_names',t.tool_names) ORDER BY t.id),'[]'::json) FROM agent_triggers t WHERE t.agent_key=a.key)
   ) AS x FROM agents a LEFT JOIN llm_profiles lp ON lp.id=a.llm_profile_id LEFT JOIN agent_prompts p ON p.id=a.current_prompt_id
 ) q),
 'llm_profiles',(SELECT COALESCE(json_agg(json_build_object('name',name,'format',format,'base_url',base_url,'proxy',proxy,'model',model,'api_key',CASE WHEN COALESCE(api_key,'')='' THEN '' ELSE '${ARTEX_LLM_API_KEY}' END,'rate_per_second',rate_per_second,'rate_per_minute',rate_per_minute,'context_window_k',context_window_k,'reasoning_effort',reasoning_effort,'thinking_type',thinking_type,'is_default',is_default,'priority',priority,'pool_exclude',pool_exclude,'streaming',streaming,'max_tokens',max_tokens,'max_tokens_field',max_tokens_field,'session_header_key',session_header_key) ORDER BY name),'[]'::json) FROM llm_profiles),
 'mcps',(SELECT COALESCE(json_agg(json_build_object('name',m.name,'transport',m.transport,'command',m.command,'args',m.args,'env',m.env,'url',m.url,'enabled',m.enabled,'insecure',m.insecure,'tools',(SELECT COALESCE(json_agg(json_build_object('name',c.tool_name,'description',c.description) ORDER BY c.tool_name),'[]'::json) FROM mcp_tools_cache c WHERE c.server_id=m.id)) ORDER BY m.name),'[]'::json) FROM mcp_servers m),
 'tools',(SELECT COALESCE(json_agg(json_build_object('key',key,'system',system,'description',description,'schema',schema,'agents',agents,'enabled',enabled,'kind',kind,'exec',exec,'deferred',deferred) ORDER BY key),'[]'::json) FROM tools)
)::text;
'''


def sqlq(s):
    return "'" + str(s).replace("'", "''") + "'"


def resolve_env(obj):
    if isinstance(obj, dict): return {k: resolve_env(v) for k, v in obj.items()}
    if isinstance(obj, list): return [resolve_env(v) for v in obj]
    if isinstance(obj, str):
        def sub(m):
            name = m.group(1)
            if name in {'PRIVATE_HOST', 'PRIVATE_IP', 'ARTEX_SECRET', 'TASK_ID', 'ARTEX_INSTALL_PATH', 'ARTEX_PRIVATE_MCP_HOST'}:
                return '${' + name + '}'
            val = os.environ.get(name)
            if val is None: raise ValueError('required environment variable is unset: ' + name)
            return val
        return re.sub(r'\$\{([A-Z][A-Z0-9_]*)\}', sub, obj)
    return obj


def export(path):
    cfg = load_config(ARGS.config)
    db = cfg['database']
    raw = json.loads(psql(EXPORT_SQL, db, readonly=True, psql_bin=ARGS.psql, pg_lib=ARGS.pg_lib))
    data = prepare_profile(raw)
    data = {'schema_version': 1, 'profile': 'local-team', 'source_release': 'ARTEX-0.3.15', **data}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    skill_root = ARGS.skill_root or cfg.get('skill_dir') or os.environ.get('ARTEX_SKILL_DIR')
    if not ARGS.integration_root or not ARGS.skill_source or not ARGS.collector_source or not skill_root:
        raise ValueError('--integration-root, --skill-root, --skill-source, and --collector-source are required to package the complete profile')
    package_gateway(Path(path).parent, Path(ARGS.integration_root), Path(skill_root), Path(ARGS.skill_source), Path(ARGS.collector_source), data['agents'])
    print('profile exported; no credentials, task records, runtime artifacts, or connection settings were written')


def package_gateway(profile_dir, integration_root, skill_root, skill_source, collector_source, agents):
    src_tools = integration_root / 'tools'
    dst_tools = profile_dir / 'gateway/integrations/tools'
    dst_tools.mkdir(parents=True, exist_ok=True)
    for name in ('privacy_mcp.py','privacy_active_probe.py','privacy_task_observer.py','privacy_browser_probe.cjs','chromium_privacy_launcher.py','artex_api.py'):
        src = src_tools / name
        if not src.is_file():
            if name == 'windows_privacy.ps1':
                continue
            raise ValueError('gateway dependency missing: ' + name)
        content = src.read_text(encoding='utf-8')
        if name == 'privacy_mcp.py':
            content = content.replace('import json\n', 'import json\nimport os\n')
            content = re.sub(r"ROOT = Path\([^\n]+\)", "ROOT = Path(os.environ['ARTEX_INTEGRATIONS_ROOT'])", content)
            content = re.sub(r"PS = [^\n]+", "PS = os.environ['ARTEX_POWERSHELL']", content)
            content = re.sub(r"COLLECTOR = [^\n]+", "COLLECTOR = os.environ['ARTEX_PRIVACY_COLLECTOR']", content)
        elif name == 'privacy_active_probe.py':
            content = content.replace('from artex_api import request, RUNTIME', 'from artex_api import request')
            content = re.sub(r"ROOT = RUNTIME.parent / 'integrations'", "ROOT = Path(os.environ['ARTEX_INTEGRATIONS_ROOT'])", content)
            content = re.sub(r"WIN_ROOT = [^\n]+", "WIN_ROOT = os.environ['ARTEX_WINDOWS_INTEGRATIONS_ROOT']", content)
            content = re.sub(r"PS = [^\n]+", "PS = os.environ['ARTEX_POWERSHELL']", content)
            content = re.sub(r"WIN_CURL = [^\n]+", "WIN_CURL = os.environ['ARTEX_WINDOWS_CURL']", content)
            content = re.sub(r"WIN_NODE = [^\n]+", "WIN_NODE = os.environ['ARTEX_WINDOWS_NODE']", content)
            content = content.replace("'/home/cyc/.local/bin/node'", "os.environ.get('ARTEX_NODE', 'node')")
        elif name == 'artex_api.py':
            content = content.replace('import base64\n', 'import base64\nimport os\n')
            content = re.sub(r"RUNTIME = Path\([^\n]+\)", "RUNTIME = Path(os.environ['ARTEX_RUNTIME_ROOT'])", content)
            content = re.sub(r"BASE = [^\n]+", "BASE = os.environ.get('ARTEX_API_BASE', 'http://localhost:8787')", content)
            content = re.sub(r"\nif __name__ == '__main__':.*\Z", "\n", content, flags=re.S)
        elif name == 'chromium_privacy_launcher.py':
            content = re.sub(r"CHROMIUM = [^\n]+", "CHROMIUM = os.environ['ARTEX_PRIVACY_CHROMIUM']", content)
            content = re.sub(r'^#![^\n]+', '#!/usr/bin/env python3', content, count=1, flags=re.M)
        if name == 'privacy_active_probe.py':
            content = content.replace("'http://127.0.0.1:18118'", "'http://localhost:18118'")
            content = content.replace("'/usr/bin/curl'", "shutil.which('curl') or 'curl'")
            if 'import shutil' not in content:
                content = content.replace('import subprocess\n', 'import subprocess\nimport shutil\n')
        # The browser probe's loopback listeners and protocol constants are code.
        # Keep them intact; machine-specific launch paths are parameters above.
        if name == 'privacy_task_observer.py':
            content = re.sub(r"listener.get\('_local_ip'\)\s+in\s+\(peer_ip,\s*'[^']+',\s*'::'\)", "(listener.get('_local_ip') == peer_ip or listener.get('_local_ip') == '::' or _is_loopback(listener.get('_local_ip')))", content)
            content = content.replace('import time\n', 'import time\nimport ipaddress\n')
            content = content.replace('PROC = Path(\'/proc\')', "def _is_loopback(value):\n    try:\n        return ipaddress.ip_address(value).is_loopback\n    except ValueError:\n        return False\n\nPROC = Path('/proc')")
        dst = dst_tools / name
        dst.write_text(content, encoding='utf-8')
    collector_text = collector_source.read_text(encoding='utf-8')
    # Registry provider paths and default-route prefixes are program constants.
    # This collector has no machine-specific installation paths or credentials.
    (dst_tools / 'windows_privacy.ps1').write_text(collector_text, encoding='utf-8')
    dst_skills = profile_dir / 'gateway/skills'
    skill_sources = {'artex-windows-privacy-audit': skill_source}
    skill_sources.update({name: skill_root / name for name in {s['name'] for a in agents for s in a.get('skills', [])} if name != 'artex-windows-privacy-audit'})
    for name, src in sorted(skill_sources.items()):
        if not (src / 'SKILL.md').is_file():
            raise ValueError('a referenced skill is absent from --skill-root; export is incomplete')
        copy_skill_tree(src, dst_skills / name)
    # Runtime output directories are intentionally excluded from the profile.
    for p in profile_dir.rglob('__pycache__'):
        shutil.rmtree(p, ignore_errors=True)


def copy_skill_tree(source, destination):
    allowed = {'.md','.py','.js','.cjs','.mjs','.json','.yaml','.yml','.toml','.txt','.sh','.ps1','.sql','.html','.css'}
    for path in source.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(source)
        if any(part.lower() in {'__pycache__','.git','logs','runtime','workspace','evidence','reports'} for part in rel.parts):
            continue
        if path.suffix.lower() not in allowed or path.name.lower().startswith(('.env','secret','token')):
            continue
        out = destination / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_text(encoding='utf-8', errors='replace')
        out.write_text(scrub(raw), encoding='utf-8')


def apply(profile_path, target_db, include_models=False, confirm=False):
    if not target_db or not confirm:
        raise ValueError('specify --database and --confirm-target to import into that database')
    profile = json.loads(Path(profile_path).read_text(encoding='utf-8'))
    if profile.get('schema_version') != 1 or profile.get('profile') != 'local-team':
        raise ValueError('unsupported profile')
    profile = copy.deepcopy(profile)
    if not include_models:
        profile['llm_profiles'] = []
    profile = resolve_env(profile)
    db = load_config(ARGS.config)['database']
    schema = (ROOT / 'db/schema.sql').read_text(encoding='utf-8')
    psql(schema, db, target_db, psql_bin=ARGS.psql, pg_lib=ARGS.pg_lib)
    # Import is idempotent by stable agent/MCP/tool names. All work occurs in one transaction.
    payload = sqlq(json.dumps(profile, ensure_ascii=False))
    sql = f"""
BEGIN;
SET LOCAL standard_conforming_strings=on;
CREATE TEMP TABLE _profile(payload jsonb) ON COMMIT DROP;
INSERT INTO _profile VALUES ({payload}::jsonb);
"""
    # Clear an existing default before inserting the selected replacement.
    if include_models and any(x.get('is_default') for x in profile.get('llm_profiles', [])):
        sql += 'UPDATE llm_profiles SET is_default=false WHERE is_default;\n'
    # Profiles are resolved up front; simple SQL records keep the importer independent of runtime code.
    for m in profile.get('llm_profiles', []) if include_models else []:
        sql += f"""INSERT INTO llm_profiles(name,format,base_url,proxy,model,api_key,rate_per_second,rate_per_minute,context_window_k,reasoning_effort,thinking_type,is_default,priority,pool_exclude,streaming,max_tokens,max_tokens_field,session_header_key)
VALUES ({sqlq(m['name'])},{sqlq(m['format'])},{sqlq(m.get('base_url') or '')},{sqlq(m.get('proxy') or '')},{sqlq(m['model'])},NULLIF({sqlq(m.get('api_key') or '')},''),{float(m.get('rate_per_second') or 0)},{float(m.get('rate_per_minute') or 0)},{int(m.get('context_window_k') or 0)},{sqlq(m.get('reasoning_effort') or '')},{sqlq(m.get('thinking_type') or '')},{str(bool(m.get('is_default'))).lower()},{int(m.get('priority') or 0)},{str(bool(m.get('pool_exclude'))).lower()},{str(bool(m.get('streaming', True))).lower()},{int(m.get('max_tokens') or 0)},{sqlq(m.get('max_tokens_field') or '')},{sqlq(m.get('session_header_key') or '')})
ON CONFLICT(name) DO UPDATE SET format=EXCLUDED.format,base_url=EXCLUDED.base_url,proxy=EXCLUDED.proxy,model=EXCLUDED.model,api_key=COALESCE(EXCLUDED.api_key,llm_profiles.api_key),rate_per_second=EXCLUDED.rate_per_second,rate_per_minute=EXCLUDED.rate_per_minute,context_window_k=EXCLUDED.context_window_k,reasoning_effort=EXCLUDED.reasoning_effort,thinking_type=EXCLUDED.thinking_type,is_default=EXCLUDED.is_default,priority=EXCLUDED.priority,pool_exclude=EXCLUDED.pool_exclude,streaming=EXCLUDED.streaming,max_tokens=EXCLUDED.max_tokens,max_tokens_field=EXCLUDED.max_tokens_field,session_header_key=EXCLUDED.session_header_key;
"""
    for a in profile.get('agents', []):
        llm = 'NULL' if not a.get('llm_profile') else f"(SELECT id FROM llm_profiles WHERE name={sqlq(a['llm_profile'])})"
        cols = ['key','name','description','role','builtin','enabled','llm_profile_id','max_turns','run_seconds','web_search','interactive_shell','wrapup_prompt','wrapup_max_turns','task_timeout_wrapup_prompt','task_timeout_wrapup_max_turns','trigger_run_mode','trigger_merge_mode','trigger_max_parallel']
        vals = [sqlq(a['key']),sqlq(a['name']),sqlq(a.get('description','')),sqlq(a['role']),str(bool(a['builtin'])).lower(),str(bool(a['enabled'])).lower(),llm,str(int(a.get('max_turns') or 0)),str(int(a.get('run_seconds') or 0)),str(bool(a.get('web_search'))).lower(),str(bool(a.get('interactive_shell'))).lower(),sqlq(a.get('wrapup_prompt','')),str(int(a.get('wrapup_max_turns') or 0)),sqlq(a.get('task_timeout_wrapup_prompt','')),str(int(a.get('task_timeout_wrapup_max_turns') or 0)),sqlq(a.get('trigger_run_mode','serial')),sqlq(a.get('trigger_merge_mode','all')),str(int(a.get('trigger_max_parallel') or 5))]
        updates = ','.join((f'{c}=coalesce(EXCLUDED.{c},agents.llm_profile_id)' if c == 'llm_profile_id' and not include_models else f'{c}=EXCLUDED.{c}') for c in cols[1:])
        sql += f"INSERT INTO agents({','.join(cols)}) VALUES ({','.join(vals)}) ON CONFLICT(key) DO UPDATE SET {updates};\n"
        sql += f"DELETE FROM agent_prompt_vars WHERE agent_id=(SELECT id FROM agents WHERE key={sqlq(a['key'])});\n"
        for v in a.get('prompt_vars', []):
            sql += f"INSERT INTO agent_prompt_vars(agent_id,var_name,description,example,source) SELECT id,{sqlq(v['name'])},{sqlq(v.get('description') or '')},{sqlq(v.get('example') or '')},{sqlq(v['source'])} FROM agents WHERE key={sqlq(a['key'])} ON CONFLICT(agent_id,var_name) DO UPDATE SET description=EXCLUDED.description,example=EXCLUDED.example,source=EXCLUDED.source;\n"
        prompt = a.get('prompt','')
        import hashlib
        tag = '$artex_' + hashlib.sha256(prompt.encode()).hexdigest() + '$'
        if tag in prompt:
            raise ValueError('prompt conflicts with import delimiter')
        sql += f"""DO {tag} DECLARE aid bigint; pid bigint; tmpl text; BEGIN SELECT id,current_prompt_id INTO aid,pid FROM agents WHERE key={sqlq(a['key'])}; SELECT template_text INTO tmpl FROM agent_prompts WHERE id=pid; IF tmpl IS DISTINCT FROM {sqlq(prompt)} THEN INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES(aid,COALESCE((SELECT max(version)+1 FROM agent_prompts WHERE agent_id=aid),1),{sqlq(prompt)},'Imported local-team profile','profile-sync') RETURNING id INTO pid; UPDATE agents SET current_prompt_id=pid WHERE id=aid; END IF; END {tag};
DELETE FROM agent_triggers WHERE agent_key={sqlq(a['key'])};
"""
        for t in a.get('triggers', []):
            fields = ['enabled','interval_sec','on_finding','on_goal_met','on_task_timeout','on_tool_call','on_task_create','interval_message','finding_message','goal_message','task_timeout_message','tool_call_message','task_create_message','tool_names']
            vals_t = [str(bool(t.get('enabled'))).lower(),str(int(t.get('interval_sec') or 0)),str(bool(t.get('on_finding'))).lower(),str(bool(t.get('on_goal_met'))).lower(),str(bool(t.get('on_task_timeout'))).lower(),str(bool(t.get('on_tool_call'))).lower(),str(bool(t.get('on_task_create'))).lower(),sqlq(t.get('interval_message','')),sqlq(t.get('finding_message','')),sqlq(t.get('goal_message','')),sqlq(t.get('task_timeout_message','')),sqlq(t.get('tool_call_message','')),sqlq(t.get('task_create_message','')),sqlq(t.get('tool_names',''))]
            sql += f"INSERT INTO agent_triggers(agent_key,{','.join(fields)}) VALUES({sqlq(a['key'])},{','.join(vals_t)});\n"
    for m in profile.get('mcps', []):
        args = json.dumps(m.get('args', []), ensure_ascii=False)
        env = json.dumps(m.get('env', {}), ensure_ascii=False)
        sql += f"""INSERT INTO mcp_servers(name,transport,command,args,env,url,enabled,insecure) VALUES({sqlq(m['name'])},{sqlq(m['transport'])},NULLIF({sqlq(m.get('command') or '')},''),{sqlq(args)}::jsonb,{sqlq(env)}::jsonb,NULLIF({sqlq(m.get('url') or '')},''),{str(bool(m.get('enabled'))).lower()},{str(bool(m.get('insecure'))).lower()})
ON CONFLICT(name) DO UPDATE SET transport=EXCLUDED.transport,command=EXCLUDED.command,args=EXCLUDED.args,env=EXCLUDED.env,url=EXCLUDED.url,enabled=EXCLUDED.enabled,insecure=EXCLUDED.insecure;
DELETE FROM mcp_tools_cache WHERE server_id=(SELECT id FROM mcp_servers WHERE name={sqlq(m['name'])});
"""
        for t in m.get('tools', []):
            sql += f"INSERT INTO mcp_tools_cache(server_id,tool_name,description) SELECT id,{sqlq(t['name'])},{sqlq(t.get('description') or '')} FROM mcp_servers WHERE name={sqlq(m['name'])} ON CONFLICT(server_id,tool_name) DO UPDATE SET description=EXCLUDED.description;\n"
    # Exact agent visibility restoration, including disabled per-tool rows.
    for a in profile.get('agents', []):
        key = sqlq(a['key'])
        sql += f"DELETE FROM agent_visibility WHERE agent_id=(SELECT id FROM agents WHERE key={key}); DELETE FROM agent_skill_visibility WHERE agent_id=(SELECT id FROM agents WHERE key={key});\n"
        for b in a.get('mcp_bindings', []):
            sql += f"INSERT INTO agent_visibility(agent_id,resource_kind,resource_id,mcp_tool_name,enabled) SELECT a.id,'mcp',m.id,{sqlq(b.get('tool') or '')},{str(bool(b.get('enabled'))).lower()} FROM agents a CROSS JOIN mcp_servers m WHERE a.key={key} AND m.name={sqlq(b['server'])} ON CONFLICT(agent_id,resource_kind,resource_id,mcp_tool_name) DO UPDATE SET enabled=EXCLUDED.enabled;\n"
        for s in a.get('skills', []):
            sql += f"INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) SELECT id,{sqlq(s['name'])},{str(bool(s.get('enabled'))).lower()} FROM agents WHERE key={key} ON CONFLICT(agent_id,skill_name) DO UPDATE SET enabled=EXCLUDED.enabled;\n"
    # Restore tool definitions and bindings; sensitive/custom exec values are env placeholders.
    for t in profile.get('tools', []):
        sql += f"""INSERT INTO tools(key,system,description,schema,agents,enabled,kind,exec,deferred) VALUES({sqlq(t['key'])},{str(bool(t.get('system',True))).lower()},{sqlq(t.get('description',''))},{sqlq(json.dumps(t.get('schema',{}),ensure_ascii=False))}::jsonb,{sqlq(json.dumps(t.get('agents',[])))}::jsonb,{str(bool(t['enabled'])).lower()},{sqlq(t.get('kind','builtin'))},{sqlq(json.dumps(t.get('exec',{}),ensure_ascii=False))}::jsonb,{str(bool(t.get('deferred'))).lower()}) ON CONFLICT(key) DO UPDATE SET agents=EXCLUDED.agents,enabled=EXCLUDED.enabled;\n"""
    sql += 'COMMIT;\n'
    psql(sql, db, target_db, psql_bin=ARGS.psql, pg_lib=ARGS.pg_lib)
    print('profile applied to the explicit target database; no tasks started')


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('export'); e.add_argument('--output', default=str(ROOT / 'profiles/local-team/profile.json'))
    a = sub.add_parser('apply'); a.add_argument('--profile', default=str(ROOT / 'profiles/local-team/profile.json')); a.add_argument('--database', required=True); a.add_argument('--confirm-target', action='store_true'); a.add_argument('--include-models', action='store_true')
    for sp in (e, a):
        sp.add_argument('--config', default=os.environ.get('ARTEX_CONFIG'))
        sp.add_argument('--psql', default=os.environ.get('ARTEX_PROFILE_PSQL'))
        sp.add_argument('--pg-lib', default=os.environ.get('ARTEX_PROFILE_PG_LIB'))
    e.add_argument('--integration-root', default=os.environ.get('ARTEX_INTEGRATIONS_SOURCE'))
    e.add_argument('--skill-source', default=os.environ.get('ARTEX_PRIVACY_SKILL_SOURCE'))
    e.add_argument('--skill-root', default=os.environ.get('ARTEX_PROFILE_SKILL_ROOT'))
    e.add_argument('--collector-source', default=os.environ.get('ARTEX_PRIVACY_COLLECTOR_SOURCE'))
    ns = p.parse_args()
    try:
        global ARGS
        ARGS = ns
        if ns.cmd == 'export': export(ns.output)
        else: apply(ns.profile, ns.database, ns.include_models, ns.confirm_target)
    except Exception as exc:
        print(f'profile-sync failed: {exc}', file=sys.stderr); return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
