"""Bounded static Hermes queries. The input bytecode is parsed, never executed."""
import contextlib
import io
import json
import os
import struct
import sys

def inspect(request):
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    except (ImportError, ValueError, OSError) as error:
        raise ValueError('Hermes requires a runner with memory/CPU limits; use the Linux/WSL engine') from error
    from importlib.metadata import version
    if version('hermes-dec') != '0.1.8':
        raise ValueError('Hermes adapter requires hermes-dec==0.1.8')
    from hermes_dec.parsers.hbc_file_parser import HBCReader
    from hermes_dec.parsers.hbc_bytecode_parser import parse_hbc_bytecode
    path = request['path']
    if os.path.getsize(path) > 64*1024*1024:
        raise ValueError('Hermes input exceeds 64 MiB')
    with open(path, 'rb') as f:
        head = f.read(12)
        if len(head) != 12 or struct.unpack('<Q',head[:8])[0] != 0x1F1903C103BC1FC6:
            raise ValueError('Not Hermes bytecode')
        v = struct.unpack('<I',head[8:])[0]
        if v not in (72,73,76,80,81,82,83,84,85,86,87,89,90,92,93,94,95,96,97,98,99):
            raise ValueError('Unsupported Hermes version: '+str(v))
        f.seek(0)
        reader = HBCReader()
        reader.read_whole_file(f)
        offset=max(0,int(request.get('offset',0)))
        limit=min(100,max(1,int(request.get('limit',30))))
        query=request.get('query','').casefold()
        facet=request.get('facet','summary')
        result={'format':'hermes','bytecode_version':v,'function_count':len(reader.function_headers),'string_count':len(reader.strings),'engine':'hermes-dec','engine_version':'0.1.8','limitations':['Static bytecode observations do not prove runtime or server behavior. Disassembly is not recovered original JavaScript.']}
        if facet=='summary': return result
        if facet=='strings':
            matches=[(i,s) for i,s in enumerate(reader.strings) if query in s.casefold()]
            result.update(total=len(matches),offset=offset,next_offset=min(len(matches),offset+limit),items=[{'string_id':i,'value':s[:4000],'truncated':len(s)>4000} for i,s in matches[offset:offset+limit]])
        elif facet=='functions':
            matches=[(i,h) for i,h in enumerate(reader.function_headers) if query in reader.strings[h.functionName].casefold()]
            result.update(total=len(matches),offset=offset,next_offset=min(len(matches),offset+limit),items=[{'function_id':i,'name':reader.strings[h.functionName][:1000],'bytecode_offset':h.offset,'bytecode_size':h.bytecodeSizeInBytes,'param_count':h.paramCount} for i,h in matches[offset:offset+limit]])
        elif facet=='instructions':
            fid=int(request.get('function_id',-1))
            if fid<0 or fid>=len(reader.function_headers): raise ValueError('function_id out of range')
            h=reader.function_headers[fid]
            items=[];count=0
            for i,instruction in enumerate(parse_hbc_bytecode(h,reader)):
                count=i+1
                if i>=offset and i<offset+limit: items.append({'instruction_index':i,'text':repr(instruction)[:4000]})
                if i>=offset+limit: break
            result.update(function_id=fid,name=reader.strings[h.functionName],bytecode_offset=h.offset,bytecode_size=h.bytecodeSizeInBytes,items=items,next_offset=offset+len(items),has_more=count>offset+len(items))
        else: raise ValueError('Unknown facet')
        return result

try:
    request=json.loads(sys.stdin.buffer.read(65536))
    # Providers occasionally print diagnostics; keep the JSON protocol intact.
    with contextlib.redirect_stdout(io.StringIO()):
        result=inspect(request)
    print(json.dumps({'ok':True,'result':result},ensure_ascii=True))
except Exception as error:
    print(json.dumps({'ok':False,'error':str(error)[:1000]}))
