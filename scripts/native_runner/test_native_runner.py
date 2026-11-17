import hashlib
import io
import json
import os
import queue
import struct
import tempfile
import unittest
from unittest.mock import Mock

from .gdb_mi import command, parse_record
from .protocol import MAX_FRAME, read_frame, write_frame
from .main import classify_exit_code, expectation_matches, profile_settings, validate_session_action, MAX_CACHE_BYTES, MAX_CACHE_ITEMS
from .process import ByteReader
from .main import serve
from .sandbox import DockerSandbox


def elf64():
    b=bytearray(120); b[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI",b,16,2,62,1)
    struct.pack_into("<Q",b,32,64)
    struct.pack_into("<HHH",b,52,64,56,1)
    struct.pack_into("<IIQQQQQQ",b,64,1,5,0,0x400000,0x400000,len(b),len(b),0x1000)
    return bytes(b)


class FakeProc:
    def __init__(self, output=b"", code=0):
        self.stdin=io.BytesIO(); self.stdout=io.BytesIO(output); self.stderr=io.BytesIO(); self.returncode=code
    def poll(self): return self.returncode
    def wait(self,timeout=None): return self.returncode
    def terminate(self): pass
    def kill(self): pass


class AsyncStream:
    def __init__(self):
        self.lines=queue.Queue()
    def feed(self,text):
        self.lines.put(text.encode("utf-8") if isinstance(text,str) else text)
    def read(self,size=-1):
        item=self.lines.get()
        return item if item is not None else b""
    def close(self):
        self.lines.put(None)


class ScriptedDebugProc:
    """Small asynchronous MI fixture that responds to startup/interrupt/registers."""
    def __init__(self):
        self.stdout=AsyncStream(); self.stderr=AsyncStream()
        self.stdin=ScriptedDebugStdin(self); self.returncode=None
    def poll(self): return self.returncode
    def wait(self,timeout=None): return self.returncode
    def terminate(self): self.returncode=-15; self.stdout.close(); self.stderr.close()
    def kill(self): self.terminate()


class ScriptedDebugStdin(io.BytesIO):
    def __init__(self,proc):
        super().__init__(); self.proc=proc; self.commands=[]
    def write(self,data):
        for line in bytes(data).decode("ascii","replace").splitlines():
            self.commands.append(line)
            match=__import__("re").match(r"^([0-9]+)(-.*)$",line)
            token,cmd=(match.group(1),match.group(2)) if match else ("",line)
            if cmd=="-gdb-set mi-async on" or cmd.startswith("-gdb-show disable-randomization"):
                self.proc.stdout.feed(f"{token}^done\n" if cmd.startswith("-gdb-set") else f'{token}^done,value="off"\n')
            elif cmd=="-gdb-show mi-async":
                self.proc.stdout.feed(f'{token}^done,value="on"\n')
            elif cmd=="-exec-interrupt":
                self.proc.stdout.feed(f"{token}^done\n")
                self.proc.stdout.feed('*stopped,reason="signal-received",signal-name="SIGSEGV",'
                                      'frame={addr="0x401234",func="main"}\n')
            elif cmd.startswith("-data-list-register-names"):
                self.proc.stdout.feed(f'{token}^done,register-names=["rip","rsp"]\n')
            elif cmd.startswith("-data-list-register-values"):
                self.proc.stdout.feed(f'{token}^done,register-values=[{{number="0",value="0x401234"}},'
                                      f'{{number="1",value="0x7fff"}}]\n')
            else:
                self.proc.stdout.feed(f"{token}^done\n")
        return len(data)


class FakeSandbox:
    def __init__(self,proc): self.proc=proc
    def inspect_elf(self,path): return "a"*64
    def start(self,*args): return {"name":"fake","process":self.proc,"staging":"unused","deadline":__import__("time").monotonic()+10,"mode":args[3]}
    def cleanup(self,session): return {"owned_process_terminated":True,"container_removed":True,"staging_removed":True}


class RunnerTests(unittest.TestCase):
    def test_elf64_validation_and_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f: f.write(elf64()); path=f.name
        try: self.assertEqual(DockerSandbox().inspect_elf(path),hashlib.sha256(elf64()).hexdigest())
        finally: os.unlink(path)

    def test_rejects_non_x86_64(self):
        with tempfile.NamedTemporaryFile(delete=False) as f: f.write(b"\x7fELF"+bytes(60)); path=f.name
        try: self.assertRaises(ValueError,DockerSandbox().inspect_elf,path)
        finally: os.unlink(path)

    def test_gdb_commands_typed_and_bounded(self):
        self.assertEqual(command("continue",{}),"-exec-continue")
        self.assertEqual(command("memory",{"address":4096,"length":32}),"-data-read-memory-bytes 0x1000 32")
        for action,args in (("eval",{"expression":"system(1)"}),("memory",{"address":0,"length":100000})):
            with self.assertRaises(ValueError): command(action,args)

    def test_parse_mi(self):
        self.assertEqual(parse_record("7^done,value=3")["token"],"7")

    def test_protocol_round_trip(self):
        stream=io.StringIO(); write_frame(stream,{"action":"status"}); stream.seek(0)
        self.assertEqual(read_frame(stream),{"action":"status"})

    def test_protocol_frame_size_is_bounded(self):
        with self.assertRaises(ValueError): read_frame(io.StringIO("{"+" "*(MAX_FRAME+1)+"}\n"))

    def test_exit_codes_and_expected_nonzero_exit(self):
        self.assertEqual(classify_exit_code(23),("exit",None))
        self.assertEqual(classify_exit_code(139),("crashed",11))
        self.assertEqual(classify_exit_code(-11),("crashed",11))
        self.assertTrue(expectation_matches("exit",23,23,None))
        self.assertTrue(expectation_matches("crashed",139,None,11))

    def test_debug_cannot_write_gdb_control_pipe(self):
        for action in ("send","close_stdin"):
            with self.assertRaises(ValueError): validate_session_action(action,"debug")
        validate_session_action("recv","debug")

    def test_profile_uses_system_settings_array_shape(self):
        p={"engine":"docker-native","settings":{"image":"lab@sha256:"+"a"*64,"enabled":False}}
        self.assertEqual(profile_settings(p)["image"],p["settings"]["image"])

    def test_output_reader_is_bounded(self):
        import time
        r=ByteReader(io.BytesIO(b"x"*20),max_bytes=10)
        for _ in range(50):
            if r.eof: break
            time.sleep(.005)
        data,eof=r.recv(10,.01)
        self.assertEqual(len(data),10); self.assertTrue(r.truncated)
        self.assertEqual(MAX_CACHE_ITEMS,128); self.assertEqual(MAX_CACHE_BYTES,8*1024*1024)

    def test_session_final_contains_unread_natural_exit_tail(self):
        first={"operation":"session","request_id":"start","artifact_path":"fixture","sha256":"a"*64,"argv":[],"mode":"exec","duration_ms":1000,"profile":{"image":"x"}}
        control={"request_id":"s1","action":"status"}
        inp=io.StringIO(json.dumps(first)+"\n"+json.dumps(control)+"\n")
        out=io.StringIO()
        self.assertEqual(serve(inp,out,FakeSandbox(FakeProc(b"tail-bytes",0))),0)
        frames=[json.loads(x) for x in out.getvalue().splitlines()]
        final=frames[-1]["observation"]
        import base64
        self.assertEqual(base64.b64decode(final["output"]["tail_base64"]),b"tail-bytes")

    def test_session_initialization_error_still_reports_cleanup(self):
        first={"operation":"session","request_id":"start","artifact_path":"fixture","sha256":"a"*64,"mode":"exec","duration_ms":1000,"profile":{"image":"x"}}
        proc=FakeProc()
        del proc.stderr  # Fail after sandbox.start but before the ready frame.
        sandbox=FakeSandbox(proc); sandbox.cleanup=Mock(wraps=sandbox.cleanup)
        out=io.StringIO()
        self.assertEqual(serve(io.StringIO(json.dumps(first)+"\n"),out,sandbox),1)
        final=json.loads(out.getvalue())["observation"]
        self.assertEqual(final["target_state"],"failed")
        self.assertIsNone(final["session_id"])
        self.assertTrue(final["errors"])
        self.assertTrue(final["cleanup"]["container_removed"])
        sandbox.cleanup.assert_called_once()

    def test_debug_signal_stop_keeps_session_open_for_inspection(self):
        first={"operation":"session","request_id":"start","artifact_path":"fixture","sha256":"a"*64,"argv":[],"mode":"debug","duration_ms":1000,"profile":{"image":"x"}}
        actions=[{"request_id":"d1","action":"debug","command":{"action":"interrupt"}},
                 {"request_id":"d2","action":"debug","command":{"action":"registers"}},
                 {"request_id":"stop","action":"stop"}]
        inp=io.StringIO("\n".join(json.dumps(x) for x in [first,*actions])+"\n")
        out=io.StringIO(); self.assertEqual(serve(inp,out,FakeSandbox(ScriptedDebugProc())),0)
        frames=[json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([f["request_id"] for f in frames if f.get("kind")=="result"], ["d1","d2","stop"])
        self.assertEqual(frames[-1]["observation"]["target_state"],"crashed")

    def test_replay_matches_expected_nonzero_exit(self):
        req={"operation":"replay","request_id":"r1","artifact_path":"fixture","sha256":"a"*64,"argv":[],"input_base64":"","expected_exit":23,"duration_ms":1000,"profile":{"image":"x"}}
        out=io.StringIO()
        self.assertEqual(serve(io.StringIO(json.dumps(req)+"\n"),out,FakeSandbox(FakeProc(b"ok",23))),0)
        self.assertTrue(json.loads(out.getvalue())["observation"]["matches_expectation"])

    def test_docker_command_contains_isolation(self):
        with tempfile.NamedTemporaryFile(delete=False) as f: f.write(elf64()); path=f.name
        try:
            p=Mock(); p.poll.return_value=None
            box=DockerSandbox(popen=Mock(return_value=p)); session=box.start(path,hashlib.sha256(elf64()).hexdigest(),[],"exec",{"image":"lab@sha256:"+"a"*64},1000)
            args=box._popen.call_args.args[0]
            for item in ("--pull=never","--network=none","--read-only","--cap-drop=ALL","--pids-limit=64","--memory=512m","--cpus=1"):
                self.assertIn(item,args)
            self.assertIn("readonly",args[args.index("--mount")+1])
            self.assertNotIn("/var/run/docker.sock",args)
            box._run=Mock(); p.poll.return_value=0; p.wait.return_value=0
            box.cleanup(session)
            box._run.return_value.returncode=1
            session["process"]=p
            self.assertFalse(box.cleanup(session)["container_removed"])
            with self.assertRaises(ValueError): box.start(path,hashlib.sha256(elf64()).hexdigest(),[],"exec",{"image":"mutable:latest"},1000)
        finally: os.unlink(path)




class CoreExportTests(unittest.TestCase):
    def test_fixed_path_bounded_exec_export_and_read(self):
        payload=b"\x7fELF"+bytes(range(64))
        def run(args,**kwargs):
            self.assertEqual(args[:3],["docker","exec","--user=65534:65534"])
            self.assertEqual(args[4:6],["/usr/bin/python3","-c"])
            self.assertIn("O_NOFOLLOW",args[6])
            self.assertIn("S_ISREG",args[6])
            self.assertIn("limit=128*1024*1024",args[6])
            self.assertIn("source.read(min(65536,limit-total+1))",args[6])
            self.assertNotIn("shell",kwargs)
            kwargs["stdout"].write(payload)
            return Mock(returncode=0,stderr=b"")
        with tempfile.TemporaryDirectory() as directory:
            session={"name":"owned-core-test","staging":directory}
            box=DockerSandbox(run=run)
            meta=box.capture_core(session)
            self.assertEqual(meta["size"],len(payload))
            self.assertEqual(meta["sha256"],hashlib.sha256(payload).hexdigest())
            self.assertEqual(box.read_core(session,0,4),b"\x7fELF")

    def test_export_failure_keeps_bounded_error_and_cleans_partial(self):
        def run(args,**kwargs):
            kwargs["stdout"].write(b"partial")
            return Mock(returncode=1,stderr=b"x"*4096+b"diagnostic-tail")
        with tempfile.TemporaryDirectory() as directory:
            session={"name":"owned-core-test","staging":directory}
            with self.assertRaisesRegex(ValueError,"diagnostic-tail") as caught:
                DockerSandbox(run=run).capture_core(session)
            self.assertLessEqual(len(str(caught.exception)),2070)
            self.assertFalse(os.path.exists(os.path.join(directory,"core.bin")))
            self.assertIsNone(session["core_path"])
            self.assertIsNone(session["core_meta"])

    def test_export_timeout_cleans_partial(self):
        import subprocess
        def run(args,**kwargs):
            kwargs["stdout"].write(b"partial")
            raise subprocess.TimeoutExpired(args,30)
        with tempfile.TemporaryDirectory() as directory:
            session={"name":"owned-core-test","staging":directory}
            with self.assertRaises(subprocess.TimeoutExpired):
                DockerSandbox(run=run).capture_core(session)
            self.assertFalse(os.path.exists(os.path.join(directory,"core.bin")))
            self.assertIsNone(session["core_path"])

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.name == "posix",
                         "executes the Linux container reader; covered on Debian")
    def test_exec_reader_rejects_symlink_and_oversized_file(self):
        from unittest.mock import patch
        from pathlib import Path
        import sys
        scripts=[]
        def capture(args,**kwargs):
            scripts.append(args[-1])
            kwargs["stdout"].write(b"test")
            return Mock(returncode=0,stderr=b"")
        with tempfile.TemporaryDirectory() as directory:
            DockerSandbox(run=capture).capture_core({"name":"owned-core-test","staging":directory})
            source=Path(directory)/"source"
            with source.open("wb") as stream: stream.truncate(128*1024*1024+1)
            real_open=os.open
            with patch("os.open",side_effect=lambda path,flags: real_open(str(source),flags)):
                with self.assertRaisesRegex(ValueError,"128 MiB"):
                    exec(scripts[0],{})
            source.unlink()
            source.symlink_to(Path(directory)/"core.bin")
            with patch("os.open",side_effect=lambda path,flags: real_open(str(source),flags)):
                with self.assertRaises(OSError):
                    exec(scripts[0],{})


if __name__=="__main__": unittest.main()
