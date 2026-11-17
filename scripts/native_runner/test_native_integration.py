"""Opt-in real Docker acceptance for synthetic local C fixtures only.

Run from the ARTEX checkout inside the prepared Linux lab:
  NATIVE_IMAGE_TAG=artex-native-local:acceptance python3 -m unittest scripts.native_runner.test_native_integration -v
The image tag is used only to inspect its immutable image ID; target containers
are always run by that sha256 image ID with --pull=never.
"""
import base64
import hashlib
import io
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from .main import serve
from .sandbox import DockerSandbox


REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "testdata" / "reverse" / "native" / "integration_fixture.c"
STACK_FIXTURE = REPO / "testdata" / "reverse" / "native" / "case_stack_overflow.c"
UAF_FIXTURE = REPO / "testdata" / "reverse" / "native" / "case_heap_uaf.c"
IMPACT_FIXTURE = REPO / "testdata" / "reverse" / "native" / "case_local_impact.c"
MEMORY_FIXTURE = REPO / "testdata" / "reverse" / "native" / "case_memory_pressure.c"


class LiveFrames:
    """Readable JSONL input that remains open like the real parent manager."""
    def __init__(self, frames):
        self.lines=queue.Queue()
        for frame in frames: self.put(frame)

    def put(self, frame): self.lines.put((json.dumps(frame,separators=(",",":"))+"\n").encode())

    def readline(self, size=-1):
        line=self.lines.get()
        return line[:size] if size>=0 else line


class DiagnosticSandbox(DockerSandbox):
    """Capture only runner stderr for a failing synthetic debug smoke."""
    def __init__(self): super().__init__(); self.last_process=None
    def start(self,*args):
        original=self._popen
        def capture(*popen_args,**kwargs):
            kwargs["stderr"]=subprocess.PIPE
            self.last_process=original(*popen_args,**kwargs)
            return self.last_process
        self._popen=capture
        try: return super().start(*args)
        finally: self._popen=original


def unpack(text): return [json.loads(line) for line in text.getvalue().splitlines()]


class NativeDockerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tag=os.environ.get("NATIVE_IMAGE_TAG","artex-native-local:acceptance")
        result=subprocess.run(["docker","image","inspect",tag,"--format","{{.Id}}"],capture_output=True,text=True,check=True)
        cls.image=result.stdout.strip()
        if not cls.image.startswith("sha256:") or len(cls.image)!=71: raise RuntimeError("lab image inspect did not return an immutable image ID")
        probe=subprocess.run(["docker","run","--rm","--pull=never","--network=none",
            "--read-only","--cap-drop=ALL","--security-opt=no-new-privileges",
            "--user=65534:65534","--entrypoint","/usr/bin/test",cls.image,"-x","/usr/bin/gcc"],
            capture_output=True,timeout=15)
        cls.compile_in_image=probe.returncode==0
        if not cls.compile_in_image:
            if probe.returncode != 1:
                raise RuntimeError("image compiler probe failed: " + probe.stderr.decode("utf-8","replace"))
            if os.environ.get("NATIVE_ALLOW_HOST_COMPILER") != "1":
                raise RuntimeError("image GCC is required; explicitly set NATIVE_ALLOW_HOST_COMPILER=1 only for host-compatible fixtures")
        cls.tmp=tempfile.TemporaryDirectory(prefix="artex-native-accept-")
        cls.binary=str(Path(cls.tmp.name)/"fixture")
        cls.compile_fixture(FIXTURE,cls.binary,[])
        cls.sha=hashlib.sha256(Path(cls.binary).read_bytes()).hexdigest()
        cls.profile={"image":cls.image,"seccomp_profile":"deploy/native-lab/seccomp-debug.json"}
        cls.sandbox=DockerSandbox()
        cls.binaries={"base":(cls.binary,cls.sha)}
        for key,source,flags in (
            ("stack",STACK_FIXTURE,["-fsanitize=address","-static-libasan","-fno-omit-frame-pointer"]),
            ("uaf",UAF_FIXTURE,["-fsanitize=address","-static-libasan","-fno-omit-frame-pointer"]),
            ("impact",IMPACT_FIXTURE,[]),
            ("memory",MEMORY_FIXTURE,[]),
        ):
            path=str(Path(cls.tmp.name)/key)
            cls.compile_fixture(source,path,flags)
            cls.binaries[key]=(path,hashlib.sha256(Path(path).read_bytes()).hexdigest())

    @classmethod
    def compile_fixture(cls,source,destination,flags):
        options=["-O0","-g","-fno-pie","-no-pie",*flags]
        if cls.compile_in_image:
            # Compile against the selected image libc/toolchain when available;
            # host-built glibc binaries must not masquerade as Debian validation.
            subprocess.run(["docker","run","--rm","--pull=never","--network=none",
                "--read-only","--cap-drop=ALL","--security-opt=no-new-privileges",
                "--user=0:0","--memory=512m","--pids-limit=64","--tmpfs","/tmp:rw,nosuid,size=128m",
                "--mount",f"type=bind,src={source},dst=/src.c,readonly",
                "--mount",f"type=bind,src={cls.tmp.name},dst=/out",
                "--entrypoint","/usr/bin/gcc",cls.image,*options,"/src.c",
                "-o","/out/"+Path(destination).name],check=True,timeout=60)
        else:
            subprocess.run(["gcc",*options,str(source),"-o",destination],check=True,timeout=60)

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def start_frame(self, argv=(), duration=5000, mode="exec"):
        return {"operation":"session","request_id":"start","artifact_path":self.binary,"sha256":self.sha,"argv":list(argv),"mode":mode,"duration_ms":duration,"profile":self.profile}

    def replay(self, argv=(), data=b"", artifact=None, sha=None, profile=None, **extra):
        frame={"operation":"replay","request_id":"replay","artifact_path":artifact or self.binary,"sha256":sha or self.sha,"argv":list(argv),"mode":"exec","duration_ms":5000,"profile":profile or self.profile,"input_base64":base64.b64encode(data).decode()}
        frame.update(extra)
        out=io.StringIO(); rc=serve(io.StringIO(json.dumps(frame)+"\n"),out,self.sandbox)
        return rc,unpack(out)[0]

    def test_binary_multistep_echo_and_cleanup(self):
        payload_a=b"\x00\xffA"; payload_b=b"B\x00\x80"
        frames=[self.start_frame(duration=12000)]
        for i,payload in enumerate((payload_a,payload_b),1):
            frames += [{"request_id":f"send{i}","action":"send","data_base64":base64.b64encode(payload).decode()},
                       {"request_id":f"recv{i}","action":"recv","max_bytes":64,"timeout_ms":3000}]
        frames.append({"request_id":"close","action":"close_stdin"})
        inp=LiveFrames(frames); out=io.StringIO()
        rc=serve(inp,out,self.sandbox); result=unpack(out)
        replies={f.get("request_id"):f for f in result}
        self.assertEqual(base64.b64decode(replies["recv1"]["observation"]["data_base64"]),payload_a)
        self.assertEqual(base64.b64decode(replies["recv2"]["observation"]["data_base64"]),payload_b)
        final=result[-1]["observation"]
        self.assertEqual(final["target_state"],"exit",json.dumps(result)); self.assertEqual(final["exit_code"],0)
        self.assertTrue(all(final["cleanup"].values())); self.assertEqual(rc,0)

    def test_replay_expected_nonzero_exit(self):
        rc,frame=self.replay(["nonzero"],expected_exit=23)
        self.assertEqual(rc,0); self.assertEqual(frame["observation"]["target_state"],"exit")
        self.assertEqual(frame["observation"]["exit_code"],23); self.assertTrue(frame["observation"]["matches_expectation"])
        self.assertTrue(all(frame["observation"]["cleanup"].values()))

    def test_replay_sigsegv(self):
        rc,frame=self.replay(["segv"],expected_signal=11)
        obs=frame["observation"]
        self.assertEqual(obs["target_state"],"crashed",json.dumps(frame)); self.assertEqual(obs["signal"],11)
        self.assertTrue(obs["matches_expectation"]); self.assertTrue(all(obs["cleanup"].values())); self.assertEqual(rc,0)

    def test_timeout_removes_container(self):
        frame=self.start_frame(["sleep"],duration=400)
        out=io.StringIO(); rc=serve(LiveFrames([frame]),out,self.sandbox)
        final=unpack(out)[-1]["observation"]
        self.assertEqual(final["target_state"],"timeout"); self.assertTrue(all(final["cleanup"].values())); self.assertEqual(rc,1)

    def assert_debug_register_stack_evidence(self,by_id,result):
        evidence={}
        for request_id,key in (("registers","register-values"),("stack","stack")):
            records=by_id[request_id]["observation"].get("records",[])
            self.assertFalse(any(r.get("record")=="^" and r.get("class")=="error" for r in records),json.dumps(result))
            done=[r.get("values",{}) for r in records if r.get("record")=="^" and r.get("class")=="done"]
            rows=[row for values in done for row in values.get(key,[])]
            self.assertTrue(rows,json.dumps(result))
            evidence[key]=rows
        self.assertTrue(any(isinstance(r,dict) and str(r.get("number","")).isdigit() and r.get("value") not in (None,"","<unavailable>") for r in evidence["register-values"]),json.dumps(result))
        frames=[r.get("frame",r) for r in evidence["stack"] if isinstance(r,dict)]
        self.assertTrue(any(f.get("func")=="main" and str(f.get("addr","")).startswith("0x") for f in frames),json.dumps(result))

    def test_debug_sigsegv_registers_stack_and_cleanup(self):
        frames=[self.start_frame(["segv"],duration=12000,mode="debug"),
                {"request_id":"run","action":"debug","timeout_ms":4000,"command":{"action":"run"}},
                {"request_id":"registers","action":"debug","timeout_ms":3000,"command":{"action":"registers"}},
                {"request_id":"stack","action":"debug","timeout_ms":3000,"command":{"action":"stack","count":8}},
                {"request_id":"stop","action":"stop"}]
        diagnostic=DiagnosticSandbox()
        out=io.StringIO(); rc=serve(LiveFrames(frames),out,diagnostic); result=unpack(out)
        stderr=base64.b64decode(result[-1]["observation"].get("stderr",{}).get("tail_base64","")).decode("utf-8","replace")
        by_id={frame.get("request_id"):frame for frame in result}
        self.assert_debug_register_stack_evidence(by_id,result)
        final=result[-1]["observation"]
        self.assertEqual(final["target_state"],"crashed",json.dumps(result))
        self.assertEqual(final["signal"],"SIGSEGV"); self.assertTrue(all(final["cleanup"].values())); self.assertEqual(rc,0)

    def test_replay_owner_cancellation_cleans_container(self):
        request=self.start_frame(["sleep"],duration=10000)
        request.update(operation="replay",request_id="replay",input_base64="",expected_exit=0)
        child=subprocess.Popen([sys.executable,"-m","scripts.native_runner.main"],cwd=REPO,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            child.stdin.write(json.dumps(request)+"\n");child.stdin.flush()
            time.sleep(.5)
            child.stdin.write('{"cancel":true}\n');child.stdin.flush()
            line=child.stdout.readline();child.wait(timeout=8)
            frame=json.loads(line);obs=frame["observation"]
            self.assertEqual(obs["target_state"],"cancelled",line)
            self.assertTrue(all(obs["cleanup"].values()))
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream: stream.close()


    def test_mutable_image_tag_is_rejected_before_docker_run(self):
        with self.assertRaisesRegex(ValueError,"sha256"):
            self.sandbox.start(self.binary,self.sha,[],"exec",{"image":"artex-native-local:acceptance"},1000)

    # N01-N15: one named assertion per acceptance item. Existing legacy tests
    # remain as compatibility coverage; these are the itemized evidence cases.
    def test_N01_static_elf_and_dynamic_replay(self):
        path,sha=self.binaries["base"]
        self.assertEqual(self.sandbox.inspect_elf(path),sha)
        rc,frame=self.replay(data=b"N01",artifact=path,sha=sha)
        obs=frame["observation"]
        self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"exit")
        self.assertEqual(base64.b64decode(obs["output_base64"]),b"N01")
        self.assertTrue(all(obs["cleanup"].values()))

    def test_N02_nonzero_exit_is_not_crash(self):
        rc,frame=self.replay(["nonzero"],expected_exit=23)
        obs=frame["observation"]
        self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"exit")
        self.assertEqual(obs["exit_code"],23); self.assertTrue(obs["matches_expectation"])

    def test_N03_all_bytes_and_request_idempotency(self):
        payload=bytes(range(256))
        frames=[self.start_frame(duration=12000)]
        send={"request_id":"send-all","action":"send","data_base64":base64.b64encode(payload).decode()}
        receive={"request_id":"recv-all","action":"recv","max_bytes":512,"timeout_ms":3000}
        frames += [send,send,receive,receive,{"request_id":"close-all","action":"close_stdin"}]
        out=io.StringIO(); rc=serve(LiveFrames(frames),out,self.sandbox); result=unpack(out)
        by_id={f.get("request_id"):f for f in result}
        self.assertEqual(base64.b64decode(by_id["recv-all"]["observation"]["data_base64"]),payload)
        for request_id in ("send-all","recv-all"):
            duplicates=[f for f in result if f.get("request_id")==request_id]
            self.assertEqual(len(duplicates),2,json.dumps(result))
            for field in ("request_id","kind","observation"):
                self.assertEqual(duplicates[0][field],duplicates[1][field],json.dumps(result))
            for response in duplicates:
                self.assertIsInstance(response["event_seq"],int,json.dumps(result))
                self.assertNotIsInstance(response["event_seq"],bool,json.dumps(result))
            self.assertLess(duplicates[0]["event_seq"],duplicates[1]["event_seq"],json.dumps(result))
        # Whole-session target output must contain exactly one payload, not two
        # writes hidden behind a cached receive response.
        self.assertEqual(base64.b64decode(result[-1]["observation"]["output"]["tail_base64"]),payload,json.dumps(result))
        self.assertEqual(result[-1]["observation"]["output"]["bytes_seen"],len(payload),json.dumps(result))
        self.assertEqual(result[-1]["observation"]["target_state"],"exit")
        self.assertTrue(all(result[-1]["observation"]["cleanup"].values())); self.assertEqual(rc,0)

    def test_N04_signal_status_has_source(self):
        rc,frame=self.replay(["segv"],expected_signal=11)
        obs=frame["observation"]
        self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"crashed")
        self.assertEqual(obs["signal"],11); self.assertEqual(obs.get("signal_source"),"docker_exit_status_convention")
        self.assertTrue(obs["matches_expectation"])

    def _asan_crash(self,key,trigger):
        path,sha=self.binaries[key]
        # Static ASan uses the selected image without an untracked derived image.
        # Sanitizers normally exit 1, not a signal: require actual diagnostic
        # evidence rather than treating any crash as proof of the named defect.
        rc,frame=self.replay(data=trigger,artifact=path,sha=sha,expected_exit=1)
        obs=frame["observation"]
        expected="stack-buffer-overflow" if key=="stack" else "heap-use-after-free"
        sanitizer=obs.get("stderr",{}).get("sanitizer",{})
        self.assertTrue(sanitizer.get("detected"),json.dumps(frame))
        self.assertTrue(any(expected in line for line in sanitizer.get("summaries",[])),json.dumps(frame))
        self.assertEqual(obs["exit_code"],1,json.dumps(frame))
        self.assertTrue(all(obs["cleanup"].values()),json.dumps(frame))
        self.assertEqual(rc,0,json.dumps(frame))
        # Negative control must not produce the named sanitizer finding.
        rc,normal=self.replay(data=b"NORMAL",artifact=path,sha=sha,expected_exit=0)
        self.assertEqual(rc,0,json.dumps(normal))
        self.assertFalse(normal["observation"].get("stderr",{}).get("sanitizer",{}).get("detected"))

    def test_N05_stack_buffer_overflow_asan(self):
        self._asan_crash("stack",b"!"+b"A"*23)

    def test_N06_heap_use_after_free_asan(self):
        self._asan_crash("uaf",b"!")

    def test_N07_impact_marker_reproduces_three_of_three(self):
        path,sha=self.binaries["impact"]
        outputs=[]
        for _ in range(3):
            rc,frame=self.replay(data=b"IMPACT",artifact=path,sha=sha)
            obs=frame["observation"]
            self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"exit")
            outputs.append(base64.b64decode(obs["output_base64"]))
            self.assertTrue(all(obs["cleanup"].values()))
        self.assertTrue(all(b"LOCAL_IMPACT_MARKER" in output for output in outputs))

    def test_N08_normal_input_has_no_marker_three_of_three(self):
        path,sha=self.binaries["impact"]
        outputs=[]
        for _ in range(3):
            rc,frame=self.replay(data=b"NORMAL",artifact=path,sha=sha)
            obs=frame["observation"]
            self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"exit")
            outputs.append(base64.b64decode(obs["output_base64"]))
        self.assertTrue(all(b"LOCAL_IMPACT_MARKER" not in output for output in outputs))
        self.assertTrue(all(b"NORMAL_INPUT" in output for output in outputs))

    def test_N09_near_miss_does_not_trigger_marker(self):
        path,sha=self.binaries["impact"]
        rc,frame=self.replay(data=b"IMPACT!",artifact=path,sha=sha)
        obs=frame["observation"]
        output=base64.b64decode(obs["output_base64"])
        self.assertEqual(rc,0); self.assertEqual(obs["target_state"],"exit")
        self.assertNotIn(b"LOCAL_IMPACT_MARKER",output); self.assertIn(b"NORMAL_INPUT",output)

    def test_N10_memory_pressure_is_contained_and_cleaned(self):
        class OOMEvidenceSandbox(DockerSandbox):
            state = None
            def cleanup(self,session):
                try:
                    if session:
                        result=subprocess.run(["docker","inspect","--format","{{json .State}}",session["name"]],
                            capture_output=True,text=True,timeout=5,check=True)
                        self.state=json.loads(result.stdout)
                finally:
                    cleaned=super().cleanup(session)
                return cleaned
        box=OOMEvidenceSandbox(); prior=self.sandbox
        try:
            self.sandbox=box
            path,sha=self.binaries["memory"]
            rc,frame=self.replay(artifact=path,sha=sha,duration_ms=15000)
        finally:
            self.sandbox=prior
        obs=frame["observation"]
        self.assertEqual(obs["target_state"],"crashed",json.dumps(frame))
        self.assertEqual(obs["exit_code"],137,json.dumps(frame))
        self.assertTrue(box.state and box.state.get("OOMKilled"),box.state)
        self.assertTrue(all(obs["cleanup"].values()),json.dumps(frame))
        self.assertNotEqual(rc,0)

    def test_N11_control_stream_eof_cleans_session(self):
        class EOFInput:
            def __init__(self,frame): self.lines=[(json.dumps(frame)+"\n").encode(),b""]
            def readline(self,size=-1): return self.lines.pop(0) if self.lines else b""
        request=self.start_frame(["sleep"],duration=12000)
        out=io.StringIO(); rc=serve(EOFInput(request),out,self.sandbox)
        result=unpack(out); final=result[-1]["observation"]
        self.assertEqual(final["target_state"],"cancelled",json.dumps(result))
        self.assertTrue(all(final["cleanup"].values()),json.dumps(result)); self.assertEqual(rc,0)

    def test_N12_timeout_cleanup(self):
        frame=self.start_frame(["sleep"],duration=400)
        out=io.StringIO(); rc=serve(LiveFrames([frame]),out,self.sandbox)
        final=unpack(out)[-1]["observation"]
        self.assertEqual(final["target_state"],"timeout")
        self.assertTrue(all(final["cleanup"].values())); self.assertEqual(rc,1)

    def test_N13_owner_cancellation_cleanup(self):
        request=self.start_frame(["sleep"],duration=10000)
        request.update(operation="replay",request_id="replay",input_base64="",expected_exit=0)
        child=subprocess.Popen([sys.executable,"-m","scripts.native_runner.main"],cwd=REPO,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            child.stdin.write(json.dumps(request)+"\n"); child.stdin.flush(); time.sleep(.5)
            child.stdin.write('{"cancel":true}\n'); child.stdin.flush()
            line=child.stdout.readline(); child.wait(timeout=8)
            obs=json.loads(line)["observation"]
            self.assertEqual(obs["target_state"],"cancelled",line)
            self.assertTrue(all(obs["cleanup"].values()))
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream: stream.close()

    def test_N14_mutable_image_tag_rejected(self):
        with self.assertRaisesRegex(ValueError,"sha256"):
            self.sandbox.start(self.binary,self.sha,[],"exec",{"image":"artex-native-local:acceptance"},1000)

    def test_start_stops_at_main_before_segv_then_continue_crashes(self):
        frames=[self.start_frame(["segv"],duration=12000,mode="debug"),
                {"request_id":"debug-start","action":"debug","timeout_ms":4000,"command":{"action":"start"}},
                {"request_id":"snapshot","action":"debug","timeout_ms":5000,"command":{"action":"core_snapshot"}},
                {"request_id":"core-bytes","action":"core_read","offset":0,"length":64},
                {"request_id":"continue","action":"debug","timeout_ms":4000,"command":{"action":"continue"}},
                {"request_id":"stop","action":"stop"}]
        out=io.StringIO(); rc=serve(LiveFrames(frames),out,self.sandbox); result=unpack(out)
        by_id={frame.get("request_id"):frame for frame in result}
        obs=by_id["debug-start"]["observation"]
        self.assertEqual(obs["target_state"],"stopped",json.dumps(result))
        stops=[record for record in obs["records"] if record.get("record")=="*" and record.get("class")=="stopped"]
        self.assertTrue(stops,json.dumps(result))
        self.assertEqual(stops[-1]["values"]["reason"],"breakpoint-hit",json.dumps(result))
        self.assertEqual(stops[-1]["values"]["frame"]["func"],"main",json.dumps(result))
        self.assertIn("core",by_id["snapshot"]["observation"],json.dumps(result))
        core=by_id["snapshot"]["observation"]["core"]
        self.assertGreaterEqual(core["size"],64,json.dumps(result))
        self.assertRegex(core["sha256"],r"^[0-9a-f]{64}$")
        read=by_id["core-bytes"]["observation"]
        self.assertEqual(read["core"],core,json.dumps(result))
        header=base64.b64decode(read["data_base64"],validate=True)
        self.assertEqual(read["bytes"],64,json.dumps(result))
        self.assertEqual(len(header),64,json.dumps(result))
        self.assertEqual(header[:4],b"\x7fELF",json.dumps(result))
        self.assertEqual(int.from_bytes(header[16:18],"little"),4,json.dumps(result))
        final=result[-1]["observation"]
        self.assertEqual(final["target_state"],"crashed",json.dumps(result))
        self.assertEqual(final["signal"],"SIGSEGV",json.dumps(result))
        self.assertTrue(all(final["cleanup"].values()),json.dumps(result)); self.assertEqual(rc,0)

    def test_N15_debugger_register_stack_evidence(self):
        frames=[self.start_frame(["segv"],duration=12000,mode="debug"),
                {"request_id":"run","action":"debug","timeout_ms":4000,"command":{"action":"run"}},
                {"request_id":"registers","action":"debug","timeout_ms":3000,"command":{"action":"registers"}},
                {"request_id":"stack","action":"debug","timeout_ms":3000,"command":{"action":"stack","count":8}},
                {"request_id":"stop","action":"stop"}]
        out=io.StringIO(); rc=serve(LiveFrames(frames),out,self.sandbox); result=unpack(out)
        by_id={frame.get("request_id"):frame for frame in result}
        self.assert_debug_register_stack_evidence(by_id,result)
        self.assertEqual(result[-1]["observation"]["target_state"],"crashed")
        self.assertEqual(result[-1]["observation"]["signal"],"SIGSEGV")
        self.assertTrue(all(result[-1]["observation"]["cleanup"].values())); self.assertEqual(rc,0)


if __name__=="__main__" and len(sys.argv)>=3 and sys.argv[1]=="--acceptance-json":
    destination=Path(sys.argv[2])
    destination.parent.mkdir(parents=True,exist_ok=True)
    stream=io.StringIO()
    selected=sys.argv[3:]
    suite=(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name,NativeDockerIntegration) for name in selected)
           if selected else unittest.defaultTestLoader.loadTestsFromTestCase(NativeDockerIntegration))
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    log=stream.getvalue()
    destination.with_suffix(".log").write_text(log,encoding="utf-8")
    payload={"image_id":NativeDockerIntegration.image if hasattr(NativeDockerIntegration,"image") else None,
             "fixture_compiler": "container" if getattr(NativeDockerIntegration,"compile_in_image",False) else "host",
             "test_count":result.testsRun,"passed":result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
             "failed":len(result.failures)+len(result.errors),"skipped":[{"test":str(test),"reason":reason} for test,reason in result.skipped],
             "failures":[{"test":str(test),"traceback":trace} for test,trace in result.failures],
             "errors":[{"test":str(test),"traceback":trace} for test,trace in result.errors],
             "log_path":str(destination.with_suffix(".log"))}
    destination.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    print(json.dumps(payload,indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
elif __name__=="__main__": unittest.main()
