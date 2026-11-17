"""Docker-free contract tests for the native runner hardening.

These tests use scripted in-memory MI/byte streams.  They never invoke Docker,
so they run on Windows as well as the Linux lab host.
"""
import base64
import io
import json
import os
import queue
import re
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from . import main as runner_main
from .cases import evaluate_assertion, validate_assertion
from .elf import elf_file_offset, inspect_elf
from .gdb_mi import (MAX_MI_LINE, MIReader, command, parse_record)
from .main import (_build_target_observation, _parse_proc_maps, doctor,
                   expectation_matches, serve)
from .process import ByteReader, OutputBudget
from .sandbox import (DockerSandbox, docker_environment, normalize_target,
                      validate_argv)


def elf64():
    b = bytearray(120)
    b[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", b, 16, 2, 62, 1)
    struct.pack_into("<Q", b, 32, 64)
    struct.pack_into("<HHH", b, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", b, 64, 1, 5, 0, 0x400000, 0x400000, len(b), len(b), 0x1000)
    return bytes(b)


class BlockingStream:
    def __init__(self):
        self.lines = queue.Queue()
        self.closed = False

    def feed(self, text):
        self.lines.put(text.encode("utf-8") if isinstance(text, str) else text)

    def close(self):
        self.closed = True
        self.lines.put(None)

    def read(self, size=-1):
        item = self.lines.get()
        if item is None:
            return b""
        return item


class LiveInput:
    """One JSONL line, then an owner that stays connected."""
    def __init__(self, frame):
        self.first = (json.dumps(frame) + "\n").encode()
        self.used = False
        self.never = threading.Event()

    def readline(self, size=-1):
        if not self.used:
            self.used = True
            return self.first
        self.never.wait()
        return b""

    def fileno(self):
        raise OSError("in-memory")


class CommandPipe(io.BytesIO):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler
        self.commands = []
        self.write_count = 0

    def write(self, data):
        self.write_count += 1
        for line in bytes(data).decode("ascii", "replace").splitlines():
            self.commands.append(line)
            self.handler(line)
        return len(data)


class ScriptedProc:
    def __init__(self, handler):
        self.stdout = BlockingStream()
        self.stderr = BlockingStream()
        self.stdin = CommandPipe(handler)
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = -15
        self.stdout.close()
        self.stderr.close()

    def kill(self):
        self.terminate()


class ContractSandbox:
    def __init__(self, proc, target_metadata=None, attached=None, output_source="target_stdout"):
        self.proc = proc
        self.staging = tempfile.mkdtemp(prefix="artex-contract-")
        self.target_metadata = target_metadata or {}
        self.attached = attached or []
        self.output_source = output_source
        self.cleanup_calls = 0
        self.last_start = None

    def inspect_elf(self, path):
        return "a" * 64

    def start(self, artifact, sha256, argv, mode, profile, duration_ms, target=None,
              input_mode="stdin", input_data=None):
        self.last_start = {"artifact": artifact, "sha256": sha256, "argv": argv,
                           "mode": mode, "profile": profile, "duration_ms": duration_ms,
                           "target": target, "input_mode": input_mode,
                           "input_data": input_data}
        return {"name": "fake", "process": self.proc, "staging": self.staging,
                "deadline": time.monotonic() + 10, "mode": mode,
                "target_metadata": self.target_metadata,
                "attached_artifacts": self.attached,
                "attachments_by_container": {item["container_path"]: item
                                             for item in self.attached},
                "output_source": self.output_source,
                "output_trusted": self.output_source != "harness_stdout",
                "core_path": None, "core_meta": None}

    def cleanup(self, session):
        self.cleanup_calls += 1
        import shutil
        shutil.rmtree(self.staging, ignore_errors=True)
        return {"owned_process_terminated": True, "container_removed": True,
                "staging_removed": True, "core_removed": True}


class FailingCleanupSandbox(ContractSandbox):
    def cleanup(self, session):
        super().cleanup(session)
        return {"owned_process_terminated": True, "container_removed": False,
                "staging_removed": True, "core_removed": True}


def run_session(first, frames, sandbox):
    inp = io.StringIO("\n".join(json.dumps(frame) for frame in [first, *frames]) + "\n")
    out = io.StringIO()
    rc = serve(inp, out, sandbox)
    return rc, [json.loads(line) for line in out.getvalue().splitlines()]


def by_id(frames):
    return {frame.get("request_id"): frame for frame in frames}


def mi_handler(proc, stop_after_run=True, respond_registers=True, run_only_running=False,
               memory_contents="deadbeef", memory_empty=False, memory_malformed=False):
    def handle(line):
        match = re.match(r"^([0-9]+)(-.*)$", line)
        token, cmd = (match.group(1), match.group(2)) if match else ("", line)
        if cmd == "-exec-run":
            proc.stdout.feed(f"{token}^running\n")
            if not run_only_running:
                proc.stdout.feed('*stopped,reason="signal-received",signal-name="SIGSEGV",'
                                 'frame={addr="0x401234",func="main",file="fixture.c",line="9"},'
                                 'thread-id="1",stopped-threads="all"\n')
        elif cmd == "-exec-interrupt":
            proc.stdout.feed(f"{token}^done\n")
            proc.stdout.feed('*stopped,reason="signal-received",signal-name="SIGSEGV",'
                             'frame={addr="0x401234",func="main"}\n')
        elif cmd == "-gdb-set mi-async on":
            proc.stdout.feed(f"{token}^done\n")
        elif cmd == "-gdb-show mi-async":
            proc.stdout.feed(f'{token}^done,value="on"\n')
        elif cmd.startswith("-gdb-show disable-randomization"):
            proc.stdout.feed(f'{token}^done,value="off"\n')
        elif cmd.startswith("-data-list-register-names"):
            proc.stdout.feed(f'{token}^done,register-names=["rax","rip","rsp"]\n')
        elif cmd.startswith("-data-list-register-values"):
            if respond_registers:
                proc.stdout.feed(f'{token}^done,register-values=[{{number="0",value="0x1"}},'
                                 f'{{number="1",value="0x401234"}},{{number="2",value="0x7fff"}}]\n')
        elif cmd.startswith("-stack-list-frames"):
            proc.stdout.feed(f'{token}^done,stack=[frame={{level="0",addr="0x401234",'
                             f'func="main",file="fixture.c",line="9"}}]\n')
        elif cmd.startswith("-list-thread-groups"):
            proc.stdout.feed(f'{token}^done,groups=[{{id="i1",type="process",pid="4242"}}]\n')
        elif cmd.startswith("-file-list-shared-libraries"):
            proc.stdout.feed(f'{token}^done,shared-libraries=[{{id="/lib/libc.so.6",'
                             f'target-name="/lib/libc.so.6",ranges=[{{from="0x7f0000000000",'
                             f'to="0x7f0000200000"}}]}}]\n')
        elif cmd.startswith("-break-insert"):
            proc.stdout.feed(f'{token}^done,bkpt={{number="1",addr="0x1000",func="main"}}\n')
        elif cmd.startswith("-data-read-memory-bytes"):
            if memory_empty:
                proc.stdout.feed(f"{token}^done\n")
            elif memory_malformed:
                proc.stdout.feed(f'{token}^done,memory=[{{begin="0x1000",offset="0",'
                                 f'end="0x1004",contents="zz"}}]\n')
            else:
                proc.stdout.feed(f'{token}^done,memory=[{{begin="0x1000",offset="0",'
                                 f'end="0x1004",contents="{memory_contents}"}}]\n')
        elif cmd.startswith("-gdb-generate-core-file"):
            proc.stdout.feed(f"{token}^done\n")
        else:
            proc.stdout.feed(f'{token}^done\n')
    return handle


class ElfContractTests(unittest.TestCase):
    def test_build_id_note_and_load_metadata(self):
        build_id = b"abcd"
        note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
        note = note + b"\0" * ((4 - len(note) % 4) % 4)
        phoff = 64
        note_off = phoff + 2 * 56
        size = note_off + len(note)
        data = bytearray(size)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", data, 16, 2, 62, 1)
        struct.pack_into("<Q", data, 32, phoff)
        struct.pack_into("<HHH", data, 52, 64, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, phoff, 1, 5, 0, 0x400000, 0x400000, size, 0x1000, 0x1000)
        struct.pack_into("<IIQQQQQQ", data, phoff + 56, 4, 4, note_off, 0, 0, len(note), len(note), 4)
        data[note_off:] = note
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(bytes(data))
            path = handle.name
        try:
            meta = inspect_elf(path)
            self.assertEqual(meta["build_id"], build_id.hex())
            self.assertEqual(len(meta["loads"]), 1)
            self.assertEqual(elf_file_offset(meta, 0x400100), 0x100)
        finally:
            os.unlink(path)


class MIParserContractTests(unittest.TestCase):
    def test_malformed_mi_is_preserved_not_raised(self):
        for raw in ('*stopped,reason="unterminated',
                    '^done,frame={addr=',
                    '^done,frame={addr="0x1"'):
            record = parse_record(raw)
            self.assertEqual(record["kind"], "malformed", raw)
            self.assertEqual(record["raw"], raw)
            self.assertIn("error", record)

    def test_oversized_mi_line_is_rejected(self):
        record = parse_record("~" + "x" * (MAX_MI_LINE + 10))
        self.assertEqual(record["kind"], "malformed")

    def test_nested_mi_values_and_raw_are_preserved(self):
        raw = ('*stopped,reason="signal-received",signal-name="SIGSEGV",'
               'frame={addr="0x401234",func="main",args=[{name="argc",value="1"}]}')
        record = parse_record(raw)
        self.assertEqual(record["record"], "*")
        self.assertEqual(record["class"], "stopped")
        self.assertEqual(record["values"]["frame"]["addr"], "0x401234")
        self.assertEqual(record["values"]["frame"]["args"][0]["name"], "argc")
        self.assertEqual(record["raw"], raw)
        self.assertEqual(record["body"], raw[raw.index(","):])

    def test_mi_stream_escapes_decode(self):
        record = parse_record('~"line one\\nline two"\n')
        self.assertEqual(record["kind"], "stream")
        self.assertEqual(record["text"], "line one\nline two")

    def test_typed_command_table_rejects_console_eval_and_unknown_fields(self):
        self.assertEqual(command("continue", {}), "-exec-continue")
        self.assertEqual(command("memory", {"address": 0x1000, "length": 4}), "-data-read-memory-bytes 0x1000 4")
        for action, args in (
                ("console", {}), ("eval", {"expression": "1"}),
                ("registers", {"pid": 1}), ("memory", {"address": 1, "length": 1, "target": "x"}),
                ("run", {"address": 1}), ("memory", {"address": True, "length": 4}),
                ("memory", {"address": 1, "length": 999999})):
            with self.assertRaises(ValueError, msg=(action, args)):
                command(action, args)
        self.assertEqual(command("run", {}, token="12"), "12-exec-run")
        self.assertEqual(command("start", {}), "-exec-run --start")
        self.assertEqual(command("start", {}, token="13"), "13-exec-run --start")
        with self.assertRaises(ValueError):
            command("run", {}, token="12\n-console")


class MIReaderContractTests(unittest.TestCase):
    def test_async_running_then_stopped_are_buffered_in_order(self):
        stream = BlockingStream()
        reader = MIReader(stream)
        stream.feed('*running,thread-id="all"\n')
        time.sleep(0.02)
        stream.feed('*stopped,reason="breakpoint-hit",frame={addr="0x401000"}\n')
        stream.close()
        deadline = time.monotonic() + 2
        records = []
        while time.monotonic() < deadline:
            chunk = reader.drain()
            records.extend(chunk)
            if reader.eof and not chunk:
                break
            time.sleep(0.01)
        classes = [(record.get("record"), record.get("class")) for record in records]
        self.assertIn(("*", "running"), classes)
        self.assertIn(("*", "stopped"), classes)
        self.assertTrue(all("raw" in record for record in records))


class ObservationContractTests(unittest.TestCase):
    def setUp(self):
        self.meta = {"type": 2, "loads": [{"vaddr": 0x400000, "offset": 0,
                                           "filesz": 0x2000, "memsz": 0x2000}],
                     "build_id": "deadbeef"}
        self.stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                     "frame": {"addr": "0x401234"}}

    def test_main_module_offset_and_signature_from_proc_maps(self):
        maps = _parse_proc_maps("00400000-00402000 r-xp 00000000 00:01 1 /work/sample\n"
                                "7f0000000000-7f0000200000 r-xp 00000000 00:01 2 /lib/libc.so.6\n")
        observation = _build_target_observation(
            "a" * 64, self.meta, {}, self.stop, {"rip": "0x401234"}, None, None, maps)
        self.assertEqual(observation["evidence_source"], "target_debugger")
        self.assertEqual(observation["raw_pc"], 0x401234)
        self.assertEqual(observation["module_path"], "/work/sample")
        self.assertEqual(observation["module_offset"], 0x1234)
        self.assertEqual(observation["module_sha256"], "a" * 64)
        self.assertEqual(observation["crash_signature"]["signal"], 11)
        self.assertEqual(observation["crash_signature"]["module_offset"], 0x1234)

    def test_unknown_shared_module_identity_has_no_invented_signature(self):
        maps = _parse_proc_maps("7f0000000000-7f0000200000 r-xp 00000000 00:01 2 /lib/libc.so.6\n")
        stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                "frame": {"addr": "0x7f0000001234"}}
        observation = _build_target_observation(
            "a" * 64, self.meta, {}, stop, None, None, None, maps)
        self.assertEqual(observation["module_path"], "/lib/libc.so.6")
        self.assertEqual(observation["module_offset"], 0x1234)
        self.assertIsNone(observation["module_sha256"])
        self.assertIsNone(observation["module_build_id"])
        self.assertFalse(observation["module_identity_known"])
        self.assertIn("module_identity", observation["unknown_fields"])
        self.assertIsNone(observation["crash_signature"])

    def test_build_id_only_identity_is_emitted(self):
        attached = {"/work/deps/libx.so": {"sha256": None, "build_id": "0123abcd"}}
        maps = _parse_proc_maps("7f0000000000-7f0000200000 r-xp 00000000 00:01 2 /work/deps/libx.so\n")
        stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                "frame": {"addr": "0x7f0000001234"}}
        observation = _build_target_observation(
            "a" * 64, self.meta, attached, stop, None, None, None, maps)
        self.assertEqual(observation["module_build_id"], "0123abcd")
        self.assertEqual(observation["crash_signature"]["module_build_id"], "0123abcd")

    def test_main_executable_maps_and_elf_fallback_agree(self):
        stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                "frame": {"addr": "0x401234"}}
        maps = _parse_proc_maps("00400000-00402000 r-xp 00000000 00:01 1 /work/sample\n")
        by_maps = _build_target_observation(
            "a" * 64, self.meta, {}, stop, None, None, None, maps)
        by_elf = _build_target_observation(
            "a" * 64, self.meta, {}, stop, None, None, None, None)
        for observation in (by_maps, by_elf):
            self.assertEqual(observation["module_path"], "/work/sample")
            self.assertEqual(observation["module_offset"], 0x1234)
            self.assertEqual(observation["module_offset_basis"], "elf_file_offset")
            self.assertEqual(observation["module_sha256"], "a" * 64)
            self.assertEqual(observation["crash_signature"]["module_offset"], 0x1234)
        self.assertEqual(by_maps["module_offset"], by_elf["module_offset"])

    def test_shared_library_fallback_offset_is_unknown_without_maps(self):
        attached = {"/work/deps/liba.so": {"sha256": None, "build_id": "0123abcd"}}
        stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                "frame": {"addr": "0x70001123"}}
        maps = _parse_proc_maps("70001000-70002000 r-xp 00001000 00:01 2 /work/deps/liba.so\n")
        by_maps = _build_target_observation(
            "a" * 64, self.meta, attached, stop, None, None,
            [{"path": "/work/deps/liba.so",
              "ranges": [{"from": 0x70001000, "to": 0x70002000}]}], maps)
        self.assertEqual(by_maps["module_offset"], 0x1123)
        self.assertEqual(by_maps["module_offset_basis"], "elf_file_offset")
        self.assertIsNotNone(by_maps["crash_signature"])
        fallback = _build_target_observation(
            "a" * 64, self.meta, attached, stop, None, None,
            [{"path": "/work/deps/liba.so",
              "ranges": [{"from": 0x70001000, "to": 0x70002000}]}], None)
        self.assertEqual(fallback["module_path"], "/work/deps/liba.so")
        self.assertIsNone(fallback["module_offset"])
        self.assertIsNone(fallback["module_offset_basis"])
        self.assertIn("module_offset", fallback["unknown_fields"])
        self.assertIsNone(fallback["crash_signature"])
        missing = _build_target_observation(
            "a" * 64, self.meta, attached, stop, None, None, None, None)
        self.assertEqual(missing["module_path"], "unknown")
        self.assertIsNone(missing["module_offset"])
        self.assertIsNone(missing["crash_signature"])

    def test_pie_without_runtime_base_keeps_explicit_unknown(self):
        meta = {"type": 3, "loads": [{"vaddr": 0, "offset": 0, "filesz": 100, "memsz": 100}],
                "build_id": "deadbeef", "text_vaddr": 0x1000}
        stop = {"reason": "signal-received", "signal-name": "SIGSEGV",
                "frame": {"addr": "0x555555551234"}}
        observation = _build_target_observation("a" * 64, meta, {}, stop, None, None, None, None)
        self.assertEqual(observation["raw_pc"], 0x555555551234)
        self.assertIsNone(observation["module_offset"])
        self.assertIn("module_offset", observation["unknown_fields"])
        self.assertIsNone(observation["crash_signature"])

    def test_elf_file_offset_translation(self):
        self.assertEqual(elf_file_offset(self.meta, 0x401234), 0x1234)
        self.assertIsNone(elf_file_offset(self.meta, 0x900000))


class ValidationContractTests(unittest.TestCase):
    def test_target_schema_rejects_unknown_and_malformed_attachments(self):
        with self.assertRaises(ValueError):
            normalize_target({"dependencies": [], "address": 1})
        with self.assertRaises(ValueError):
            normalize_target({"dependencies": [{"artifact_path": "x", "sha256": "a" * 64,
                                                "name": "x", "address": 1}]})
        with self.assertRaises(ValueError):
            normalize_target({"loader": {"artifact_path": "x", "sha256": "a" * 64,
                                         "name": "x", "mount": "/etc"}})
        with self.assertRaises(ValueError):
            normalize_target({"harness": {"artifact_path": "x", "sha256": "a" * 64,
                                          "language": "ruby"}})

    def test_file_placeholder_is_exact_and_required(self):
        self.assertEqual(validate_argv(["arg", "{input}"], "file"), ["arg", "{input}"])
        with self.assertRaises(ValueError):
            validate_argv(["arg"], "file")
        with self.assertRaises(ValueError):
            validate_argv(["prefix-{input}"], "file")
        with self.assertRaises(ValueError):
            validate_argv(["{input}"], "stdin")

    def test_sandbox_rejects_unknown_target_before_launch(self):
        box = DockerSandbox(popen=Mock(), run=Mock())
        with self.assertRaises(ValueError):
            box.start("unused", "a" * 64, [], "exec", {"image": "lab@sha256:" + "a" * 64},
                      1000, {"dependencies": [], "address": 1})

    def test_file_mode_mount_and_exact_replacement(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(elf64())
            path = handle.name
        try:
            proc = Mock()
            proc.poll.return_value = None
            proc.stdin, proc.stdout, proc.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
            box = DockerSandbox(popen=Mock(return_value=proc), run=Mock())
            session = box.start(path, __import__("hashlib").sha256(elf64()).hexdigest(),
                                ["a", "{input}"], "exec",
                                {"image": "lab@sha256:" + "a" * 64}, 1000,
                                {}, "file", b"data")
            args = box._popen.call_args.args[0]
            mount_values = [args[i + 1] for i, item in enumerate(args) if item == "--mount"]
            self.assertTrue(any("dst=/work/input.bin" in value for value in mount_values))
            self.assertIn("/work/input.bin", args)
            box.cleanup(session)
        finally:
            os.unlink(path)

    def test_debug_command_line_enables_mi_async(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(elf64())
            path = handle.name
        try:
            proc = Mock()
            proc.poll.return_value = None
            proc.stdin, proc.stdout, proc.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
            box = DockerSandbox(popen=Mock(return_value=proc), run=Mock())
            box._run.return_value.returncode = 0
            session = box.start(path, __import__("hashlib").sha256(elf64()).hexdigest(),
                                [], "debug",
                                {"image": "lab@sha256:" + "a" * 64,
                                 "seccomp_profile": "deploy/native-lab/seccomp-debug.json"},
                                1000)
            args = box._popen.call_args.args[0]
            self.assertIn("--eval-command=set mi-async on", args)
            self.assertIn("--interpreter=mi2", args)
            box.cleanup(session)
        finally:
            os.unlink(path)

    def test_docker_environment_does_not_inherit_secrets(self):
        with patch.dict(os.environ, {"PATH": "/bin", "AWS_SECRET_ACCESS_KEY": "secret",
                                     "ARTEX_TEST_SECRET": "secret"}, clear=False):
            env = docker_environment()
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("ARTEX_TEST_SECRET", env)
            self.assertEqual(env["PATH"], "/bin")


class SessionDebugContractTests(unittest.TestCase):
    def _start(self, duration=2000):
        return {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                "sha256": "a" * 64, "argv": [], "mode": "debug", "duration_ms": duration,
                "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}

    def test_run_uses_actual_running_and_stopped_records_then_allows_registers(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"])(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc, target_metadata={
            "type": 2, "loads": [{"vaddr": 0x400000, "offset": 0, "filesz": 0x2000,
                                 "memsz": 0x2000}], "build_id": "deadbeef"})
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 2000,
             "command": {"action": "run"}},
            {"request_id": "regs", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "registers"}},
            {"request_id": "stack", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "stack", "count": 4}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        frames_by_id = by_id(result)
        self.assertEqual(rc, 0, json.dumps(result))
        self.assertEqual(frames_by_id["run"]["observation"]["target_state"], "stopped")
        self.assertTrue(frames_by_id["run"]["observation"]["records"])
        self.assertEqual(frames_by_id["regs"]["observation"]["registers"]["rip"], "0x401234")
        self.assertTrue(frames_by_id["stack"]["observation"]["stack"])
        final = result[-1]["observation"]
        self.assertEqual(final["target_state"], "crashed")
        self.assertEqual(final["signal"], "SIGSEGV")
        observation = final["target_observation"]
        self.assertEqual(observation["evidence_source"], "target_debugger")
        self.assertEqual(observation["raw_pc"], 0x401234)
        self.assertEqual(observation["module_offset"], 0x1234)
        self.assertEqual(observation["crash_signature"]["signal"], 11)
        self.assertEqual(observation["crash_signature"]["artifact_sha256"], "a" * 64)
        self.assertTrue(final["cleanup_verified"])
        self.assertEqual(sandbox.cleanup_calls, 1)

    def test_registers_are_rejected_while_running_and_do_not_reach_gdb(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"], run_only_running=True)(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 120,
             "command": {"action": "run"}},
            {"request_id": "regs", "action": "debug", "timeout_ms": 120,
             "command": {"action": "registers"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        frames_by_id = by_id(result)
        self.assertEqual(frames_by_id["run"]["observation"]["target_state"], "running")
        self.assertTrue(frames_by_id["run"]["observation"]["timed_out"])
        self.assertIn("target is running", frames_by_id["regs"]["observation"]["error"])
        self.assertFalse(any("-data-list-register-values" in command for command in proc.stdin.commands))
        self.assertEqual(result[-1]["observation"]["target_state"], "cancelled")
        self.assertEqual(rc, 0)

    def test_interrupt_while_running_updates_state_from_stopped_record(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"], run_only_running=True)(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 100,
             "command": {"action": "run"}},
            {"request_id": "interrupt", "action": "debug", "timeout_ms": 500,
             "command": {"action": "interrupt"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        frames_by_id = by_id(result)
        self.assertEqual(frames_by_id["interrupt"]["observation"]["target_state"], "stopped")
        self.assertEqual(result[-1]["observation"]["target_state"], "crashed")
        self.assertEqual(rc, 0)

    def test_startup_enables_mi_async_before_execution_and_interrupts(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"], run_only_running=True)(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 100,
             "command": {"action": "run"}},
            {"request_id": "interrupt", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "interrupt"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        commands = proc.stdin.commands
        set_index = commands.index("1-gdb-set mi-async on")
        show_index = commands.index("2-gdb-show mi-async")
        run_index = next(index for index, command in enumerate(commands)
                         if command.endswith("-exec-run"))
        self.assertLess(set_index, show_index)
        self.assertLess(show_index, run_index)
        ready = result[0]["observation"]
        self.assertTrue(ready["debug_available"])
        self.assertTrue(ready["debug_setup"]["ok"])
        self.assertEqual(ready["debug_setup"]["mi_async"], "on")
        frames_by_id = by_id(result)
        self.assertEqual(frames_by_id["interrupt"]["observation"]["target_state"], "stopped")
        self.assertEqual(result[-1]["observation"]["target_state"], "crashed")
        self.assertEqual(rc, 0)

    def test_mi_async_setup_failure_does_not_advertise_debug_support(self):
        holder = {}

        def handler(line):
            match = re.match(r"^([0-9]+)(-.*)$", line)
            token, cmd = (match.group(1), match.group(2)) if match else ("", line)
            if cmd == "-gdb-set mi-async on":
                holder["proc"].stdout.feed(f'{token}^error,msg="mi-async unsupported"\n')
            elif cmd == "-gdb-show mi-async":
                holder["proc"].stdout.feed(f'{token}^done,value="off"\n')
            elif cmd.startswith("-gdb-show disable-randomization"):
                holder["proc"].stdout.feed(f'{token}^done,value="off"\n')
            else:
                holder["proc"].stdout.feed(f"{token}^done\n")
        proc = ScriptedProc(lambda line: handler(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "run"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        ready = result[0]["observation"]
        self.assertFalse(ready["debug_available"])
        self.assertFalse(ready["debug_setup"]["ok"])
        self.assertIn("mi-async", ready["debug_setup"]["error"])
        final = result[-1]["observation"]
        self.assertEqual(final["target_state"], "failed")
        self.assertEqual(final["signal_source"], "debugger_unavailable")
        self.assertIsNone(final["target_observation"])
        self.assertTrue(any("mi-async setup failed" in error for error in final["errors"]))
        self.assertFalse(any(command.endswith("-exec-run") for command in proc.stdin.commands))
        self.assertEqual(rc, 1)

    def test_memory_debug_action_decodes_role_wrapped_mi_values(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"], memory_contents="41424344")(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 2000,
             "command": {"action": "run"}},
            {"request_id": "mem", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "memory", "address": 0x1000, "length": 4}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        observation = by_id(result)["mem"]["observation"]
        self.assertEqual(base64.b64decode(observation["data_base64"]), b"ABCD")
        self.assertEqual(observation["bytes"], 4)
        self.assertEqual(observation["memory_rows"], 1)
        self.assertFalse(observation["invalid_contents"])
        self.assertFalse(observation["truncated"])
        self.assertEqual(rc, 0)

    def test_memory_debug_action_handles_empty_and_malformed_responses(self):
        for kwargs, invalid in (({"memory_empty": True}, False),
                                ({"memory_malformed": True}, True)):
            with self.subTest(kwargs=kwargs):
                holder = {}
                proc = ScriptedProc(lambda line: mi_handler(holder["proc"], **kwargs)(line))
                holder["proc"] = proc
                sandbox = ContractSandbox(proc)
                frames = [
                    {"request_id": "run", "action": "debug", "timeout_ms": 2000,
                     "command": {"action": "run"}},
                    {"request_id": "mem", "action": "debug", "timeout_ms": 1000,
                     "command": {"action": "memory", "address": 0x1000, "length": 4}},
                    {"request_id": "stop", "action": "stop"},
                ]
                rc, result = run_session(self._start(), frames, sandbox)
                observation = by_id(result)["mem"]["observation"]
                self.assertEqual(observation["data_base64"], "")
                self.assertEqual(observation["bytes"], 0)
                self.assertEqual(observation["invalid_contents"], invalid)
                self.assertNotIn("error", observation)
                self.assertEqual(rc, 0)

    def test_breakpoint_debug_action_decodes_role_wrapped_bkpt(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"])(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "bp", "action": "debug", "timeout_ms": 1000,
             "command": {"action": "breakpoint", "address": 0x1000}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        breakpoint = by_id(result)["bp"]["observation"]["breakpoint"]
        self.assertEqual(breakpoint["number"], "1")
        self.assertEqual(breakpoint["addr"], "0x1000")
        self.assertEqual(breakpoint["func"], "main")
        self.assertEqual(rc, 0)

    def test_malformed_mi_does_not_break_later_state(self):
        holder = {}

        def handler(line):
            match = re.match(r"^([0-9]+)(-.*)$", line)
            token, cmd = (match.group(1), match.group(2)) if match else ("", line)
            if cmd == "-exec-run":
                holder["proc"].stdout.feed(f'{token}^done,frame={{addr=\n')
                holder["proc"].stdout.feed(f"{token}^running\n")
                holder["proc"].stdout.feed('*stopped,reason="signal-received",'
                                           'signal-name="SIGSEGV",frame={addr="0x401000"}\n')
            elif cmd == "-gdb-show mi-async":
                holder["proc"].stdout.feed(f'{token}^done,value="on"\n')
            elif cmd.startswith("-gdb-show disable-randomization"):
                holder["proc"].stdout.feed(f'{token}^done,value="off"\n')
            else:
                holder["proc"].stdout.feed(f"{token}^done\n")
        proc = ScriptedProc(lambda line: handler(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "run", "action": "debug", "timeout_ms": 2000,
             "command": {"action": "run"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        self.assertEqual(result[-1]["observation"]["target_state"], "crashed", json.dumps(result))
        self.assertEqual(rc, 0)

    def test_unknown_debug_fields_are_rejected_without_writing_mi(self):
        holder = {}
        proc = ScriptedProc(lambda line: mi_handler(holder["proc"])(line))
        holder["proc"] = proc
        sandbox = ContractSandbox(proc)
        frames = [
            {"request_id": "bad", "action": "debug",
             "command": {"action": "registers", "pid": 1}},
            {"request_id": "bad2", "action": "debug",
             "command": {"action": "memory", "address": 1, "length": 1, "target": "host"}},
            {"request_id": "bad3", "action": "debug", "address": 1,
             "command": {"action": "interrupt"}},
            {"request_id": "stop", "action": "stop"},
        ]
        rc, result = run_session(self._start(), frames, sandbox)
        frames_by_id = by_id(result)
        self.assertIn("unsupported field", frames_by_id["bad"]["observation"]["error"])
        self.assertIn("unsupported field", frames_by_id["bad2"]["observation"]["error"])
        self.assertIn("unsupported debug request field", frames_by_id["bad3"]["observation"]["error"])
        self.assertFalse(any("-data-list-register-values" in command for command in proc.stdin.commands))
        self.assertEqual(rc, 0)


class ReplayAndLifecycleContractTests(unittest.TestCase):
    def test_exec_close_stdin_is_idempotent_and_send_is_rejected(self):
        proc = ScriptedProc(lambda line: None)
        class CountClose(io.BytesIO):
            calls = 0
            def close(self):
                self.calls += 1
                super().close()
        pipe = CountClose(); proc.stdin = pipe
        first = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                 "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                 "profile": {"image": "lab@sha256:" + "a" * 64}}
        close = {"request_id": "close", "action": "close_stdin"}
        rc, frames = run_session(first, [close, close,
            {"request_id": "close-again", "action": "close_stdin"},
            {"request_id": "late-send", "action": "send", "data_base64": "QQ=="},
            {"request_id": "stop", "action": "stop"}], ContractSandbox(proc))
        replies = by_id(frames)
        self.assertEqual(rc, 0)
        self.assertEqual(pipe.calls, 1)
        self.assertTrue(replies["close"]["observation"]["stdin_closed"])
        self.assertTrue(replies["close-again"]["observation"]["stdin_closed"])
        self.assertIn("stdin is closed", replies["late-send"]["observation"]["error"])
        self.assertTrue(frames[-1]["observation"]["cleanup_verified"])
        proc.stdout.close(); proc.stderr.close()

    def test_exec_close_stdin_allows_natural_exit(self):
        proc = ScriptedProc(lambda line: None)
        class ExitOnClose(io.BytesIO):
            def close(self):
                super().close()
                proc.returncode = 0
                proc.stdout.close(); proc.stderr.close()
        proc.stdin = ExitOnClose()
        first = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                 "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                 "profile": {"image": "lab@sha256:" + "a" * 64}}
        rc, frames = run_session(first, [{"request_id": "close", "action": "close_stdin"}],
                                 ContractSandbox(proc))
        self.assertEqual(rc, 0)
        self.assertTrue(by_id(frames)["close"]["observation"]["stdin_closed"])
        self.assertEqual(frames[-1]["observation"]["target_state"], "exit")
        self.assertEqual(frames[-1]["observation"]["exit_code"], 0)
        self.assertTrue(frames[-1]["observation"]["cleanup_verified"])

    def _replay(self, proc, **extra):
        request = {"operation": "replay", "request_id": "r1", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                   "profile": {"image": "lab@sha256:" + "a" * 64}, "input_base64": ""}
        request.update(extra)
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out, ContractSandbox(proc))
        return rc, json.loads(out.getvalue())["observation"]

    def test_replay_reads_stdout_and_stderr_without_deadlock(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.feed(b"stdout-data")
        proc.stderr.feed(b"stderr-data" * 4096)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 23
        rc, observation = self._replay(proc, expected_exit=23)
        self.assertEqual(observation["target_state"], "exit")
        self.assertEqual(base64.b64decode(observation["output_base64"]), b"stdout-data")
        self.assertTrue(observation["matches_expectation"])
        self.assertGreater(observation["stderr"]["bytes"], 4096)
        self.assertEqual(rc, 0)

    def test_expected_exit_mismatch_is_not_success(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        rc, observation = self._replay(proc, expected_exit=23)
        self.assertEqual(rc, 1)
        self.assertEqual(observation["target_state"], "exit")
        self.assertFalse(observation["matches_expectation"])

    def test_expected_signal_satisfied_is_success(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 139
        rc, observation = self._replay(proc, expected_signal=11)
        self.assertEqual(rc, 0)
        self.assertEqual(observation["target_state"], "crashed")
        self.assertEqual(observation["signal"], 11)
        self.assertTrue(observation["matches_expectation"])

    def test_wrong_signal_is_not_success(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 134
        rc, observation = self._replay(proc, expected_signal=11)
        self.assertEqual(rc, 1)
        self.assertEqual(observation["target_state"], "crashed")
        self.assertEqual(observation["signal"], 6)
        self.assertFalse(observation["matches_expectation"])

    def test_normal_exit_instead_of_expected_signal_is_not_success(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        rc, observation = self._replay(proc, expected_signal=11)
        self.assertEqual(rc, 1)
        self.assertEqual(observation["target_state"], "exit")
        self.assertEqual(observation["exit_code"], 0)
        self.assertFalse(observation["matches_expectation"])

    def test_unexpected_crash_is_not_a_successful_target_exit(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 139
        rc, observation = self._replay(proc)
        self.assertEqual(rc, 1)
        self.assertEqual(observation["target_state"], "crashed")
        self.assertEqual(observation["signal"], 11)
        self.assertFalse(observation["matches_expectation"])
        self.assertTrue(observation["cleanup_verified"])

    def test_output_limit_is_explicit_and_cleanup_verified(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.feed(b"x" * 5000)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        with patch.object(runner_main, "MAX_STREAM", 1024):
            rc, observation = self._replay(proc)
        self.assertEqual(rc, 1)
        self.assertEqual(observation["outcome"], "limited")
        self.assertTrue(observation["output_limited"])
        self.assertTrue(observation["cleanup_verified"])
        self.assertTrue(observation["cleanup"]["container_removed"])

    def test_cleanup_failure_is_explicit(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        request = {"operation": "replay", "request_id": "r1", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                   "profile": {"image": "lab@sha256:" + "a" * 64}, "input_base64": ""}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out,
                   FailingCleanupSandbox(proc))
        observation = json.loads(out.getvalue())["observation"]
        self.assertEqual(rc, 1)
        self.assertEqual(observation["outcome"], "cleanup_unverified")
        self.assertFalse(observation["cleanup_verified"])
        self.assertIn("cleanup could not be confirmed", observation["errors"])

    def test_session_lease_expiry_cleans_and_cancels(self):
        proc = ScriptedProc(lambda line: None)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 5000,
                   "lease_ms": 1000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        sandbox = ContractSandbox(proc)
        started = time.monotonic()
        inp = LiveInput(request)
        out = io.StringIO()
        rc = serve(inp, out, sandbox)
        elapsed = time.monotonic() - started
        final = json.loads(out.getvalue().splitlines()[-1])["observation"]
        self.assertEqual(final["target_state"], "cancelled")
        self.assertEqual(final["reason"], "lease_expired")
        self.assertTrue(final["cleanup_verified"])
        self.assertLess(elapsed, 4)
        self.assertEqual(rc, 0)

    def test_exec_natural_exit_is_not_reported_as_cancelled(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.feed(b"tail-bytes")
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        sandbox = ContractSandbox(proc)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 5000,
                   "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out, sandbox)
        final = json.loads(out.getvalue().splitlines()[-1])["observation"]
        self.assertEqual(final["target_state"], "exit")
        self.assertEqual(final["exit_code"], 0)
        self.assertEqual(base64.b64decode(final["output"]["tail_base64"]), b"tail-bytes")
        self.assertEqual(rc, 0)

    def test_harness_output_is_not_target_evidence(self):
        proc = ScriptedProc(lambda line: None)
        proc.stdout.feed(b"HARNESS_CLAIM")
        proc.stdout.close()
        proc.stderr.close()
        proc.returncode = 0
        request = {"operation": "replay", "request_id": "r1", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                   "profile": {"image": "lab@sha256:" + "a" * 64}, "input_base64": "",
                   "target": {"harness": {"artifact_path": "h.py", "sha256": "b" * 64,
                                          "language": "python"}}}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out,
                   ContractSandbox(proc, output_source="harness_stdout"))
        observation = json.loads(out.getvalue())["observation"]
        self.assertEqual(observation["output_source"], "harness_stdout")
        self.assertEqual(observation["target_evidence"], "harness_only")
        self.assertFalse(observation["target_exit_trusted"])
        self.assertEqual(observation["target_state_source"], "harness_process")
        self.assertEqual(rc, 0)

    def test_session_owner_eof_cleans_up(self):
        proc = ScriptedProc(lambda line: None)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 5000,
                   "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        sandbox = ContractSandbox(proc)
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out, sandbox)
        final = json.loads(out.getvalue().splitlines()[-1])["observation"]
        self.assertEqual(final["target_state"], "cancelled")
        self.assertEqual(final["reason"], "owner_eof")
        self.assertTrue(final["cleanup_verified"])
        self.assertEqual(sandbox.cleanup_calls, 1)
        self.assertEqual(rc, 0)

    def test_repeated_send_id_does_not_write_bytes_twice(self):
        proc = ScriptedProc(lambda line: None)
        sandbox = ContractSandbox(proc)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 2000,
                   "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        payload = base64.b64encode(b"once").decode()
        frames = [{"request_id": "send", "action": "send", "data_base64": payload},
                  {"request_id": "send", "action": "send", "data_base64": payload}]
        rc, result = run_session(request, frames, sandbox)
        sends = [frame for frame in result if frame.get("request_id") == "send"]
        self.assertEqual(len(sends), 2)
        self.assertEqual(sends[0]["observation"], sends[1]["observation"])
        self.assertLess(sends[0]["event_seq"], sends[1]["event_seq"])
        self.assertEqual(proc.stdin.write_count, 1)
        self.assertEqual(result[-1]["observation"]["target_state"], "cancelled")

    def test_reused_request_id_with_different_data_is_rejected(self):
        proc = ScriptedProc(lambda line: None)
        sandbox = ContractSandbox(proc)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 2000,
                   "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        frames = [{"request_id": "send", "action": "send",
                   "data_base64": base64.b64encode(b"one").decode()},
                  {"request_id": "send", "action": "send",
                   "data_base64": base64.b64encode(b"two").decode()}]
        rc, result = run_session(request, frames, sandbox)
        errors = [frame["observation"].get("error") for frame in result
                  if frame.get("request_id") == "send"]
        self.assertTrue(any("reused with different input" in str(error) for error in errors))
        self.assertEqual(proc.stdin.write_count, 1)

    def test_heartbeats_do_not_consume_request_cache(self):
        proc = ScriptedProc(lambda line: None)
        sandbox = ContractSandbox(proc)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 2000,
                   "lease_ms": 30000, "profile": {"image": "lab@sha256:" + "a" * 64}}
        frames = [{"request_id": f"hb-{index}", "action": "heartbeat"}
                  for index in range(runner_main.MAX_CACHE_ITEMS + 4)]
        rc, result = run_session(request, frames, sandbox)
        heartbeats = [frame for frame in result if str(frame.get("request_id", "")).startswith("hb-")]
        self.assertEqual(len(heartbeats), runner_main.MAX_CACHE_ITEMS + 4)
        self.assertFalse(any("session request limit reached" in json.dumps(frame)
                             for frame in heartbeats))

    def test_exceptional_initialization_reports_cleanup(self):
        class RaisingSandbox(ContractSandbox):
            def start(self, *args, **kwargs):
                raise RuntimeError("staging failed")
        proc = ScriptedProc(lambda line: None)
        sandbox = RaisingSandbox(proc)
        request = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                   "sha256": "a" * 64, "argv": [], "mode": "exec", "duration_ms": 1000,
                   "profile": {"image": "lab@sha256:" + "a" * 64}}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(request) + "\n"), out, sandbox)
        final = json.loads(out.getvalue())["observation"]
        self.assertEqual(final["target_state"], "failed")
        self.assertIn("staging failed", " ".join(final["errors"]))
        self.assertEqual(rc, 1)


class DoctorContractTests(unittest.TestCase):
    class Result:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def test_probe_timeout_removes_owned_container(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            joined = " ".join(str(item) for item in argv)
            if "version" in argv and "--format" in argv:
                return self.Result(0, "24.0.0")
            if "image" in argv and "inspect" in argv:
                return self.Result(0, '[{"Architecture":"amd64"}]')
            if "--entrypoint" in argv and "/usr/bin/gdb" in argv and "--version" in argv:
                return self.Result(0, "GNU gdb (Debian) 13.1")
            if "--entrypoint" in argv and "artex-ptrace-probe" in joined:
                raise subprocess.TimeoutExpired(argv, 20)
            if "rm" in argv:
                return self.Result(0, "")
            if "inspect" in argv:
                return self.Result(1, "", "No such object")
            if "--entrypoint" in argv and "/lib64/ld-linux-x86-64.so.2" in argv:
                return self.Result(0, "ld.so")
            if "--entrypoint" in argv and "/usr/bin/python3" in argv:
                return self.Result(0, "Python 3.11")
            return self.Result(0, "")

        result = doctor(profile={"settings": {"image": "lab@sha256:" + "a" * 64,
                                               "seccomp_profile": "deploy/native-lab/seccomp-debug.json"}},
                        run=fake_run)
        self.assertFalse(result["ptrace_available"])
        self.assertTrue(result["ptrace_probe_cleanup_verified"])
        self.assertIn("timed out", result["ptrace_probe_error"])
        names = [argv[argv.index("--name") + 1] for argv in calls if "--name" in argv]
        self.assertTrue(names)
        self.assertTrue(any("rm" in argv and names[0] in argv for argv in calls))

    def test_successful_bounded_probe_enables_debug(self):
        probe_calls = []

        def fake_run(argv, **kwargs):
            joined = " ".join(str(item) for item in argv)
            if "version" in argv and "--format" in argv:
                return self.Result(0, "24.0.0")
            if "image" in argv and "inspect" in argv:
                return self.Result(0, '[{"Architecture":"amd64"}]')
            if "--entrypoint" in argv and "/usr/bin/gdb" in argv and "--version" in argv:
                return self.Result(0, "GNU gdb (Debian) 13.1")
            if "--entrypoint" in argv and "artex-ptrace-probe" in joined:
                probe_calls.append(list(argv))
                return self.Result(0, "Program exited normally.")
            if "rm" in argv:
                return self.Result(0, "")
            if "inspect" in argv:
                return self.Result(1, "", "No such object")
            if "--entrypoint" in argv and "/lib64/ld-linux-x86-64.so.2" in argv:
                return self.Result(0, "ld.so")
            if "--entrypoint" in argv and "/usr/bin/python3" in argv:
                return self.Result(0, "Python 3.11")
            return self.Result(0, "")

        result = doctor(profile={"settings": {"image": "lab@sha256:" + "a" * 64,
                                               "seccomp_profile": "deploy/native-lab/seccomp-debug.json"}},
                        run=fake_run)
        self.assertTrue(result["ptrace_available"])
        self.assertIn("debug", result["actions"])
        self.assertTrue(result["ptrace_probe_cleanup_verified"])
        self.assertEqual(len(probe_calls), 1)
        probe = probe_calls[0]
        self.assertIn("--cap-drop=ALL", probe)
        self.assertIn("--user=65534:65534", probe)
        self.assertIn("--security-opt=no-new-privileges", probe)
        self.assertTrue(any(str(item).startswith("seccomp=") for item in probe))


class CaseSourceContractTests(unittest.TestCase):
    def test_output_assertion_uses_runner_target_stdout_label(self):
        assertion = {"type": "stdout_contains_base64",
                     "value": base64.b64encode(b"IMPACT").decode()}
        self.assertTrue(evaluate_assertion(
            {"target_state": "exit", "output_source": "target_stdout",
             "output_base64": assertion["value"]}, assertion))
        self.assertFalse(evaluate_assertion(
            {"target_state": "exit", "output_source": "harness_stdout",
             "output_base64": assertion["value"]}, assertion))
        self.assertFalse(evaluate_assertion(
            {"target_state": "exit", "output_source": "harness",
             "output_base64": assertion["value"]}, assertion))

    def test_debug_signal_number_is_accepted_for_signal_assertion(self):
        assertion = {"type": "signal", "value": 11, "exit_code": 139,
                     "signal_source": "debugger"}
        self.assertTrue(evaluate_assertion(
            {"target_state": "crashed", "exit_code": 139, "signal": "SIGSEGV",
             "signal_number": 11, "signal_source": "debugger"}, assertion))


class ManifestContractTests(unittest.TestCase):
    def test_environment_probe_uses_python_without_shell_utilities(self):
        calls=[]
        def fake(argv,**kwargs):
            calls.append(argv)
            if "run" in argv:
                return subprocess.CompletedProcess(argv,0,json.dumps({"architecture":"x86_64",
                    "kernel":"test-kernel","gdb":"GNU gdb 17.1","python":"Python 3.14",
                    "loader":"GLIBC 2.43","os":"Linux"}),"")
            return subprocess.CompletedProcess(argv,0,"sha256:"+"a"*64,"")
        result=DockerSandbox(run=fake).environment_manifest("sha256:"+"a"*64)
        self.assertEqual(result["kernel"],"test-kernel")
        self.assertEqual(result["gdb"],"GNU gdb 17.1")
        command=next(c for c in calls if "run" in c)
        self.assertEqual(command[command.index("--entrypoint")+1],"/usr/bin/python3")
        self.assertNotIn("/bin/sh",command)
        self.assertIn("--network=none",command)
        self.assertTrue(any("rm" in c for c in calls))

    def test_maps_probe_is_bounded_python_and_rejects_host_pid_strings(self):
        fake=Mock(return_value=subprocess.CompletedProcess([],0,"00400000-00401000 r-xp 0 00:00 0 /work/sample\n",""))
        box=DockerSandbox(run=fake)
        self.assertIsNone(box.read_inferior_maps({"name":"owned"},"1/../../etc/passwd"))
        fake.assert_not_called()
        self.assertIn("/work/sample",box.read_inferior_maps({"name":"owned"},7))
        command=fake.call_args.args[0]
        self.assertIn("/usr/bin/python3",command)
        self.assertNotIn("/bin/cat",command)
        self.assertEqual(command[-1],"7")

    def test_manifest_contains_hashes_and_no_host_secret_env(self):
        sandbox = ContractSandbox(ScriptedProc(lambda line: None), attached=[
            {"kind": "dependency", "name": "libx.so", "sha256": "b" * 64,
             "size": 1, "build_id": "abcd", "container_path": "/work/deps/libx.so"}])
        first = {"profile": {"image": "lab@sha256:" + "a" * 64}}
        environment = {"platform": "linux/x86_64", "architecture": "x86_64",
                       "kernel": "6.0", "gdb": "13.1", "loader": "2.36",
                       "python": "3.11", "image_id": "sha256:" + "c" * 64}
        manifest = runner_main._manifest("exec", "d" * 64, first, {
            "version": 1, "attached_artifacts": sandbox.attached}, environment)
        self.assertEqual(manifest["attached_hashes"][0]["sha256"], "b" * 64)
        self.assertEqual(manifest["image"], "lab@sha256:" + "a" * 64)
        self.assertEqual(manifest["environment"], environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", json.dumps(manifest))


class ReviewRegressionTests(unittest.TestCase):
    def test_replay_docker_client_signal_cannot_satisfy_expected_target_signal(self):
        for code in (-9, -15):
            with self.subTest(code=code):
                proc = ScriptedProc(lambda line: None)
                proc.returncode = code; proc.stdout.close(); proc.stderr.close()
                rc, result = ReplayAndLifecycleContractTests()._replay(proc, expected_signal=-code)
                self.assertEqual(rc, 1)
                self.assertEqual(result["target_state"], "failed")
                self.assertIsNone(result["exit_code"])
                self.assertIsNone(result["signal"])
                self.assertFalse(result["matches_expectation"])
                self.assertFalse(result["target_exit_trusted"])
                self.assertEqual(result["docker_exit_code"], code)
                self.assertEqual(result["docker_client_exit_code"], code)
                self.assertEqual(result["target_state_source"], "docker_client")
                self.assertEqual(result["signal_source"], "docker_client_signal")
                self.assertTrue(result["cleanup_verified"])

    def test_gdb_death_after_stop_is_failure_but_queued_target_exit_wins(self):
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                proc = ScriptedProc(lambda line: None)
                regular = mi_handler(proc)
                def handler(line):
                    if "-exec-continue" in line:
                        token = line.split("-", 1)[0]
                        proc.stdout.feed(f"{token}^running\n*running,thread-id=\"all\"\n")
                        if terminal:
                            # More than one drain batch: EOF must not hide the exit.
                            proc.stdout.feed('~"noise"\n' * 600 + '*stopped,reason="exited-normally"\n')
                        proc.returncode = 0 if terminal else -9
                        proc.stdout.close(); proc.stderr.close()
                    else:
                        regular(line)
                proc.stdin.handler = handler
                first = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                         "sha256": "a" * 64, "mode": "debug", "duration_ms": 1000}
                frames = [{"request_id": "run", "action": "debug", "command": {"action": "run"}},
                          {"request_id": "continue", "action": "debug", "command": {"action": "continue"}}]
                class OpenFrames:
                    def __init__(self):
                        self.q = queue.Queue()
                        for frame in [first, *frames]: self.q.put(json.dumps(frame) + "\n")
                    def readline(self, size=-1): return self.q.get()
                out = io.StringIO(); start = time.monotonic()
                rc = serve(OpenFrames(), out, ContractSandbox(proc))
                result = json.loads(out.getvalue().splitlines()[-1])["observation"]
                self.assertLess(time.monotonic() - start, 2)
                self.assertTrue(result["cleanup_verified"])
                self.assertEqual(rc, 0 if terminal else 1)
                self.assertEqual(result["target_state"], "exit" if terminal else "failed")
                if not terminal:
                    self.assertIn("GDB process exited before reporting target termination", result["errors"])
                    self.assertEqual(result["reason"], "debugger_exited_without_target_exit")

    def test_running_clears_current_stop_evidence_but_preserves_completed_reply(self):
        for record in ('*running,thread-id="all"', '7^running'):
            with self.subTest(record=record):
                runtime = object.__new__(runner_main._SessionRuntime)
                snapshot = {"raw_pc": 4096, "crash_signature": {"signal": 11}}
                stop = {"signal-name": "SIGSEGV", "frame": {"addr": "0x1000"}}
                completed_reply = {"target_observation": snapshot, "records": [dict(stop)]}
                tx = {"tokens": [], "results": {}, "cancelled": False}
                runtime.awaiting = {}; runtime.pending = None; runtime.observation_tx = tx
                runtime.state = {"target_state": "stopped", "exit_code": None,
                                 "signal_name": "SIGSEGV", "signal_number": 11,
                                 "stop_info": stop, "stop_snapshot": snapshot}
                runtime.apply_record(parse_record(record))
                self.assertEqual(runtime.state["target_state"], "running")
                for field in ("signal_name", "signal_number", "stop_info", "stop_snapshot", "exit_code"):
                    self.assertIsNone(runtime.state[field], field)
                self.assertTrue(tx["cancelled"])
                self.assertIsNone(runtime.observation_tx)
                self.assertEqual(completed_reply["target_observation"]["raw_pc"], 4096)
                self.assertEqual(completed_reply["target_observation"]["crash_signature"]["signal"], 11)
                self.assertEqual(completed_reply["records"][0]["signal-name"], "SIGSEGV")

    def test_core_snapshot_alias_exports_and_exposes_core(self):
        from types import SimpleNamespace
        for action in ("core", "core_snapshot"):
            with self.subTest(action=action):
                metadata = {"size": 4, "sha256": "b" * 64, "path": "/tmp/artex-core"}
                capture = Mock(return_value=metadata)
                runtime = SimpleNamespace(sandbox=SimpleNamespace(capture_core=capture), session={})
                result = runner_main._debug_extras({"action": action, "results": {}}, runtime)
                capture.assert_called_once_with(runtime.session)
                self.assertEqual(result["core"], metadata)
                self.assertEqual(runtime.session["core_meta"], metadata)

    def test_session_docker_client_signal_is_not_target_crash(self):
        for code in (-9, -15):
            with self.subTest(code=code):
                proc = ScriptedProc(lambda line: None)
                proc.returncode = code
                proc.stdout.close(); proc.stderr.close()
                sandbox = ContractSandbox(proc)
                first = {"operation": "session", "request_id": "start", "artifact_path": "fixture",
                         "sha256": "a" * 64, "mode": "exec", "duration_ms": 1000}
                rc, frames = run_session(first, [], sandbox)
                final = frames[-1]["observation"]
                self.assertEqual(rc, 1)
                self.assertEqual(final["target_state"], "failed")
                self.assertIsNone(final["exit_code"])
                self.assertIsNone(final["signal"])
                self.assertIsNone(final["signal_number"])
                self.assertEqual(final["docker_client_exit_code"], code)
                self.assertEqual(final["signal_source"], "docker_client_signal")
                self.assertEqual(final["target_state_source"], "docker_client")
                self.assertFalse(final["target_exit_trusted"])
                self.assertIn("Docker client terminated by signal", final["errors"])
                self.assertTrue(final["cleanup_verified"])
                self.assertEqual(sandbox.cleanup_calls, 1)


if __name__ == "__main__":
    unittest.main()
