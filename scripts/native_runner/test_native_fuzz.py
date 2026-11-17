import base64
import hashlib
import io
import json
import os
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from .fuzz import (
    MAX_CORPUS_BYTES, MAX_OUTPUT_DISK, MAX_OUTPUT_FILES, MAX_OUTPUT_FILE,
    MAX_RESPONSE, SUPERVISOR, SUPERVISOR_LIB, FuzzBudgetTimeout,
    FuzzCancelled, FuzzRunner, collect_tree_candidates, coverage_edges,
    read_stats, regular_bytes, remove_staging, safe_directory,
    scan_output_tree, serve_fuzz, validate,
)
from .sandbox import docker_environment

ANCHORED_FS = (hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
               and hasattr(os, "O_NONBLOCK")
               and os.open in getattr(os, "supports_dir_fd", set()))


def supervisor_functions():
    namespace = {"__name__": "artex_supervisor_test"}
    exec(SUPERVISOR_LIB, namespace)
    return namespace


def elf64():
    b = bytearray(120)
    b[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", b, 16, 2, 62, 1)
    struct.pack_into("<Q", b, 32, 64)
    struct.pack_into("<HHH", b, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", b, 64, 1, 5, 0, 0x400000, 0x400000, len(b), len(b), 0x1000)
    return bytes(b)


def seed(data):
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii")}


def request(**changes):
    value = {
        "operation": "fuzz", "request_id": "f1",
        "artifact_path": "fixture", "sha256": "a" * 64,
        "argv": [], "input_mode": "stdin",
        "profile": {"image": "sha256:" + "a" * 64, "fuzz_enabled": True},
        "duration_ms": 1000, "seeds": [seed(b"ZX")],
        "max_executions": 100, "max_crashes": 1,
    }
    value.update(changes)
    return value


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class FakeProc:
    def __init__(self, code=0, stdout=b"", stderr=b""):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class FakeRun:
    def __init__(self, inspect_running=b"false", rm=0, inspect=1, copy=None,
                 stop=0, rm_stderr=b"", inspect_stderr=b"no such container: x",
                 stop_stderr=b""):
        self.inspect_running, self.rm, self.inspect, self.copy = (
            inspect_running, rm, inspect, copy)
        self.stop, self.rm_stderr = stop, rm_stderr
        self.inspect_stderr, self.stop_stderr = inspect_stderr, stop_stderr
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if "stop" in args:
            return Mock(returncode=self.stop, stdout=b"", stderr=self.stop_stderr)
        if "cp" in args:
            if self.copy:
                self.copy(args)
            return Mock(returncode=0, stdout=b"", stderr=b"")
        if "rm" in args:
            return Mock(returncode=self.rm, stdout=b"", stderr=self.rm_stderr)
        if "inspect" in args:
            return Mock(returncode=self.inspect, stdout=self.inspect_running,
                        stderr=self.inspect_stderr)
        return Mock(returncode=0, stdout=b"", stderr=b"")


class RunnerHarness(FuzzRunner):
    """Campaign-flow harness that replaces only Docker execution boundaries."""

    def __init__(self, state="completed", output=True, cleanup_ok=True, probe_error=False):
        super().__init__(run=FakeRun())
        self.state, self.output, self.cleanup_ok, self.probe_error = state, output, cleanup_ok, probe_error
        self.saw_command = None

    def tool_checks(self, spec, cancelled, deadline):
        return {"afl_version": "4.04c", "showmap_version": "4.04c", "options_verified": True}

    def probe(self, spec, cancelled, deadline):
        if self.probe_error:
            raise ValueError("no AFL instrumentation edges were observed")
        return 3

    def campaign_process(self, spec, cancelled, deadline):
        if self.state == "timeout":
            return "timeout", "fake-fuzz", FakeProc(-15), ""
        if self.state != "completed":
            return self.state, "fake-fuzz", FakeProc(1), ""
        if not self.output:
            payload = {"exit": 0, "findings": False, "queue": [], "crashes": [],
                       "stats_base64": None, "truncated": False}
        else:
            queue = [{"name": "id_000000,seed", "sha256": hashlib.sha256(b"ZX").hexdigest(),
                      "data_base64": base64.b64encode(b"ZX").decode()}]
            crashes = [{"name": "id_000000,sig_06", "sha256": hashlib.sha256(b"ZZ").hexdigest(),
                        "data_base64": base64.b64encode(b"ZZ").decode()}]
            payload = {"exit": 0, "findings": True, "queue": queue, "crashes": crashes,
                       "stats_base64": base64.b64encode(
                           b"execs_done : 17\nsaved_crashes : 1\n").decode(),
                       "truncated": False}
        return self.state, "fake-fuzz", FakeProc(0), json.dumps(payload)

    def cleanup(self):
        stage_removed = self.staging is None or remove_staging(self.staging)
        return {"owned_process_terminated": True, "container_removed": self.cleanup_ok,
                "staging_removed": stage_removed}


class ValidationTests(unittest.TestCase):
    def test_valid_stdin_and_file(self):
        self.assertEqual(validate(request())["input_mode"], "stdin")
        value = request(input_mode="file", argv=["--file", "{input}"])
        self.assertEqual(validate(value)["input_mode"], "file")

    def test_unknown_and_unauthorized_fields(self):
        for value in (
            request(extra=True),
            request(operation="session"),
            request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": True, "command": "sh"}),
            request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": True, "secrets": []}),
            request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": False}),
            request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": True, "enabled": False}),
            request(profile={"image": "latest", "fuzz_enabled": True}),
            request(profile={"image": "sha256:" + "A" * 64, "fuzz_enabled": True}),
            request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": True, "network": "bridge"}),
            request(profile={"id": "x", "engine": "frida", "settings": {
                "image": "sha256:" + "a" * 64, "fuzz_enabled": True}}),
            request(request_id=""),
            request(request_id="x" * 129),
        ):
            with self.assertRaises(ValueError):
                validate(value)

    def test_budget_bounds(self):
        for change in (
            {"duration_ms": 999}, {"duration_ms": 60001},
            {"max_executions": 99}, {"max_executions": 1000001},
            {"max_crashes": 0}, {"max_crashes": 9},
            {"input_mode": "pipe"}, {"input_mode": None},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(request(**change))
        with self.assertRaises(ValueError):
            validate(request(profile={"image": "sha256:" + "a" * 64, "fuzz_enabled": True,
                                      "max_duration_ms": 1000}, duration_ms=1001))

    def test_argv_bounds(self):
        for argv, mode in (
            (["{input}"], "stdin"),
            ([], "file"),
            (["{input}", "{input}"], "file"),
            (["a{input}"], "stdin"),
            (["a{input}"], "file"),
            (["@@"], "stdin"),
            (["a\x00b"], "stdin"),
            (["A" * 4097], "stdin"),
            (["x"] * 65, "stdin"),
        ):
            with self.subTest(argv=argv, mode=mode), self.assertRaises(ValueError):
                validate(request(argv=argv, input_mode=mode))

    def test_seed_bounds(self):
        cases = [
            {"seeds": []}, {"seeds": [seed(b"")]},
            {"seeds": [{"sha256": "0" * 64, "data_base64": "QQ=="}]},
            {"seeds": [{"sha256": hashlib.sha256(b"A").hexdigest(), "data_base64": "QQ"}]},
            {"seeds": [dict(seed(b"A"), extra=1)]},
            {"seeds": [seed(b"A" * 4097)]},
            {"seeds": [seed(b"A" * 4096)] * 17},
            {"seeds": [seed(b"A")] * 33},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(request(**change))

    def test_seed_total_and_canonical(self):
        self.assertLessEqual(len(validate(request(seeds=[seed(b"A" * 4096)] * 16))["seeds"]), 16)
        bad = seed(b"ZX")
        bad["data_base64"] += "\n"
        with self.assertRaises(ValueError):
            validate(request(seeds=[bad]))

    def test_artifact_identity(self):
        for change in ({"artifact_path": ""}, {"artifact_path": "a\x00b"},
                       {"sha256": "A" * 64}, {"sha256": "a" * 63}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(request(**change))

    def test_profile_shape_with_nested_settings(self):
        value = request(profile={"id": "lab", "engine": "docker-native", "settings": {
            "image": "sha256:" + "a" * 64, "fuzz_enabled": True, "max_duration_ms": 1000,
            "platform": "linux", "network": "none", "read_only_root": True,
            "seccomp_profile": "deploy/x.json"}})
        self.assertEqual(validate(value)["image"], "sha256:" + "a" * 64)


class FilesystemTests(unittest.TestCase):
    def test_regular_bytes_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write(root / "target", b"data")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symlink unavailable: " + str(exc))
            with self.assertRaises(ValueError):
                regular_bytes(link, 10)
            self.assertEqual(regular_bytes(target, 10), b"data")

    def test_safe_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest("symlink unavailable: " + str(exc))
            with self.assertRaises(ValueError):
                safe_directory(link)

    def test_scan_tree_rejects_all_parent_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "retrieved"
            outside = Path(directory) / "outside"
            outside.mkdir()
            write(outside / "id_000000", b"ZZ")
            try:
                (root / "findings").mkdir(parents=True)
                (root / "findings" / "default").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest("symlink unavailable: " + str(exc))
            with self.assertRaises(ValueError):
                scan_output_tree(root)

    def test_scan_tree_bounds_files_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root / "a", b"a")
            write(root / "b", b"b")
            write(root / "c", b"c")
            with patch("scripts.native_runner.fuzz.MAX_OUTPUT_FILES", 2):
                with self.assertRaisesRegex(ValueError, "file count"):
                    scan_output_tree(root)
            with patch("scripts.native_runner.fuzz.MAX_OUTPUT_DISK", 2):
                with self.assertRaisesRegex(ValueError, "disk"):
                    scan_output_tree(root)
            with patch("scripts.native_runner.fuzz.MAX_OUTPUT_FILE", 0):
                with self.assertRaisesRegex(ValueError, "per-file"):
                    scan_output_tree(root)

    def test_scan_tree_rejects_special_and_symlinked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write(root / "target", b"x")
            try:
                (root / "link").symlink_to(target)
            except OSError as exc:
                self.skipTest("symlink unavailable: " + str(exc))
            with self.assertRaises(ValueError):
                scan_output_tree(root)

    def test_candidate_collection_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root / "findings" / "default" / "queue" / "id_000000,one", b"ZX")
            write(root / "findings" / "default" / "queue" / "id_000001,two", b"ZX")
            write(root / "findings" / "default" / "queue" / "id_000002,big", b"A" * 5000)
            write(root / "findings" / "default" / "queue" / "README.txt", b"readme")
            items, truncated = collect_tree_candidates(root, ("findings", "default", "queue"), 32, MAX_CORPUS_BYTES)
            self.assertEqual(len(items), 1)
            self.assertTrue(truncated)
            self.assertEqual(base64.b64decode(items[0]["data_base64"]), b"ZX")
            with self.assertRaises(ValueError):
                write(root / "findings" / "default" / "queue" / "surprise", b"x")
                collect_tree_candidates(root, ("findings", "default", "queue"), 32, MAX_CORPUS_BYTES)

    def test_stats_and_coverage_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stats = write(root / "fuzzer_stats", b"execs_done : 10\nsaved_crashes : 1\nunknown : 2\n")
            self.assertEqual(read_stats(stats), {"execs_done": 10, "saved_crashes": 1})
            good = write(root / "map", b"1:1\n2:2\n")
            self.assertEqual(coverage_edges(good), 2)
            for data in (b"", b"1:0\n", b"bad\n", b"1:1\n2:2\n3:3\n4:4\n5:5\n"):
                path = write(root / "bad", data)
                with patch("scripts.native_runner.fuzz.MAX_PROBE_MAP", 5):
                    with self.assertRaises(ValueError):
                        coverage_edges(path)


@unittest.skipUnless(ANCHORED_FS, "anchored dir_fd/O_NOFOLLOW APIs unavailable")
class SupervisorReadTests(unittest.TestCase):
    """Exercise the production in-container supervisor read path only."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artex-supervisor-")
        self.root = Path(self.temp.name)
        self.assertIn(SUPERVISOR_LIB, SUPERVISOR)
        self.lib = supervisor_functions()
        self.read = self.lib["read_regular"]
        self.collect = self.lib["collect"]

    def tearDown(self):
        self.temp.cleanup()

    def test_read_regular_normal_limit_and_missing(self):
        write(self.root / "plain.txt", b"hello")
        self.assertEqual(self.read(str(self.root / "plain.txt"), 16,
                                   root=str(self.root)), b"hello")
        with self.assertRaises(ValueError):
            self.read(str(self.root / "plain.txt"), 4, root=str(self.root))
        with self.assertRaises(ValueError):
            self.read(str(self.root / "missing.txt"), 16, root=str(self.root))
        with self.assertRaises(ValueError):
            self.read("/work/out/plain.txt", 16, root=str(self.root))

    def test_read_regular_rejects_symlink_parent_and_file(self):
        outside = tempfile.TemporaryDirectory(prefix="artex-supervisor-out-")
        self.addCleanup(outside.cleanup)
        outside_root = Path(outside.name)
        write(outside_root / "secret.txt", b"secret")
        write(self.root / "real.txt", b"real")
        try:
            (self.root / "linkdir").symlink_to(outside_root, target_is_directory=True)
            (self.root / "linkfile").symlink_to(outside_root / "secret.txt")
        except OSError as exc:
            self.skipTest("symlink unavailable: " + str(exc))
        with self.assertRaises(ValueError):
            self.read(str(self.root / "linkdir" / "secret.txt"), 64,
                      root=str(self.root))
        with self.assertRaises(ValueError):
            self.read(str(self.root / "linkfile"), 64, root=str(self.root))
        with self.assertRaises(ValueError):
            self.read(str(self.root / "linkdir"), 64, root=str(self.root))

    def test_read_regular_rejects_fifo(self):
        fifo = self.root / "fifo"
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError) as exc:
            self.skipTest("mkfifo unavailable: " + str(exc))
        with self.assertRaises(ValueError):
            self.read(str(fifo), 64, root=str(self.root))

    def test_collect_keeps_count_and_total_bounds(self):
        queue = self.root / "findings" / "default" / "queue"
        write(queue / "id_000000", b"aa")
        write(queue / "id_000001", b"bb")
        write(queue / "id_000002", b"cc")
        items, truncated, used = self.collect(str(queue), 2, 100,
                                             root=str(self.root))
        self.assertEqual(len(items), 2)
        self.assertTrue(truncated)
        self.assertEqual(used, 4)
        items, truncated, used = self.collect(str(queue), 10, 4,
                                             root=str(self.root))
        self.assertEqual(len(items), 2)
        self.assertTrue(truncated)
        self.assertEqual(used, 4)

    def test_anchored_root_fd_survives_directory_replacement(self):
        with tempfile.TemporaryDirectory(prefix="artex-anchor-") as base:
            root = Path(base) / "root"
            root.mkdir()
            write(root / "a.txt", b"original")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.rename(root, Path(base) / "moved")
                (Path(base) / "root").mkdir()
                write(Path(base) / "root" / "a.txt", b"replacement")
                self.assertEqual(
                    self.lib["_read_regular_at"](root_fd, ["a.txt"], 64),
                    b"original")
            finally:
                os.close(root_fd)
            linkroot = Path(base) / "linkroot"
            try:
                linkroot.symlink_to(Path(base) / "root", target_is_directory=True)
            except OSError as exc:
                self.skipTest("symlink unavailable: " + str(exc))
            with self.assertRaises(ValueError):
                self.read(str(linkroot / "a.txt"), 64, root=str(linkroot))


class QuiesceTests(unittest.TestCase):
    def test_absent_container_is_confirmed_gone(self):
        absent = b"Error: No such container: artex-afl-x"
        runner = FuzzRunner(run=FakeRun(stop=1, stop_stderr=absent,
                                       inspect=1, inspect_stderr=absent))
        self.assertTrue(runner._quiesce("artex-afl-x", FakeProc(0)))

    def test_daemon_unreachable_is_a_cleanup_failure(self):
        daemon = b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        runner = FuzzRunner(run=FakeRun(stop=1, stop_stderr=daemon,
                                       inspect=1, inspect_stderr=daemon))
        self.assertFalse(runner._quiesce("artex-afl-x", FakeProc(0)))

    def test_permission_error_is_a_cleanup_failure(self):
        denied = b"permission denied while trying to connect to the Docker daemon"
        runner = FuzzRunner(run=FakeRun(stop=1, stop_stderr=denied,
                                       inspect=1, inspect_stderr=denied))
        self.assertFalse(runner._quiesce("artex-afl-x", FakeProc(0)))

    def test_running_container_is_a_cleanup_failure(self):
        runner = FuzzRunner(run=FakeRun(stop=0, inspect=0,
                                       inspect_running=b"true"))
        self.assertFalse(runner._quiesce("artex-afl-x", FakeProc(0)))

    def test_local_cli_is_waited_before_absent_check(self):
        order = []

        class OrderedProc(FakeProc):
            def __init__(self):
                super().__init__(None)

            def terminate(self):
                order.append("terminate")
                super().terminate()

            def wait(self, timeout=None):
                order.append("wait")
                return super().wait(timeout)

        class OrderedRun(FakeRun):
            def __call__(self, args, **kwargs):
                order.append("run:" + args[1])
                return super().__call__(args, **kwargs)

        absent = b"Error: No such container: artex-afl-x"
        runner = FuzzRunner(run=OrderedRun(stop=1, stop_stderr=absent,
                                          inspect=1, inspect_stderr=absent))
        self.assertTrue(runner._quiesce("artex-afl-x", OrderedProc()))
        self.assertLess(order.index("wait"), order.index("run:stop"))
        self.assertLess(order.index("run:stop"), order.index("run:inspect"))

    def test_cleanup_absent_container_is_not_a_false_failure(self):
        absent = b"Error: No such container: artex-afl-x"
        runner = FuzzRunner(run=FakeRun(rm=1, rm_stderr=absent,
                                       inspect=1, inspect_stderr=absent))
        runner.names = ["artex-afl-x"]
        runner.staging = None
        result = runner.cleanup()
        self.assertTrue(result["container_removed"])

    def test_cleanup_daemon_error_is_not_swallowed(self):
        daemon = b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        runner = FuzzRunner(run=FakeRun(rm=1, rm_stderr=daemon,
                                       inspect=1, inspect_stderr=daemon))
        runner.names = ["artex-afl-x"]
        runner.staging = None
        result = runner.cleanup()
        self.assertFalse(result["container_removed"])


class CommandTests(unittest.TestCase):
    def test_command_is_isolated_and_has_no_output_bind_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FuzzRunner()
            runner.staging = directory
            spec = {"image": "sha256:" + "a" * 64}
            cmd = runner.command("owned-name", spec, "/usr/bin/afl-fuzz", ["-h"])
            for item in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--user=65534:65534",
                         "--cpus=1", "--memory=512m", "--pids-limit=128",
                         "--log-driver=none", "--init"):
                self.assertIn(item, cmd)
            self.assertIn("/work/out:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048,mode=1777", cmd)
            mounts = [cmd[i + 1] for i, item in enumerate(cmd) if item == "--mount"]
            self.assertEqual(len(mounts), 2)
            self.assertTrue(all("dst=/work/out" not in mount for mount in mounts))
            self.assertTrue(all("readonly" in mount for mount in mounts))
            self.assertEqual(cmd[cmd.index("--entrypoint") + 1], "/usr/bin/afl-fuzz")
            self.assertEqual(cmd[cmd.index("--name") + 1], "owned-name")
            self.assertNotIn("SECRET", " ".join(cmd))

    def test_docker_environment_does_not_inherit_secrets(self):
        with patch.dict(os.environ, {"SECRET_TOKEN": "nope", "PATH": "/bin"}, clear=True):
            env = docker_environment()
            self.assertNotIn("SECRET_TOKEN", env)
            self.assertEqual(env["PATH"], "/bin")

    def test_tool_checks_requires_supported_options_and_versions(self):
        runner = FuzzRunner()
        fuzz = ("afl-fuzz++4.04c\n-i dir\n-o dir\n-V seconds\n-E execs\n-G maxlength\n"
                "-m megs\n-t msec\n")
        show = "afl-showmap++4.04c\n-o file\n-q\n-m megs\n-t msec\n"
        responses = iter([(fuzz, 0, False), (show, 0, False)])
        runner._run_help = lambda *args: next(responses)
        result = runner.tool_checks({"image": "sha256:" + "a" * 64}, threading.Event(), 1)
        self.assertEqual(result["afl_version"], "4.04c")
        self.assertTrue(result["options_verified"])
        responses = iter([(fuzz.replace("-E execs", ""), 0, False), (show, 0, False)])
        runner._run_help = lambda *args: next(responses)
        with self.assertRaisesRegex(ValueError, "bounded-campaign"):
            runner.tool_checks({"image": "sha256:" + "a" * 64}, threading.Event(), 1)
        # A probe that returned no exit status without cancellation is a real
        # tool/process error, not a deadline timeout.
        runner._run_help = lambda *args: ("", None, False)
        with self.assertRaisesRegex(ValueError, "did not complete"):
            runner.tool_checks({"image": "sha256:" + "a" * 64}, threading.Event(), 1)

    def test_help_probe_checks_cancel_before_launch(self):
        runner = FuzzRunner(run=FakeRun())
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(FuzzCancelled):
            runner._run_help({"image": "sha256:" + "a" * 64}, "/usr/bin/afl-fuzz",
                             ["-h"], cancelled, time.monotonic() + 1)
        self.assertEqual(runner.names, [])

    def test_cleanup_verifies_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FuzzRunner(run=FakeRun(inspect=0, inspect_running=b"true"))
            runner.staging = directory
            runner.names = ["owned"]
            runner.processes = [FakeProc(0)]
            result = runner.cleanup()
            self.assertFalse(result["container_removed"])
            runner = FuzzRunner(run=FakeRun())
            runner.staging = directory + "-2"
            Path(runner.staging).mkdir()
            runner.processes = [FakeProc(None)]
            result = runner.cleanup()
            self.assertTrue(result["owned_process_terminated"])
            self.assertTrue(result["container_removed"])
            self.assertTrue(result["staging_removed"])


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact = write(self.root / "fixture.elf", elf64())
        self.request = request(artifact_path=str(self.artifact),
                               sha256=hashlib.sha256(elf64()).hexdigest())

    def tearDown(self):
        self.temp.cleanup()

    def test_completed_campaign_contract(self):
        result = RunnerHarness().campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "completed")
        self.assertEqual(result["engine"], "afl++")
        self.assertEqual(result["corpus"][0]["data_base64"], base64.b64encode(b"ZX").decode())
        self.assertEqual(result["crashes"][0]["data_base64"], base64.b64encode(b"ZZ").decode())
        self.assertEqual(result["stats"]["execs_done"], 17)
        self.assertFalse(result["stats_trusted"])
        self.assertFalse(result["coverage_claimed"])
        self.assertEqual(result["candidate_status"], "unverified_requires_replay")
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(result["manifest"]["probe_edges"], 3)
        self.assertEqual(result["manifest"]["probe_executions"], 1)
        self.assertTrue(result["manifest"]["options_verified"])
        self.assertEqual(result["manifest"]["output_disk_limit_bytes"], MAX_OUTPUT_DISK)
        self.assertEqual(set(result), {"engine", "target_state", "manifest", "stats",
                                       "corpus", "crashes", "cleanup", "errors",
                                       "stats_trusted", "coverage_claimed",
                                       "candidate_status", "truncated", "limited",
                                       "reason", "cleanup_verified"})

    def test_uninstrumented_or_missing_output_fails_and_cleans(self):
        result = RunnerHarness(probe_error=True).campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "failed")
        self.assertTrue(result["errors"])
        self.assertTrue(result["cleanup_verified"])
        result = RunnerHarness(output=False).campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "failed")
        self.assertIn("no campaign corpus", " ".join(result["errors"]))

    def test_cancel_and_timeout_are_reported_with_cleanup(self):
        cancelled = threading.Event()
        cancelled.set()
        result = RunnerHarness().campaign(self.request, cancelled)
        self.assertEqual(result["target_state"], "cancelled")
        self.assertTrue(result["cleanup_verified"])
        result = RunnerHarness(state="timeout").campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "timeout")
        self.assertEqual(result["reason"], "budget_exhausted")
        self.assertTrue(result["cleanup_verified"])

    def test_cancel_between_help_probes_is_cancelled(self):
        fuzz_help = ("afl-fuzz++4.04c\n-i dir\n-o dir\n-V seconds\n-E execs\n"
                     "-G maxlength\n-m megs\n-t msec\n")

        class CancelBetweenHelpProbes(RunnerHarness):
            tool_checks = FuzzRunner.tool_checks

            def __init__(self, cancel):
                super().__init__()
                self.cancel = cancel
                self.calls = 0

            def _run_help(self, spec, entrypoint, args, cancelled, deadline):
                self.calls += 1
                if self.calls == 1:
                    # Owner cancellation arrives after the first fixed help
                    # probe; the second probe must not turn that into failure.
                    self.cancel.set()
                    return fuzz_help, 0, False
                return FuzzRunner._run_help(self, spec, entrypoint, args,
                                            cancelled, deadline)

        cancelled = threading.Event()
        runner = CancelBetweenHelpProbes(cancelled)
        result = runner.campaign(self.request, cancelled)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(result["target_state"], "cancelled", result["errors"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["reason"], "cancelled")
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(runner.calls, 2)

    def test_cancel_during_help_probe_is_prompt_and_cancelled(self):
        class CancelDuringHelpProbe(RunnerHarness):
            tool_checks = FuzzRunner.tool_checks

            def start(self, command, stdin):
                process = FakeProc(None)
                self.processes.append(process)
                return process

        cancelled = threading.Event()

        def stop():
            time.sleep(0.1)
            cancelled.set()

        threading.Thread(target=stop, daemon=True).start()
        runner = CancelDuringHelpProbe()
        started = time.monotonic()
        result = runner.campaign(self.request, cancelled)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0, "cancellation was not prompt")
        self.assertEqual(result["target_state"], "cancelled", result["errors"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["reason"], "cancelled")
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(runner.processes[0].returncode, -15)

    def test_budget_timeout_during_tool_check_is_timeout_not_failure(self):
        class TimeoutRunner(RunnerHarness):
            def tool_checks(self, spec, cancelled, deadline):
                raise FuzzBudgetTimeout("out of budget")

        result = TimeoutRunner().campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "timeout")
        self.assertEqual(result["reason"], "budget_exhausted")
        self.assertTrue(result["cleanup_verified"])

    def test_cleanup_failure_overrides_success(self):
        result = RunnerHarness(cleanup_ok=False).campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "failed")
        self.assertIn("cleanup_unverified", result["errors"])

    def test_response_cap(self):
        with patch("scripts.native_runner.fuzz.MAX_RESPONSE", 1):
            result = RunnerHarness().campaign(self.request, threading.Event())
        self.assertEqual(result["target_state"], "failed")
        self.assertIn("response_limit", result["errors"])

    def test_serve_fuzz_cancel_eof_and_exit_codes(self):
        class WaitingRunner:
            def __init__(self):
                self.seen = None

            def campaign(self, first, cancelled):
                self.seen = cancelled.wait(0.5)
                return {"target_state": "cancelled", "cleanup_verified": True,
                        "cleanup": {"owned_process_terminated": True,
                                    "container_removed": True, "staging_removed": True}}

        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with os.fdopen(read_fd, "rb", buffering=0) as inp:
            frames = []
            runner = WaitingRunner()
            rc = serve_fuzz({"operation": "fuzz"}, inp, frames.append, runner=runner)
        self.assertEqual(rc, 0)
        self.assertTrue(runner.seen)
        self.assertEqual(frames[-1]["kind"], "final")
        self.assertEqual(frames[-1]["observation"]["target_state"], "cancelled")

        class FailedRunner(WaitingRunner):
            def campaign(self, first, cancelled):
                return {"target_state": "failed", "cleanup_verified": True,
                        "cleanup": {"owned_process_terminated": True,
                                    "container_removed": True, "staging_removed": True}}

        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with os.fdopen(read_fd, "rb", buffering=0) as inp:
            rc = serve_fuzz({"operation": "fuzz"}, inp, lambda frame: None,
                            runner=FailedRunner())
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
