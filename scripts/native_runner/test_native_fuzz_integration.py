"""Opt-in real closed-loop test against the local signed AFL++ image.

Run only with an explicitly selected local image:
  ARTEX_FUZZ_REAL_DOCKER=1 \
  ARTEX_FUZZ_REAL_IMAGE=artex-afl:bookworm-4.04c-review \
  python -B -m unittest scripts.native_runner.test_native_fuzz_integration -v

The only compiled program is testdata/reverse/native/fuzz_fixture.c. No network,
download, model call, product target, or exploit chain is involved.
"""
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from .fuzz import FuzzRunner
from .main import serve

ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("ARTEX_FUZZ_REAL_IMAGE", "")
SOURCE = ROOT / "testdata" / "reverse" / "native" / "fuzz_fixture.c"


def run(args, timeout=120):
    return subprocess.run(args, capture_output=True, timeout=timeout,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin"})


CAMPAIGN_NAME = re.compile(r"^artex-afl-[0-9a-f]{16}$")


def campaign_running(names):
    """Return (True, name, source) only when AFL itself is executing.

    The supervisor's own argv also contains /usr/bin/afl-fuzz, so a plain
    substring match is not enough. Prefer fuzzer_stats with execs_done >= 1,
    and only accept docker-top rows whose command starts with afl-fuzz.
    """
    for name in list(names):
        if not CAMPAIGN_NAME.match(name):
            continue
        stats = run(["docker", "exec", name, "cat",
                     "/work/out/findings/default/fuzzer_stats"], 5)
        match = re.search(rb"execs_done\s*:\s*([0-9]+)", stats.stdout)
        if stats.returncode == 0 and match and int(match.group(1)) >= 1:
            return True, name, "fuzzer_stats execs_done=" + match.group(1).decode()
        top = run(["docker", "top", name, "-eo", "pid,args"], 5)
        if top.returncode == 0:
            for line in top.stdout.decode("utf-8", "replace").splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[1].startswith("/usr/bin/afl-fuzz"):
                    return True, name, "docker top afl-fuzz"
    return False, None, ""


def image_id(image):
    result = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], 30)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-2000:])
    value = result.stdout.decode().strip()
    if not value.startswith("sha256:"):
        raise RuntimeError("local image did not resolve to a digest")
    return value


def compile_fixture(image, destination, compiler):
    directory = destination.parent
    args = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit=128",
            "--memory=512m", "--cpus=1",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048",
            "--mount", f"type=bind,src={SOURCE},dst=/input/fixture.c,readonly",
            "--mount", f"type=bind,src={directory},dst=/output",
            "--entrypoint", compiler, image,
            "-O0", "-g", "-fno-pie", "-no-pie", "/input/fixture.c",
            "-o", "/output/" + destination.name]
    result = run(args)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-3000:])
    if not destination.is_file():
        raise RuntimeError("compiler produced no fixture")
    return destination


def data_seed(data):
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii")}


@unittest.skipUnless(os.environ.get("ARTEX_FUZZ_REAL_DOCKER") == "1",
                     "set ARTEX_FUZZ_REAL_DOCKER=1 and ARTEX_FUZZ_REAL_IMAGE")
class RealAFLClosedLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not IMAGE:
            raise unittest.SkipTest("ARTEX_FUZZ_REAL_IMAGE is required")
        if shutil.which("docker") is None:
            raise unittest.SkipTest("docker CLI is unavailable")
        cls.image = image_id(IMAGE)
        cls.temp = tempfile.TemporaryDirectory(prefix="artex-fuzz-real-")
        cls.root = Path(cls.temp.name)
        cls.instrumented = compile_fixture(cls.image, cls.root / "fuzz_fixture.afl.elf",
                                           "/usr/bin/afl-clang-fast")
        cls.plain = compile_fixture(cls.image, cls.root / "fuzz_fixture.plain.elf",
                                    "/usr/bin/gcc")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def profile(self):
        return {"image": self.image, "fuzz_enabled": True, "enabled": True,
                "platform": "linux", "network": "none", "read_only_root": True,
                "max_duration_ms": 60000}

    def request(self, artifact, *, duration=10000, max_executions=2000,
                max_crashes=2, seeds=None):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        return {"operation": "fuzz", "request_id": "real-fuzz",
                "artifact_path": str(artifact), "sha256": digest, "argv": [],
                "input_mode": "stdin", "profile": self.profile(),
                "duration_ms": duration,
                "seeds": seeds or [data_seed(b"ZX")],
                "max_executions": max_executions, "max_crashes": max_crashes}

    def assert_no_owned_containers(self, names):
        for name in names:
            result = run(["docker", "inspect", name], 10)
            self.assertNotEqual(result.returncode, 0, "owned container still exists: " + name)

    def test_real_campaign_crash_and_independent_replay(self):
        req = self.request(self.instrumented)
        runner = FuzzRunner()
        result = runner.campaign(req, threading.Event())
        self.assertEqual(result["target_state"], "completed", result["errors"])
        self.assertTrue(result["cleanup_verified"], result["cleanup"])
        self.assertGreaterEqual(result["manifest"]["probe_edges"], 1)
        self.assertTrue(result["manifest"]["options_verified"])
        self.assertGreaterEqual(len(result["corpus"]), 1)
        self.assertGreaterEqual(len(result["crashes"]), 1, result)
        self.assertFalse(result["stats_trusted"])
        self.assertFalse(result["coverage_claimed"])
        self.assert_no_owned_containers(runner.names)

        candidate = result["crashes"][0]
        replay = {"operation": "replay", "request_id": "real-replay",
                  "artifact_path": str(self.instrumented),
                  "sha256": hashlib.sha256(self.instrumented.read_bytes()).hexdigest(),
                  "argv": [], "input_mode": "stdin", "mode": "exec",
                  "input_base64": candidate["data_base64"],
                  "expected_signal": 6, "duration_ms": 10000,
                  "profile": self.profile()}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(replay) + "\n"), out)
        frames = [json.loads(line) for line in out.getvalue().splitlines()]
        observation = frames[-1]["observation"]
        self.assertEqual(rc, 0, observation)
        self.assertEqual(observation["target_state"], "crashed")
        self.assertEqual(observation["signal"], 6)
        self.assertTrue(observation["matches_expectation"])
        self.assertTrue(observation["cleanup_verified"])

    def test_real_file_mode_campaign_and_replay(self):
        req = self.request(self.instrumented, duration=8000, max_executions=2000)
        req["input_mode"] = "file"
        req["argv"] = ["{input}"]
        runner = FuzzRunner()
        result = runner.campaign(req, threading.Event())
        self.assertEqual(result["target_state"], "completed", result["errors"])
        self.assertTrue(result["cleanup_verified"])
        self.assertGreaterEqual(len(result["crashes"]), 1, result)
        candidate = result["crashes"][0]
        replay = {"operation": "replay", "request_id": "real-file-replay",
                  "artifact_path": str(self.instrumented),
                  "sha256": hashlib.sha256(self.instrumented.read_bytes()).hexdigest(),
                  "argv": ["{input}"], "input_mode": "file", "mode": "exec",
                  "input_base64": candidate["data_base64"],
                  "expected_signal": 6, "duration_ms": 10000,
                  "profile": self.profile()}
        out = io.StringIO()
        rc = serve(io.StringIO(json.dumps(replay) + "\n"), out)
        observation = json.loads(out.getvalue().splitlines()[-1])["observation"]
        self.assertEqual(rc, 0, observation)
        self.assertEqual(observation["target_state"], "crashed")
        self.assertTrue(observation["matches_expectation"])
        self.assertTrue(observation["cleanup_verified"])

    def test_uninstrumented_fixture_is_rejected_and_cleaned(self):
        runner = FuzzRunner()
        result = runner.campaign(self.request(self.plain, duration=6000, max_executions=100), threading.Event())
        self.assertEqual(result["target_state"], "failed")
        self.assertTrue(result["cleanup_verified"])
        self.assertIn("instrumentation", " ".join(result["errors"]).lower())
        self.assert_no_owned_containers(runner.names)

    def test_real_startup_cancellation_cleans_up(self):
        runner = FuzzRunner()
        cancelled = threading.Event()

        def stop():
            # Startup/help-probe phase cancellation. This deliberately does not
            # claim that afl-fuzz was already running.
            time.sleep(2.0)
            cancelled.set()

        threading.Thread(target=stop, daemon=True).start()
        started = time.monotonic()
        result = runner.campaign(self.request(self.instrumented, duration=10000, max_executions=100000),
                                 cancelled)
        elapsed = time.monotonic() - started
        self.assertTrue(cancelled.is_set())
        self.assertEqual(result["target_state"], "cancelled", result["errors"])
        self.assertEqual(result["reason"], "cancelled")
        self.assertLess(elapsed, 8.0, "cancellation waited for the campaign budget")
        self.assertTrue(result["cleanup_verified"])
        self.assert_no_owned_containers(runner.names)

    def test_real_running_campaign_cancellation_cleans_up(self):
        runner = FuzzRunner()
        cancelled = threading.Event()
        observed = threading.Event()
        cancel_at = []

        def watch():
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline and not cancelled.is_set():
                running, name, source = campaign_running(runner.names)
                if running:
                    print(f"observed running campaign {name}: {source}", flush=True)
                    cancel_at.append(time.monotonic())
                    observed.set()
                    cancelled.set()
                    return
                time.sleep(0.05)

        threading.Thread(target=watch, daemon=True).start()
        result = runner.campaign(
            self.request(self.instrumented, duration=10000, max_executions=200000),
            cancelled)
        self.assertTrue(observed.is_set(),
                        "never observed afl-fuzz running in the campaign")
        self.assertEqual(result["target_state"], "cancelled", result["errors"])
        self.assertEqual(result["reason"], "cancelled")
        cancel_to_result = time.monotonic() - cancel_at[0]
        print(f"cancel_to_result={cancel_to_result:.3f}s", flush=True)
        self.assertLess(cancel_to_result, 6.0,
                        "cancellation was not prompt after observing afl-fuzz")
        self.assertTrue(result["cleanup_verified"])
        self.assert_no_owned_containers(runner.names)


if __name__ == "__main__":
    unittest.main()
