"""Bounded, single-worker AFL++ campaigns.

Only a synthetic or explicitly authorized local ELF is executed.  The campaign
output is a candidate list: AFL statistics and crash files are untrusted until
an independent native replay binds them to an immutable NativeCase.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .elf import inspect_elf
from .process import ByteReader, OutputBudget
from .protocol import read_frame
from .sandbox import DockerSandbox, docker_environment

MAX_ARTIFACT = 64 * 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
MAX_CANDIDATE = 4096
MAX_CORPUS = 32
MAX_CORPUS_BYTES = 65536
MAX_ARGV = 64
MAX_HELP_OUTPUT = 64 * 1024
MAX_PROBE_MAP = 1024 * 1024
MAX_OUTPUT_FILES = 2048
MAX_OUTPUT_FILE = 1024 * 1024
MAX_OUTPUT_DISK = 64 * 1024 * 1024
MAX_SUPERVISOR_OUTPUT = 2 * 1024 * 1024
CLEANUP_RESERVE_SECONDS = 0.35
AFL_FUZZ = "/usr/bin/afl-fuzz"
AFL_SHOWMAP = "/usr/bin/afl-showmap"

# Fixed in-container supervisor. It is the only process that reads the tmpfs
# output tree, and it streams back only bounded, selected evidence. The target
# receives no writable host bind mount.
SUPERVISOR_LIB = r'''
import base64, json, os, stat, subprocess, sys
MAX_FILE = 4096
MAX_CORPUS = 32
MAX_CORPUS_BYTES = 65536
MAX_STATS = 65536
MAX_MAP = 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
OUT_ROOT = "/work/out"

def linked(path):
    st = os.lstat(path)
    return stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & 0x400)

def _relative_parts(path, root):
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        raise ValueError("path outside output root")
    if rel in ("", ".", "..") or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        raise ValueError("path outside output root")
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise ValueError("path outside output root")
    return parts

def _open_root(root):
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                       getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("unsafe output root") from exc

def _read_regular_at(root_fd, parts, limit):
    # Walk from an already-open trusted root fd. Every component is opened
    # relative to its parent with O_DIRECTORY|O_NOFOLLOW, and the final regular
    # file is opened relative to the last directory and verified with fstat.
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            except OSError as exc:
                raise ValueError("unsafe output directory") from exc
            os.close(fd)
            fd = child
        try:
            file_fd = os.open(parts[-1], os.O_RDONLY |
                              getattr(os, "O_NOFOLLOW", 0) |
                              getattr(os, "O_NONBLOCK", 0), dir_fd=fd)
        except OSError as exc:
            raise ValueError("unsafe output file") from exc
        try:
            actual = os.fstat(file_fd)
            if not stat.S_ISREG(actual.st_mode) or actual.st_size > limit:
                raise ValueError("unsafe output file")
            data = os.read(file_fd, limit + 1)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError("oversized output file")
    return data

def read_regular(path, limit, root=OUT_ROOT):
    parts = _relative_parts(path, root)
    root_fd = _open_root(root)
    try:
        return _read_regular_at(root_fd, parts, limit)
    finally:
        os.close(root_fd)

def safe_dir(path, root=OUT_ROOT):
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        raise ValueError("output directory outside root")
    if rel == ".." or rel.startswith(".." + os.sep):
        raise ValueError("output directory outside root")
    current = root
    for part in [""] + [p for p in rel.split(os.sep) if p not in ("", ".")]:
        current = os.path.join(current, part) if part else root
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise ValueError("missing directory: " + str(exc))
        if linked(current) or not stat.S_ISDIR(st.st_mode):
            raise ValueError("unsafe output directory component")

def collect(path, count, total, crashes=False, root=OUT_ROOT):
    if not os.path.exists(path):
        return [], False, 0
    safe_dir(path, root)
    items, seen, used, truncated = [], set(), 0, False
    names = sorted(entry.name for entry in os.scandir(path))
    for name in names:
        child = os.path.join(path, name)
        st = os.lstat(child)
        if linked(child):
            raise ValueError("linked candidate output entry")
        if stat.S_ISDIR(st.st_mode):
            continue
        if name == "README.txt":
            continue
        if not (name.startswith("id:") or name.startswith("id_")):
            raise ValueError("unexpected candidate output entry")
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("special candidate output entry")
        if st.st_size > MAX_FILE:
            truncated = True
            continue
        if len(items) >= count or used + st.st_size > total:
            truncated = True
            continue
        data = read_regular(child, MAX_FILE, root=root)
        digest = __import__("hashlib").sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        used += len(data)
        items.append({"name": name, "sha256": digest,
                      "data_base64": base64.b64encode(data).decode("ascii")})
    return items, truncated, used

def showmap(command, root=OUT_ROOT):
    rc = subprocess.call(command, stdin=sys.stdin.buffer,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    path = os.path.join(root, "probe.map")
    if not os.path.exists(path):
        return {"exit": rc, "probe_map_base64": None}
    data = read_regular(path, MAX_MAP, root=root)
    return {"exit": rc,
            "probe_map_base64": base64.b64encode(data).decode("ascii")}

def fuzz(command, max_crashes, root=OUT_ROOT):
    rc = subprocess.call(command, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = os.path.join(root, "findings", "default")
    result = {"exit": rc, "findings": False, "queue": [], "crashes": [],
              "stats_base64": None, "truncated": False}
    if not os.path.exists(base):
        return result
    safe_dir(base, root)
    safe_dir(os.path.join(base, "queue"), root)
    safe_dir(os.path.join(base, "crashes"), root)
    result["findings"] = True
    result["queue"], qcut, _ = collect(os.path.join(base, "queue"),
                                       MAX_CORPUS, MAX_CORPUS_BYTES, root=root)
    result["crashes"], ccut, _ = collect(os.path.join(base, "crashes"),
                                         max_crashes, max_crashes * MAX_FILE,
                                         crashes=True, root=root)
    result["truncated"] = bool(qcut or ccut)
    stats = os.path.join(base, "fuzzer_stats")
    if os.path.exists(stats):
        result["stats_base64"] = base64.b64encode(
            read_regular(stats, MAX_STATS, root=root)).decode("ascii")
    return result
'''

SUPERVISOR_MAIN = r'''
try:
    mode = sys.argv[1]
    max_crashes = int(sys.argv[2])
    command = sys.argv[3:]
    result = showmap(command) if mode == "showmap" else fuzz(command, max_crashes)
    raw = json.dumps(result, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_JSON:
        raise ValueError("supervisor response too large")
    sys.stdout.write(raw)
    sys.stdout.flush()
except Exception as exc:
    try:
        sys.stdout.write(json.dumps({"error": str(exc)[:512]}, separators=(",", ":")))
        sys.stdout.flush()
    except Exception:
        pass
    sys.exit(2)
'''
SUPERVISOR = SUPERVISOR_LIB + SUPERVISOR_MAIN
FIELDS = {"operation", "request_id", "artifact_path", "sha256", "argv", "input_mode",
          "profile", "duration_ms", "seeds", "max_executions", "max_crashes"}
PROFILE_FIELDS = {"id", "name", "engine", "platform", "command", "args", "settings"}
SETTINGS_FIELDS = {"image", "fuzz_enabled", "enabled", "max_duration_ms", "platform",
                   "network", "read_only_root", "seccomp_profile", "max_stream_bytes",
                   "max_io_bytes", "name"}
FORBIDDEN_SETTINGS = {"command", "flags", "afl_flags", "afl_path", "showmap_path",
                      "qemu", "remote", "host", "target", "environment", "env",
                      "secrets", "secret", "docker_host", "socket"}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TOOL_RE = re.compile(r"afl-(?:fuzz|showmap)\+\+([0-9][A-Za-z0-9._-]*)")
NO_SUCH_CONTAINER = re.compile(r"no such (?:container|object)", re.I)


def _result_text(result):
    pieces = []
    for name in ("stdout", "stderr"):
        value = getattr(result, name, b"")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if value:
            pieces.append(str(value))
    return "\n".join(pieces).strip()


def _container_absent(result):
    # A successful command never means "absent"; explicit no-such errors on a
    # failed stop/rm/inspect do.
    return (getattr(result, "returncode", 0) != 0
            and bool(NO_SUCH_CONTAINER.search(_result_text(result))))


class FuzzBudgetTimeout(Exception):
    pass


class FuzzCancelled(Exception):
    pass


def integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(label + " is outside allowed bounds")
    return value


def _is_link(st):
    return bool(stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & 0x400))


def regular_bytes(path, maximum):
    """Reject links/reparse points and verify the opened object, never follow them."""
    path = Path(path)
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise ValueError("non-regular output/input file rejected")
    if before.st_size > maximum:
        raise ValueError("file exceeds byte limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        actual = os.fstat(fd)
        if (_is_link(actual) or not stat.S_ISREG(actual.st_mode)
                or actual.st_size > maximum
                or (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino)):
            raise ValueError("file changed during open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("file exceeds byte limit")
        return data
    finally:
        os.close(fd)


def safe_directory(path):
    path = Path(path)
    st = path.lstat()
    if _is_link(st) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("non-directory or linked output directory rejected")
    return path


def remove_staging(path):
    """Remove a runner-owned tree, including read-only files on Windows."""
    path = Path(path)

    def retry(function, target, _error):
        try:
            os.chmod(target, 0o700)
        except OSError:
            pass
        try:
            function(target)
        except OSError:
            pass

    try:
        shutil.rmtree(path, onexc=retry)
    except TypeError:
        shutil.rmtree(path, onerror=retry)
    except OSError:
        pass
    return not path.exists() and not path.is_symlink()


def _profile_settings(profile):
    if not isinstance(profile, dict):
        raise ValueError("profile is required")
    if "settings" in profile:
        if set(profile) - PROFILE_FIELDS:
            raise ValueError("unsupported fuzz profile field")
        if profile.get("engine") not in (None, "docker-native"):
            raise ValueError("fuzz profile engine must be docker-native")
        if profile.get("platform") not in (None, "linux"):
            raise ValueError("fuzz profile must be linux")
        settings = profile["settings"]
    else:
        settings = profile
    if not isinstance(settings, dict):
        raise ValueError("profile settings must be an object")
    if set(settings) - SETTINGS_FIELDS or set(settings) & FORBIDDEN_SETTINGS:
        raise ValueError("unsupported fuzz profile setting")
    if settings.get("fuzz_enabled") is not True:
        raise ValueError("profile.settings.fuzz_enabled must be true")
    if settings.get("enabled") is False or profile.get("enabled") is False:
        raise ValueError("profile is disabled")
    if settings.get("platform") not in (None, "linux"):
        raise ValueError("fuzz profile must be linux")
    if settings.get("network") not in (None, "none"):
        raise ValueError("fuzz profile cannot request a network")
    if settings.get("read_only_root") not in (None, True):
        raise ValueError("fuzz profile root must be read-only")
    return settings


def validate(first):
    if not isinstance(first, dict) or set(first) - FIELDS:
        raise ValueError("unsupported fuzz request field")
    if first.get("operation") != "fuzz":
        raise ValueError("expected fuzz operation")
    rid = first.get("request_id", "fuzz")
    if not isinstance(rid, str) or not 1 <= len(rid) <= 128:
        raise ValueError("request_id is invalid")
    profile = first.get("profile")
    settings = _profile_settings(profile)
    image = settings.get("image")
    DockerSandbox._check_digest_image(image)
    digest = image.rsplit("sha256:", 1)[1]
    if not re.fullmatch("[0-9a-f]{64}", digest):
        raise ValueError("profile.image digest must be lowercase SHA-256")
    duration = integer(first.get("duration_ms"), 1000, 60000, "duration_ms")
    maximum = settings.get("max_duration_ms", 60000)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1000:
        raise ValueError("profile max_duration_ms is invalid")
    if duration > min(maximum, 60000):
        raise ValueError("duration exceeds profile limit")
    executions = integer(first.get("max_executions"), 100, 1000000, "max_executions")
    crashes = integer(first.get("max_crashes"), 1, 8, "max_crashes")
    mode = first.get("input_mode")
    if mode not in ("stdin", "file"):
        raise ValueError("input_mode must be stdin or file")
    argv = first.get("argv", [])
    if not isinstance(argv, list) or len(argv) > MAX_ARGV:
        raise ValueError("argv must have at most 64 elements")
    for arg in argv:
        if not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg:
            raise ValueError("invalid target argv")
        if "@@" in arg:
            raise ValueError("target argv may not contain @@")
        if "{input}" in arg and arg != "{input}":
            raise ValueError("input placeholder must be a whole argument")
    if (mode == "file" and argv.count("{input}") != 1) or (mode == "stdin" and "{input}" in argv):
        raise ValueError("file mode requires exactly one whole input placeholder")
    seeds = first.get("seeds")
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= 32:
        raise ValueError("seeds must have 1..32 entries")
    decoded = []
    total = 0
    for seed in seeds:
        if not isinstance(seed, dict) or set(seed) != {"sha256", "data_base64"}:
            raise ValueError("invalid seed fields")
        encoded = seed["data_base64"]
        if not isinstance(encoded, str) or len(encoded) > 5464:
            raise ValueError("seed exceeds byte limit")
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError("seed is not canonical base64") from exc
        if base64.b64encode(data).decode("ascii") != encoded:
            raise ValueError("seed is not canonical base64")
        digest = hashlib.sha256(data).hexdigest()
        if not 1 <= len(data) <= MAX_CANDIDATE or seed["sha256"] != digest:
            raise ValueError("seed hash or size is invalid")
        total += len(data)
        if total > MAX_CORPUS_BYTES:
            raise ValueError("seed total exceeds 65536 bytes")
        decoded.append((digest, data))
    artifact = first.get("artifact_path")
    if (not isinstance(artifact, str) or not artifact or len(artifact) > 4096
            or any(c in artifact for c in "\x00,\n\r")):
        raise ValueError("invalid artifact_path")
    expected = first.get("sha256")
    if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
        raise ValueError("invalid artifact sha256")
    return {"request_id": rid, "image": image, "duration_ms": duration,
            "max_executions": executions, "max_crashes": crashes, "input_mode": mode,
            "argv": list(argv), "seeds": decoded, "artifact_path": artifact,
            "sha256": expected}


def scan_output_tree(root):
    """Stat every retrieved file without following links; enforce hard disk bounds."""
    root = safe_directory(root)
    files, stack = {}, [(root, 0, ())]
    total, count = 0, 0
    while stack:
        directory, depth, relative = stack.pop()
        if depth > 6:
            raise ValueError("output tree is too deep")
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                if count > MAX_OUTPUT_FILES:
                    raise ValueError("output tree exceeds file count limit")
                info = entry.stat(follow_symlinks=False)
                if _is_link(info):
                    raise ValueError("linked output entry rejected")
                child = relative + (entry.name,)
                if stat.S_ISDIR(info.st_mode):
                    stack.append((Path(entry.path), depth + 1, child))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_size > MAX_OUTPUT_FILE:
                        raise ValueError("output file exceeds per-file limit")
                    total += info.st_size
                    if total > MAX_OUTPUT_DISK:
                        raise ValueError("output tree exceeds disk limit")
                    files[child] = info.st_size
                else:
                    raise ValueError("special output entry rejected")
    return files


def collect_tree_candidates(root, relative, count_limit, total_limit):
    files = scan_output_tree(root)
    prefix = tuple(relative)
    names = sorted({path[-1] for path in files if path[:-1] == prefix})
    result, seen, total, truncated = [], set(), 0, False
    for name in names:
        if name == "README.txt":
            continue
        if not name.startswith("id:") and not name.startswith("id_"):
            raise ValueError("unexpected candidate output entry")
        path_parts = prefix + (name,)
        size = files[path_parts]
        if size > MAX_CANDIDATE:
            truncated = True
            continue
        if len(result) >= count_limit or total + size > total_limit:
            truncated = True
            continue
        data = regular_bytes(Path(root).joinpath(*path_parts), MAX_CANDIDATE)
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        total += len(data)
        result.append({"sha256": digest,
                       "data_base64": base64.b64encode(data).decode("ascii")})
    return result, truncated


def parse_stats(raw):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > 65536:
        raise ValueError("fuzzer stats exceed byte limit")
    allowed = {"execs_done", "saved_crashes", "saved_hangs", "corpus_count",
               "edges_found", "total_edges"}
    stats = {}
    for line in bytes(raw).decode("ascii", "replace").splitlines()[:512]:
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if sep and key in allowed and re.fullmatch(r"[0-9]{1,15}", value):
            stats[key] = int(value)
    return stats


def read_stats(path):
    return parse_stats(regular_bytes(path, 65536))


def coverage_edges_data(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PROBE_MAP:
        raise ValueError("no bounded coverage probe evidence")
    lines = bytes(data).splitlines()
    if not lines or len(lines) > 65536:
        raise ValueError("no bounded coverage probe evidence")
    for line in lines:
        if not re.fullmatch(rb"[0-9]{1,10}:[0-9]{1,3}", line):
            raise ValueError("malformed coverage probe output")
        if not 1 <= int(line.split(b":")[1]) <= 255:
            raise ValueError("coverage probe has zero or invalid counts")
    return len(lines)


def coverage_edges(path):
    return coverage_edges_data(regular_bytes(path, MAX_PROBE_MAP))


def supervisor_payload(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_SUPERVISOR_OUTPUT:
        raise ValueError("fuzz supervisor response exceeds limit")
    try:
        payload = json.loads(text)
    except Exception as exc:
        raise ValueError("fuzz supervisor returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("fuzz supervisor response must be an object")
    if payload.get("error"):
        raise ValueError(str(payload["error"])[:512])
    return payload


def decode_candidate(item, maximum=MAX_CANDIDATE):
    if not isinstance(item, dict) or set(item) != {"name", "sha256", "data_base64"}:
        raise ValueError("invalid supervisor candidate")
    name = item["name"]
    if not isinstance(name, str) or not (name.startswith("id:") or name.startswith("id_")):
        raise ValueError("invalid supervisor candidate name")
    encoded = item["data_base64"]
    if not isinstance(encoded, str) or len(encoded) > 5464:
        raise ValueError("supervisor candidate exceeds byte limit")
    try:
        data = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("supervisor candidate is not canonical base64") from exc
    if base64.b64encode(data).decode("ascii") != encoded:
        raise ValueError("supervisor candidate is not canonical base64")
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("supervisor candidate hash or size mismatch")
    return data


class FuzzRunner:
    def __init__(self, docker="docker", popen=subprocess.Popen, run=subprocess.run,
                 clock=time.monotonic):
        self.docker, self.popen, self.run, self.clock = docker, popen, run, clock
        self.names, self.processes, self.staging = [], [], None
        self.log_budget = OutputBudget(MAX_LOG)
        self.readers, self.reader_pairs = [], {}
        self.commands = []

    def command(self, name, spec, entrypoint, args):
        root = Path(self.staging)
        return [self.docker, "run", "--init", "--pull=never", "-i", "--name", name,
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--user=65534:65534",
                "--cpus=1", "--memory=512m", "--pids-limit=128",
                "--ulimit", "core=0", "--ulimit", "nofile=256:256",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048",
                "--tmpfs", ("/work/out:rw,nosuid,nodev,noexec,size=64m,"
                            "nr_inodes=2048,mode=1777"),
                "--mount", f"type=bind,src={root / 'sample'},dst=/work/sample,readonly",
                "--mount", f"type=bind,src={root / 'seeds'},dst=/work/seeds,readonly",
                "--workdir=/work", "--log-driver=none",
                "--env", "AFL_NO_UI=1", "--env", "AFL_SKIP_CPUFREQ=1",
                "--env", "AFL_NO_AFFINITY=1", "--env", "AFL_QUIET=1",
                "--env", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
                "--entrypoint", entrypoint, spec["image"], *args]

    def start(self, command, stdin):
        process = self.popen(command, stdin=stdin, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0,
                             env=docker_environment())
        self.processes.append(process)
        pair = (ByteReader(process.stdout, budget=self.log_budget),
                ByteReader(process.stderr, budget=self.log_budget))
        self.readers.extend(pair)
        self.reader_pairs[id(process)] = pair
        return process

    def supervised_command(self, name, spec, mode, max_crashes, entrypoint, args):
        return self.command(name, spec, "/usr/bin/python3",
                            ["-c", SUPERVISOR, mode, str(max_crashes),
                             entrypoint, *args])

    def drain_output(self, process, maximum=MAX_SUPERVISOR_OUTPUT):
        readers = self.reader_pairs.get(id(process), ())
        chunks = []
        total = 0
        end = self.clock() + 1.5
        while self.clock() < end:
            waiting = False
            for reader in readers:
                data, eof = reader.recv(65536, 0.02)
                if data and total < maximum:
                    take = min(len(data), maximum - total)
                    chunks.append(data[:take])
                    total += take
                if not eof:
                    waiting = True
            if not waiting:
                break
        return b"".join(chunks).decode("utf-8", "replace")

    def _read_process(self, process, deadline, cancelled):
        chunks = []
        total = 0
        readers = self.reader_pairs.get(id(process), ())
        status = "exited"
        while True:
            # Cancellation wins over every other condition and must stop the
            # owned process without waiting for the campaign/probe deadline.
            if cancelled is not None and cancelled.is_set():
                status = "cancelled"
                break
            for reader in readers:
                data, _ = reader.recv(4096, 0.01)
                if data and total < MAX_HELP_OUTPUT:
                    take = min(len(data), MAX_HELP_OUTPUT - total)
                    chunks.append(data[:take])
                    total += take
            if process.poll() is not None:
                break
            if self.clock() >= deadline:
                status = "timeout"
                break
            if self.log_budget.truncated:
                status = "limited"
                break
            time.sleep(0.01)
        if status != "exited":
            try:
                process.terminate()
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=0.5)
        settle = self.clock() + 0.2
        while self.clock() < settle:
            pending = False
            for reader in readers:
                data, eof = reader.recv(4096, 0.01)
                if data:
                    pending = True
                    if total < MAX_HELP_OUTPUT:
                        take = min(len(data), MAX_HELP_OUTPUT - total)
                        chunks.append(data[:take])
                        total += take
                pending = pending or not eof
            if not pending:
                break
        text = b"".join(chunks).decode("utf-8", "replace")
        return ANSI.sub("", text), process.poll(), status

    def _quiesce(self, name, process):
        try:
            # The local docker CLI is the only process that can still create the
            # container. Wait for it to exit before deciding that the owned
            # container was never created (or is already gone).
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.75)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=0.75)
            stop = self.run([self.docker, "stop", "--time", "1", name],
                            capture_output=True, timeout=3, env=docker_environment())
            if stop.returncode and not _container_absent(stop):
                # Daemon unavailable, permission denied, or any real stop
                # error must stay a cleanup failure.
                return False
            check = self.run([self.docker, "inspect", "--format", "{{.State.Running}}", name],
                             capture_output=True, timeout=3, env=docker_environment())
            if _container_absent(check):
                return True
            if check.returncode != 0:
                return False
            running = getattr(check, "stdout", b"")
            if isinstance(running, bytes):
                running = running.decode("ascii", "replace")
            return running.strip() == "false"
        except Exception:
            return False

    def cleanup(self):
        stopped = True
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1)
                stopped = stopped and process.poll() is not None
            except Exception:
                stopped = False
        removed = True
        for name in self.names:
            try:
                result = self.run([self.docker, "rm", "-f", name], capture_output=True,
                                  timeout=3, env=docker_environment())
                if result.returncode and not _container_absent(result):
                    # Never turn daemon/permission errors into "removed".
                    removed = False
                check = self.run([self.docker, "inspect", name], capture_output=True,
                                 timeout=3, env=docker_environment())
                if check.returncode == 0:
                    removed = False  # container still exists
                elif not _container_absent(check):
                    removed = False  # daemon/permission/unknown inspect failure
            except Exception:
                removed = False
        for process in self.processes:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    try:
                        stream.close()
                    except Exception:
                        pass
        stage_removed = self.staging is None
        if self.staging:
            stage_removed = remove_staging(self.staging)
        return {"owned_process_terminated": bool(stopped),
                "container_removed": bool(removed),
                "staging_removed": bool(stage_removed)}

    def wait(self, process, cancelled, deadline):
        while True:
            if cancelled.is_set():
                return "cancelled"
            if self.clock() >= deadline:
                return "timeout"
            if self.log_budget.truncated:
                return "limited"
            code = process.poll()
            if code is not None:
                return "completed" if code == 0 else "failed"
            time.sleep(0.02)

    def tool_checks(self, spec, cancelled, deadline):
        if cancelled.is_set():
            raise FuzzCancelled("campaign cancelled before tool checks")
        text, code, timed = self._run_help(spec, AFL_FUZZ, ["-h"], cancelled, deadline)
        if timed or code is None:
            raise ValueError("afl-fuzz help probe did not complete")
        fuzz_text = text
        if not re.search(r"afl-fuzz\+\+", fuzz_text):
            raise ValueError("afl-fuzz version/help is unavailable")
        required = ("-V seconds", "-E execs", "-G maxlength", "-i dir", "-o dir",
                    "-m megs", "-t msec")
        if not all(item in fuzz_text for item in required):
            raise ValueError("afl-fuzz lacks a required bounded-campaign option")
        text, code, timed = self._run_help(spec, AFL_SHOWMAP, ["-h"], cancelled, deadline)
        if cancelled.is_set():
            raise FuzzCancelled("campaign cancelled during afl-showmap help")
        if timed or code is None:
            raise ValueError("afl-showmap help probe did not complete")
        showmap_text = text
        if not re.search(r"afl-showmap\+\+", showmap_text):
            raise ValueError("afl-showmap version/help is unavailable")
        if not all(item in showmap_text for item in ("-o file", "-q", "-m megs", "-t msec")):
            raise ValueError("afl-showmap lacks a required bounded-probe option")
        fuzz_version = TOOL_RE.search(fuzz_text)
        showmap_version = TOOL_RE.search(showmap_text)
        if not fuzz_version or not showmap_version:
            raise ValueError("AFL tool versions are unavailable")
        return {"afl_version": fuzz_version.group(1),
                "showmap_version": showmap_version.group(1),
                "options_verified": True}

    def _run_help(self, spec, entrypoint, args, cancelled, deadline):
        if cancelled.is_set():
            raise FuzzCancelled("campaign cancelled before AFL help probe")
        name = "artex-afl-help-" + uuid.uuid4().hex[:16]
        self.names.append(name)
        process = self.start(self.command(name, spec, entrypoint, args),
                             subprocess.DEVNULL)
        text, code, status = self._read_process(
            process, min(deadline, self.clock() + 1.5), cancelled)
        if status == "cancelled":
            self._quiesce(name, process)
            raise FuzzCancelled("campaign cancelled during AFL help probe")
        if status == "timeout":
            raise FuzzBudgetTimeout("AFL help probe exceeded the campaign budget")
        if status == "limited":
            raise ValueError("AFL help output exceeded the log budget")
        if not self._quiesce(name, process):
            raise ValueError("AFL help container did not stop cleanly")
        if code is None:
            raise ValueError("AFL help probe did not exit")
        return text, code, False

    def probe(self, spec, cancelled, deadline):
        seed_path = Path(self.staging) / "seeds" / "seed-00"
        probe_argv = ["/work/seeds/seed-00" if x == "{input}" else x
                      for x in spec["argv"]]
        args = ["-q", "-m", "256", "-t", "500", "-o", "/work/out/probe.map",
                "--", "/work/sample", *probe_argv]
        name = "artex-afl-probe-" + uuid.uuid4().hex[:16]
        self.names.append(name)
        command = self.supervised_command(name, spec, "showmap", spec["max_crashes"],
                                          AFL_SHOWMAP, args)
        stdin = seed_path.open("rb") if spec["input_mode"] == "stdin" else subprocess.DEVNULL
        try:
            process = self.start(command, stdin)
        finally:
            if hasattr(stdin, "close"):
                stdin.close()
        state = self.wait(process, cancelled, deadline)
        if not self._quiesce(name, process):
            raise ValueError("instrumentation probe container did not stop cleanly")
        if state == "cancelled":
            return 0
        if state == "timeout":
            raise FuzzBudgetTimeout("instrumentation probe exceeded the campaign budget")
        if state != "completed":
            raise ValueError("instrumentation probe did not complete")
        try:
            payload = supervisor_payload(self.drain_output(process))
        except ValueError as exc:
            raise ValueError("AFL instrumentation probe failed: " + str(exc)) from exc
        if payload.get("exit") != 0:
            raise ValueError("AFL instrumentation probe rejected the non-instrumented target")
        encoded = payload.get("probe_map_base64")
        if not isinstance(encoded, str):
            raise ValueError("AFL instrumentation probe produced no bounded map")
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError("probe map is not canonical base64") from exc
        if base64.b64encode(data).decode("ascii") != encoded:
            raise ValueError("probe map is not canonical base64")
        return coverage_edges_data(data)

    def campaign_process(self, spec, cancelled, deadline):
        if self.clock() >= deadline:
            return "timeout", None, None, ""
        seconds = max(1, int(deadline - self.clock()))
        args = ["-i", "/work/seeds", "-o", "/work/out/findings",
                "-V", str(seconds), "-E", str(max(1, spec["max_executions"] - 1)),
                "-m", "256", "-t", "500", "-G", "4096", "-D",
                "--", "/work/sample",
                *["@@" if x == "{input}" else x for x in spec["argv"]]]
        name = "artex-afl-" + uuid.uuid4().hex[:16]
        self.names.append(name)
        command = self.supervised_command(name, spec, "fuzz", spec["max_crashes"],
                                          AFL_FUZZ, args)
        process = self.start(command, subprocess.DEVNULL)
        state = self.wait(process, cancelled, deadline)
        if not self._quiesce(name, process):
            raise ValueError("fuzz container did not stop cleanly")
        output = self.drain_output(process) if state in ("completed", "failed") else ""
        return state, name, process, output

    def campaign(self, first, cancelled):
        errors, corpus, crashes, stats = [], [], [], {}
        spec, truncated, reason, probe_edges = None, False, None, 0
        state, tool = "failed", {}
        started = self.clock()
        cleanup = {"owned_process_terminated": True, "container_removed": True,
                   "staging_removed": True}
        try:
            spec = validate(first)
            deadline = started + spec["duration_ms"] / 1000
            work_deadline = max(started, deadline - CLEANUP_RESERVE_SECONDS)
            if cancelled.is_set():
                state = "cancelled"
            else:
                self.staging = tempfile.mkdtemp(prefix="artex-afl-")
                root = Path(self.staging)
                root.chmod(0o755)
                seed_dir = root / "seeds"
                seed_dir.mkdir(mode=0o755)
                artifact = regular_bytes(spec["artifact_path"], MAX_ARTIFACT)
                if hashlib.sha256(artifact).hexdigest() != spec["sha256"]:
                    raise ValueError("artifact SHA-256 mismatch")
                sample = root / "sample"
                sample.write_bytes(artifact)
                sample.chmod(0o555)
                metadata = inspect_elf(sample)
                if metadata["type_name"] not in ("ET_EXEC", "ET_DYN") or metadata["sha256"] != spec["sha256"]:
                    raise ValueError("target must be a Linux x86-64 executable")
                for index, (_, data) in enumerate(spec["seeds"]):
                    path = seed_dir / f"seed-{index:02d}"
                    path.write_bytes(data)
                    path.chmod(0o444)
                if cancelled.is_set():
                    state = "cancelled"
                elif self.clock() >= work_deadline:
                    state = "timeout"
                    reason = "budget_exhausted"
                else:
                    check_deadline = min(work_deadline, self.clock() + 5.0)
                    tool = self.tool_checks(spec, cancelled, check_deadline)
                    if cancelled.is_set():
                        state = "cancelled"
                    elif self.clock() >= work_deadline:
                        state = "timeout"
                        reason = "budget_exhausted"
                    else:
                        probe_deadline = min(work_deadline,
                                             self.clock() + max(1.0, min(4.0, spec["duration_ms"] / 3000)))
                        probe_edges = self.probe(spec, cancelled, probe_deadline)
                        if cancelled.is_set():
                            state = "cancelled"
                        elif probe_edges <= 0:
                            raise ValueError("no AFL instrumentation edges were observed")
                        elif self.clock() >= work_deadline:
                            state = "timeout"
                            reason = "budget_exhausted"
                        else:
                            campaign_state, name, _, output = self.campaign_process(
                                spec, cancelled, work_deadline)
                            if name is None:
                                state = "timeout"
                                reason = "budget_exhausted"
                            else:
                                if campaign_state == "timeout":
                                    state = "timeout"
                                    reason = "budget_exhausted"
                                elif campaign_state == "cancelled":
                                    state = "cancelled"
                                    reason = "cancelled"
                                elif campaign_state == "limited":
                                    state = "failed"
                                    truncated = True
                                    errors.append("fuzz output exceeded log budget")
                                elif campaign_state == "failed":
                                    state = "failed"
                                    errors.append("AFL campaign exited unsuccessfully")
                                else:
                                    state = "completed"
                                if output:
                                    payload = supervisor_payload(output)
                                    if payload.get("exit") != 0 and state == "completed":
                                        state = "failed"
                                        errors.append("AFL campaign exited unsuccessfully")
                                    if payload.get("findings") is True:
                                        queue = payload.get("queue")
                                        crash_items = payload.get("crashes")
                                        if not isinstance(queue, list) or not isinstance(crash_items, list):
                                            raise ValueError("invalid supervisor candidate lists")
                                        if len(queue) > MAX_CORPUS or len(crash_items) > spec["max_crashes"]:
                                            raise ValueError("supervisor exceeded candidate count bounds")
                                        corpus, total = [], 0
                                        for item in queue:
                                            data = decode_candidate(item)
                                            if total + len(data) > MAX_CORPUS_BYTES:
                                                truncated = True
                                                break
                                            total += len(data)
                                            corpus.append({"sha256": hashlib.sha256(data).hexdigest(),
                                                           "data_base64": base64.b64encode(data).decode("ascii")})
                                        crashes, total = [], 0
                                        for item in crash_items:
                                            data = decode_candidate(item)
                                            if total + len(data) > spec["max_crashes"] * MAX_CANDIDATE:
                                                truncated = True
                                                break
                                            total += len(data)
                                            crashes.append({"sha256": hashlib.sha256(data).hexdigest(),
                                                            "data_base64": base64.b64encode(data).decode("ascii")})
                                        stats_raw = payload.get("stats_base64")
                                        if isinstance(stats_raw, str):
                                            try:
                                                stats_data = base64.b64decode(stats_raw, validate=True)
                                            except Exception as exc:
                                                raise ValueError("invalid fuzzer stats encoding") from exc
                                            stats = parse_stats(stats_data)
                                        truncated = truncated or payload.get("truncated") is True
                                    elif state == "completed":
                                        state = "failed"
                                        errors.append("no campaign corpus evidence")
                                if state == "completed" and not corpus:
                                    state = "failed"
                                    errors.append("no campaign corpus evidence")
        except FuzzCancelled:
            state = "cancelled"
            reason = "cancelled"
        except FuzzBudgetTimeout:
            state = "timeout"
            reason = "budget_exhausted"
        except Exception as exc:
            state = "failed"
            errors.append(str(exc)[:512])
        finally:
            cleanup = self.cleanup()
        if not all(cleanup.values()):
            errors.append("cleanup_unverified")
            state = "failed"
        if cancelled.is_set() and state != "failed":
            state = "cancelled"
            reason = reason or "cancelled"
        manifest = {
            "engine": "afl++",
            "artifact_sha256": spec["sha256"] if spec else None,
            "image": spec["image"] if spec else None,
            "input_mode": spec["input_mode"] if spec else None,
            "afl_version": tool.get("afl_version"),
            "showmap_version": tool.get("showmap_version"),
            "options_verified": bool(tool.get("options_verified")),
            "probe_edges": probe_edges,
            "probe_executions": 1 if probe_edges else 0,
            "output_disk_limit_bytes": MAX_OUTPUT_DISK,
            "single_worker": True,
        }
        result = {"engine": "afl++", "target_state": state, "manifest": manifest,
                  "stats": stats, "corpus": corpus, "crashes": crashes,
                  "cleanup": cleanup, "errors": errors[:8],
                  "stats_trusted": False, "coverage_claimed": False,
                  "candidate_status": "unverified_requires_replay",
                  "truncated": bool(truncated), "limited": bool(truncated),
                  "reason": reason, "cleanup_verified": all(cleanup.values())}
        if len(json.dumps(result, separators=(",", ":")).encode()) > MAX_RESPONSE:
            result.update(target_state="failed", corpus=[], crashes=[],
                          truncated=True, limited=True,
                          errors=["response_limit"])
        return result


def serve_fuzz(first, inp, emit, runner=None):
    cancelled = threading.Event()

    def controls():
        try:
            while True:
                frame = read_frame(inp)
                if frame is None or frame.get("cancel") is True or frame.get("action") == "stop":
                    cancelled.set()
                    return
                if set(frame) - {"request_id", "action", "cancel"}:
                    cancelled.set()
                    return
        except Exception:
            cancelled.set()

    try:
        inp.fileno()
    except (AttributeError, OSError, ValueError):
        pass
    else:
        threading.Thread(target=controls, daemon=True, name="artex-afl-controls").start()
    result = (runner or FuzzRunner()).campaign(first, cancelled)
    emit({"request_id": first.get("request_id", "fuzz"), "kind": "final",
          "observation": result})
    state = result["target_state"]
    return 0 if state in ("completed", "cancelled", "timeout") and result["cleanup_verified"] else 1
