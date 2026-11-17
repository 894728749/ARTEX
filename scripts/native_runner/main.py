#!/usr/bin/env python3
"""Docker-only persistent native session manager. stdout is protocol JSONL only."""
import base64
import hashlib
import json
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .elf import elf_file_offset
from .gdb_mi import (MIReader, command as gdb_command, parse_record, result_record,
                     running_record, stop_values)
from .process import ByteReader, OutputBudget, write_bounded
from .protocol import MAX_IO, PROTOCOL_VERSION, encode, read_frame, write_frame
from .sandbox import DockerSandbox, docker_environment, validate_argv

MAX_STREAM = 16 * 1024 * 1024
MAX_CACHE_ITEMS = 128
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_LEASE_MS = 120000
OBSERVATION_TIMEOUT = 2.5
MAX_MI_RESPONSE_RECORDS = 512

_SIGNAL_NUMBERS = {
    "SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
    "SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10,
    "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15,
    "SIGSTKFLT": 16, "SIGCHLD": 17, "SIGCONT": 18, "SIGSTOP": 19, "SIGTSTP": 20,
    "SIGTTIN": 21, "SIGTTOU": 22, "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25,
    "SIGVTALRM": 26, "SIGPROF": 27, "SIGWINCH": 28, "SIGIO": 29, "SIGPWR": 30,
    "SIGSYS": 31,
}
_SIGNAL_NAMES = {value: key for key, value in _SIGNAL_NUMBERS.items()}


def profile_settings(profile):
    if not isinstance(profile, dict):
        return {}
    settings = profile.get("settings")
    return settings if isinstance(settings, dict) else profile


def classify_exit_code(code):
    if code is None:
        return "running", None
    if code < 0:
        return "crashed", -code
    if code >= 128:
        return "crashed", code - 128
    return "exit", None


def expectation_matches(state, code, expected_exit, expected_signal):
    return ((expected_exit is not None and code == expected_exit)
            or (state == "crashed" and isinstance(expected_signal, int)
                and code in (128 + expected_signal, -expected_signal)))


def expectations_satisfied(state, exit_code, signal_number, expected_exit,
                           expected_signal, matches):
    """Return whether a replay result satisfies every supplied expectation.

    An expectation that is present must be met.  Without an explicit
    expectation, only a normal exit or a caller cancellation is successful; an
    unexpected crash or timeout is not.
    """
    if expected_exit is None and expected_signal is None:
        return state in ("exit", "cancelled")
    if not matches:
        return False
    if expected_exit is not None:
        if state != "exit" or exit_code != expected_exit:
            return False
    if expected_signal is not None:
        if state != "crashed" or signal_number != expected_signal:
            return False
        if exit_code not in (128 + expected_signal, -expected_signal):
            return False
    return True


def validate_session_action(action, mode):
    if mode == "debug" and action in ("send", "close_stdin"):
        raise ValueError(f"{action} is disabled in debug mode; GDB owns the control input")
    return True


def _settle_reader(reader, timeout=0.25):
    if not reader:
        return
    deadline = time.monotonic() + timeout
    while not reader.eof and time.monotonic() < deadline:
        try:
            reader.recv(MAX_IO, 0.01)
        except Exception:
            break


def _stderr_summary(reader):
    if not reader:
        return {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(),
                "truncated": False, "tail_base64": "", "tail_bytes": 0,
                "sanitizer": {"detected": False, "summaries": []}}
    return {"bytes": reader.bytes_seen, "sha256": reader.hasher.hexdigest(),
            "truncated": bool(reader.truncated),
            "tail_base64": encode(reader.tail), "tail_bytes": len(reader.tail),
            "accepted_bytes": reader.accepted, "dropped_bytes": reader.dropped,
            "sanitizer": {"detected": bool(reader.sanitizer), "summaries": reader.sanitizer}}


def _hex_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 16)
        except ValueError:
            return None
    return None


def _decimal_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value.strip()):
        return int(value, 10)
    return None


def _exit_code_from_stop(values):
    raw = values.get("exit-code") if isinstance(values, dict) else None
    if raw is None:
        return 0
    try:
        return int(str(raw), 8)
    except (TypeError, ValueError):
        return None


def _signal_number(name):
    if isinstance(name, str):
        text = name.strip().upper()
        if text in _SIGNAL_NUMBERS:
            return _SIGNAL_NUMBERS[text]
        match = re.fullmatch(r"SIG([A-Z0-9]+)", text)
        if match:
            return _SIGNAL_NUMBERS.get("SIG" + match.group(1))
    return None


def _signal_name(number):
    return _SIGNAL_NAMES.get(number, str(number) if number is not None else None)


def _registers_from_results(names_values, values_values):
    names = None
    if isinstance(names_values, dict):
        names = names_values.get("register-names")
    if not isinstance(names, list):
        names = []
    rows = None
    if isinstance(values_values, dict):
        rows = values_values.get("register-values")
    if not isinstance(rows, list):
        return None
    result = {}
    for index, row in enumerate(rows[:256]):
        if not isinstance(row, dict):
            continue
        number = _decimal_int(row.get("number"))
        name_index = number if number is not None else index
        name = names[name_index] if 0 <= name_index < len(names) and isinstance(names[name_index], str) else None
        if not name:
            name = f"r{name_index}"
        value = row.get("value")
        result[name] = value if isinstance(value, str) else str(value)
    return result or None


def _stack_from_result(values):
    if not isinstance(values, dict):
        return None
    rows = values.get("stack")
    if not isinstance(rows, list):
        return None
    stack = []
    for row in rows[:32]:
        frame = row.get("frame") if isinstance(row, dict) and isinstance(row.get("frame"), dict) else None
        if not isinstance(frame, dict):
            continue
        stack.append({key: frame.get(key) for key in
                      ("level", "addr", "func", "file", "fullname", "line", "arch")
                      if key in frame})
    return stack or None


def _shared_libraries_from_result(values):
    if not isinstance(values, dict):
        return None
    rows = values.get("shared-libraries")
    if not isinstance(rows, list):
        return None
    libraries = []
    for row in rows[:64]:
        if not isinstance(row, dict):
            continue
        path = row.get("target-name") or row.get("host-name") or row.get("id")
        ranges = []
        for item in (row.get("ranges") or [])[:32]:
            if not isinstance(item, dict):
                continue
            start, end = _hex_int(item.get("from")), _hex_int(item.get("to"))
            if start is not None and end is not None and end > start:
                ranges.append({"from": start, "to": end})
        libraries.append({"path": path if isinstance(path, str) else "unknown",
                          "target_name": row.get("target-name"),
                          "host_name": row.get("host-name"),
                          "ranges": ranges})
    return libraries or None


def _pid_from_groups(values):
    if not isinstance(values, dict):
        return None
    for key in ("groups", "threads"):
        rows = values.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            pid = _decimal_int(row.get("pid"))
            if pid:
                return pid
            match = re.search(r"(?:process|Thread|LWP)\s+([0-9]+)", str(row.get("target-id", "")))
            if match:
                return int(match.group(1))
    return None


def _parse_proc_maps(text):
    if not isinstance(text, str):
        return None
    result = []
    for line in text.splitlines()[:8192]:
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        bounds = parts[0].split("-", 1)
        if len(bounds) != 2:
            continue
        try:
            start, end = int(bounds[0], 16), int(bounds[1], 16)
            offset = int(parts[2], 16)
        except ValueError:
            continue
        path = parts[5].strip() if len(parts) > 5 else ""
        if path.endswith(" (deleted)"):
            path = path[:-10]
        if not path or path.startswith("["):
            continue
        result.append({"start": start, "end": end, "offset": offset, "path": path})
    return result or None


def _module_for_pc(pc, proc_maps, shared, main_meta):
    """Resolve a runtime PC to a single stable module coordinate.

    ``module_offset`` is always an ELF *file offset*.  Only /proc maps expose
    the per-mapping file offset needed for that coordinate.  A GDB
    shared-library text range gives a runtime start but no file offset; using
    ``pc - range_start`` there would produce a different coordinate for the
    same PC, so that fallback deliberately returns an unknown offset and no
    crash signature.  ET_EXEC has identity vaddr == runtime address and can be
    translated through its PT_LOAD table.
    """
    if pc is None:
        return None, None, None, "unknown"
    for mapping in proc_maps or []:
        if mapping["start"] <= pc < mapping["end"]:
            offset = mapping["offset"] + (pc - mapping["start"])
            base = mapping["start"] - mapping["offset"]
            return mapping["path"], offset, base, "proc_maps"
    for library in shared or []:
        for address_range in library.get("ranges", []):
            if address_range["from"] <= pc < address_range["to"]:
                # Text-range start is not a file offset; do not guess a base.
                return (library.get("path") or "unknown", None, None,
                        "gdb_shared_libraries_unresolved")
    if isinstance(main_meta, dict):
        if main_meta.get("type") == 2:
            offset = elf_file_offset(main_meta, pc)
            if offset is not None:
                return "/work/sample", offset, 0, "elf_executable"
        text_vaddr = main_meta.get("text_vaddr")
        if main_meta.get("type") == 3 and isinstance(text_vaddr, int):
            # Runtime base is only known from maps; do not guess a PIE offset
            # from the unrelocated link address.
            return "unknown", None, None, "unknown"
    return "unknown", None, None, "unknown"


def _build_target_observation(main_sha, main_meta, attached, stop_info, registers,
                              stack, shared, proc_maps, aslr_enabled=True):
    stop_info = stop_info or {}
    frame = stop_info.get("frame") if isinstance(stop_info.get("frame"), dict) else {}
    raw_pc = _hex_int(frame.get("addr"))
    if raw_pc is None and registers:
        for key in ("rip", "pc", "eip"):
            raw_pc = _hex_int(registers.get(key))
            if raw_pc is not None:
                break
    module_path, module_offset, module_base, source = _module_for_pc(
        raw_pc, proc_maps, shared, main_meta)
    module_sha = None
    module_build_id = None
    normalized_path = module_path if isinstance(module_path, str) else ""
    if normalized_path == "/work/sample":
        module_sha = main_sha
        if isinstance(main_meta, dict):
            module_build_id = main_meta.get("build_id")
    elif normalized_path in (attached or {}):
        record = attached[normalized_path]
        module_sha = record.get("sha256")
        module_build_id = record.get("build_id")
    elif source == "elf_executable":
        module_sha = main_sha
        if isinstance(main_meta, dict):
            module_build_id = main_meta.get("build_id")
    signal_number = None
    if isinstance(stop_info.get("signal-name"), str):
        signal_number = _signal_number(stop_info["signal-name"])
    unknown = []
    if raw_pc is None:
        unknown.append("raw_pc")
    if module_offset is None:
        unknown.append("module_offset")
    if not module_sha and not module_build_id:
        unknown.append("module_identity")
    if signal_number is None:
        unknown.append("signal")
    observation = {
        "evidence_source": "target_debugger",
        "artifact_sha256": main_sha,
        "raw_pc": raw_pc,
        "raw_pc_hex": f"0x{raw_pc:x}" if isinstance(raw_pc, int) else None,
        "module_path": module_path or "unknown",
        "module_offset": module_offset,
        "module_offset_basis": ("elf_file_offset" if isinstance(module_offset, int) else None),
        "module_base": module_base,
        "module_sha256": module_sha,
        "module_build_id": module_build_id,
        "module_identity_known": bool(module_sha or module_build_id),
        "module_identity_source": source,
        "registers": registers,
        "stack": stack,
        "stop_reason": stop_info.get("reason"),
        "signal": signal_number,
        "signal_name": stop_info.get("signal-name"),
        "aslr": "enabled" if aslr_enabled else "unknown",
        "unknown_fields": unknown,
        "crash_signature": None,
    }
    if signal_number is not None and raw_pc is not None and isinstance(module_offset, int) and module_offset >= 0:
        signature = {"artifact_sha256": main_sha, "module_offset": module_offset,
                     "signal": signal_number}
        if module_sha:
            signature["module_sha256"] = module_sha
        elif module_build_id:
            signature["module_build_id"] = module_build_id
        else:
            signature = None
        observation["crash_signature"] = signature
    return observation


def _environment_manifest(sandbox, image):
    environment = {"platform": "linux/x86_64",
                   "architecture": platform.machine() or "x86_64",
                   "kernel": platform.release()}
    probe = getattr(sandbox, "environment_manifest", None)
    if callable(probe) and isinstance(image, str):
        try:
            result = probe(image)
            if isinstance(result, dict):
                environment.update(result)
        except Exception:
            environment["environment_probe_error"] = "tool version probe unavailable"
    return environment


def _manifest(mode, sha, first, session, environment, duration_ms=None):
    profile = profile_settings(first.get("profile") or {})
    attached = session.get("attached_artifacts", []) if session else []
    manifest = {"engine": "docker-native", "mode": mode, "artifact_sha256": sha,
                "image": profile.get("image"),
                "architecture": environment.get("architecture"),
                "kernel": environment.get("kernel"),
                "tool_versions": {key: environment.get(key) for key in
                                  ("gdb", "loader", "python", "os", "image_id")},
                "environment": environment,
                "attached_artifacts": attached,
                "attached_hashes": [{"kind": item.get("kind"), "name": item.get("name"),
                                     "sha256": item.get("sha256"), "size": item.get("size"),
                                     "build_id": item.get("build_id")} for item in attached],
                "aslr": "enabled" if mode == "debug" else "not_applicable"}
    if duration_ms is not None:
        manifest["duration_ms"] = duration_ms
    return manifest


def _cleanup_result(sandbox, session, errors):
    if not session:
        cleanup = {"owned_process_terminated": True, "container_removed": True,
                   "staging_removed": True, "core_removed": True}
    else:
        try:
            cleanup = sandbox.cleanup(session)
        except Exception as exc:
            cleanup = {"owned_process_terminated": False, "container_removed": False,
                       "staging_removed": False, "core_removed": False,
                       "error": str(exc)}
    required = ("owned_process_terminated", "container_removed", "staging_removed")
    verified = (all(cleanup.get(key) is True for key in required)
                and cleanup.get("core_removed", True) is True)
    if not verified:
        errors.append("cleanup could not be confirmed")
    return cleanup, verified


def _mutable_image_error(image):
    return not (isinstance(image, str) and
                (re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image)
                 or re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", image)))


def doctor(docker="docker", profile=None, run=subprocess.run):
    """Bounded availability probe.  The ptrace check uses owned containers."""
    result = {"engine": "docker-native", "platform": "linux/x86_64",
              "protocol_version": PROTOCOL_VERSION,
              "docker_available": False, "image_available": False,
              "gdb_available": False, "ptrace_available": False,
              "actions": ["send", "recv", "close_stdin", "status", "stop", "heartbeat"]}

    def call(argv, **kwargs):
        kwargs.setdefault("env", docker_environment())
        return run(argv, **kwargs)

    try:
        version = call([docker, "version", "--format", "{{.Server.Version}}"],
                       capture_output=True, text=True, timeout=4, check=True).stdout.strip()
        result.update(docker_available=True, docker_server_version=version)
    except Exception as exc:
        result["availability_error"] = "docker server unavailable: " + type(exc).__name__
        return result
    result["host_architecture"] = platform.machine()
    result["kernel_version"] = platform.release()
    if profile is None:
        profile_path = os.environ.get("ARTEX_NATIVE_PROFILE")
        if profile_path:
            try:
                with open(profile_path, encoding="utf-8") as handle:
                    cfg = json.load(handle)
                profiles = cfg if isinstance(cfg, list) else cfg.get("profiles", [])
                profile = next((p for p in profiles if p.get("engine") == "docker-native"
                                and profile_settings(p).get("enabled", True)), None)
            except Exception:
                profile = None
    if not profile:
        result["availability_error"] = "no enabled docker-native profile"
        return result
    settings = profile_settings(profile)
    if settings.get("enabled") is False:
        result["availability_error"] = "docker-native profile is disabled"
        return result
    image = settings.get("image")
    if _mutable_image_error(image) or "REPLACE_WITH" in str(image):
        result["availability_error"] = "profile.image is not an immutable sha256 digest"
        return result
    result["image"] = image
    try:
        inspect = call([docker, "image", "inspect", image],
                       capture_output=True, text=True, timeout=8)
        if inspect.returncode != 0:
            result["availability_error"] = "immutable image is not present"
            return result
        metadata = json.loads(inspect.stdout)
        result["image_architecture"] = metadata[0].get("Architecture")
        if result["image_architecture"] != "amd64":
            result["availability_error"] = "image architecture is not amd64"
            return result
        result["image_available"] = True
        gdb = call([docker, "run", "--pull=never", "--rm", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                    "--entrypoint", "/usr/bin/gdb", image, "--version"],
                   capture_output=True, text=True, timeout=15)
        result["gdb_available"] = gdb.returncode == 0
        result["gdb_version"] = (gdb.stdout.splitlines() or [""])[0] if gdb.returncode == 0 else None
        loader = call([docker, "run", "--pull=never", "--rm", "--network=none", "--read-only",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                       "--entrypoint", "/lib64/ld-linux-x86-64.so.2", image, "--version"],
                      capture_output=True, text=True, timeout=15)
        result["loader_available"] = loader.returncode == 0
        result["loader_version"] = (loader.stdout.splitlines() or [""])[0] if loader.returncode == 0 else None
        py = call([docker, "run", "--pull=never", "--rm", "--network=none", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                   "--entrypoint", "/usr/bin/python3", image, "--version"],
                  capture_output=True, text=True, timeout=15)
        result["python_available"] = py.returncode == 0
        result["python_version"] = py.stdout.strip() if py.returncode == 0 else None
        root = Path(__file__).resolve().parents[2]
        seccomp = root / "deploy" / "native-lab" / "seccomp-debug.json"
        probe_source = root / "deploy" / "native-lab" / "ptrace_probe.c"
        result["ptrace_probe_source_available"] = probe_source.is_file()
        if gdb.returncode != 0:
            result["ptrace_probe_error"] = "gdb is unavailable"
        elif settings.get("seccomp_profile") not in ("deploy/native-lab/seccomp-debug.json",
                                                     "deploy\\native-lab\\seccomp-debug.json"):
            result["ptrace_probe_error"] = "debug seccomp profile setting is unavailable"
        elif not seccomp.is_file():
            result["ptrace_probe_error"] = "debug seccomp profile is unavailable"
        else:
            name = "artex-doctor-" + uuid.uuid4().hex[:16]
            probe_cmd = [docker, "run", "--pull=never", "--name", name, "--init",
                         "--network=none", "--read-only", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--pids-limit=64",
                         "--memory=512m", "--cpus=1", "--user=65534:65534",
                         "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                         "--security-opt", f"seccomp={seccomp}",
                         "--entrypoint", "/usr/bin/gdb", image,
                         "--quiet", "--nx", "--batch",
                         "-ex", "set auto-load off",
                         "-ex", "set disable-randomization off",
                         "-ex", "file /usr/local/bin/artex-ptrace-probe",
                         "-ex", "run"]
            probe = None
            timeout_error = None
            try:
                probe = call(probe_cmd, capture_output=True, text=True, timeout=20)
            except subprocess.TimeoutExpired:
                timeout_error = "ptrace probe timed out"
            except Exception as exc:
                timeout_error = "ptrace probe failed: " + type(exc).__name__
            finally:
                removed = False
                try:
                    removal = call([docker, "rm", "-f", name], capture_output=True,
                                   timeout=5)
                    removed = removal.returncode == 0
                except Exception:
                    removed = False
                try:
                    inspect_after = call([docker, "inspect", "--format", "{{.Id}}", name],
                                         capture_output=True, timeout=5)
                    if inspect_after.returncode != 0:
                        removed = True
                    else:
                        removed = False
                except Exception:
                    removed = False
                result["ptrace_probe_cleanup_verified"] = removed
            if timeout_error:
                result["ptrace_probe_error"] = timeout_error
            elif probe is not None:
                result["ptrace_probe_exit_code"] = probe.returncode
                output = (probe.stdout or "") + (probe.stderr or "")
                result["ptrace_available"] = (probe.returncode == 0
                                              and re.search(r"exited normally", output, re.I) is not None
                                              and result.get("ptrace_probe_cleanup_verified") is True)
                if not result["ptrace_available"]:
                    result["ptrace_probe_error"] = "ptrace probe did not report a normal inferior exit"
            if not result.get("ptrace_probe_cleanup_verified"):
                result["ptrace_available"] = False
                result["ptrace_probe_error"] = "ptrace probe container cleanup could not be verified"
        result["environment"] = {
            "kernel": platform.release(), "architecture": result.get("image_architecture"),
            "gdb": result.get("gdb_version"), "loader": result.get("loader_version"),
            "python": result.get("python_version")}
        if result["ptrace_available"]:
            result["actions"] += ["debug"]
        missing = []
        if not result.get("loader_available"):
            missing.append("ELF loader /lib64/ld-linux-x86-64.so.2")
        if not result.get("python_available"):
            missing.append("python3")
        if not result["ptrace_available"]:
            missing.append("bounded ptrace debug probe")
        if missing:
            result["missing_dependencies"] = missing
    except Exception as exc:
        result["availability_error"] = "doctor probe failed: " + type(exc).__name__
    return result


def serve(inp=sys.stdin, out=sys.stdout, sandbox=None):
    sandbox = sandbox or DockerSandbox()
    first = read_frame(inp)
    if first is None:
        return 0
    event_seq = 0

    def emit(frame):
        nonlocal event_seq
        event_seq += 1
        frame["event_seq"] = event_seq
        write_frame(out, frame)

    operation = first.get("operation")
    if operation == "doctor":
        emit({"request_id": first.get("request_id", "doctor"), "kind": "result",
              "observation": doctor(profile=first.get("profile"))})
        return 0
    if operation == "replay":
        return _serve_replay(first, inp, sandbox, emit)
    if operation != "session" or first.get("request_id") != "start":
        emit({"request_id": first.get("request_id", "start"), "kind": "final",
              "observation": {"target_state": "failed",
                              "errors": ["expected session start frame"]}})
        return 2
    return _serve_session(first, inp, sandbox, emit)


def _serve_replay(first, inp, sandbox, emit):
    rid = first.get("request_id", "replay")
    cancelled = threading.Event()

    def replay_control():
        try:
            while True:
                frame = read_frame(inp)
                if frame is None or frame.get("cancel") is True or frame.get("action") == "stop":
                    cancelled.set()
                    return
        except Exception:
            cancelled.set()

    try:
        inp.fileno()
    except (AttributeError, OSError, ValueError):
        pass
    else:
        threading.Thread(target=replay_control, daemon=True).start()
    session = None
    reader = None
    stderr_reader = None
    errors = []
    state = "failed"
    exit_code = None
    signal_number = None
    signal_source = None
    output = b""
    sha = None
    profile = {}
    started = time.monotonic()
    input_mode = first.get("input_mode", "stdin")
    duration = 30000
    budget = OutputBudget(MAX_STREAM)
    try:
        if first.get("mode", "exec") != "exec":
            raise ValueError("replay only supports exec mode")
        artifact = first.get("artifact_path")
        sha = sandbox.inspect_elf(artifact)
        if sha.lower() != str(first.get("sha256", "")).lower():
            raise ValueError("artifact SHA-256 mismatch")
        argv = validate_argv(first.get("argv", []), first.get("input_mode", "stdin"))
        if input_mode not in ("stdin", "file"):
            raise ValueError("input_mode must be stdin or file")
        data = base64.b64decode(first.get("input_base64", "") or "", validate=True)
        if len(data) > MAX_IO:
            raise ValueError("replay input exceeds 65536-byte limit")
        duration = first.get("duration_ms", 30000)
        if isinstance(duration, bool) or not isinstance(duration, int) or duration < 1:
            raise ValueError("duration_ms must be positive")
        duration = min(duration, 900000)
        expected_exit = first.get("expected_exit")
        expected_signal = first.get("expected_signal")
        if expected_exit is not None and (isinstance(expected_exit, bool)
                                          or not isinstance(expected_exit, int) or expected_exit < 0):
            raise ValueError("expected_exit must be a non-negative integer")
        if expected_signal is not None and (isinstance(expected_signal, bool)
                                            or not isinstance(expected_signal, int)
                                            or not 1 <= expected_signal <= 64):
            raise ValueError("expected_signal is outside 1..64")
        target = first.get("target") or {}
        profile = profile_settings(first.get("profile") or {})
        session = sandbox.start(artifact, sha, argv, "exec", profile, duration,
                                target, input_mode, data)
        proc = session["process"]
        reader = ByteReader(proc.stdout, budget=budget)
        stderr_reader = ByteReader(proc.stderr, budget=budget)
        try:
            if data and input_mode == "stdin":
                write_bounded(proc.stdin, data)
        except BrokenPipeError:
            pass
        except Exception as exc:
            errors.append("input delivery failed: " + str(exc))
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:
            pass
        chunks = []
        deadline = time.monotonic() + duration / 1000
        exit_deadline = None
        while True:
            now = time.monotonic()
            part, eof = reader.recv(MAX_IO, 0.02)
            if part:
                chunks.append(part)
            stderr_reader.recv(MAX_IO, 0)
            if cancelled.is_set():
                state = "cancelled"
                break
            code = proc.poll()
            if code is not None:
                if exit_deadline is None:
                    exit_deadline = now + 0.5
                if eof or now >= exit_deadline:
                    exit_code = code
                    state, signal_number = classify_exit_code(code)
                    if code < 0:
                        signal_source = "docker_client_signal"
                        errors.append("Docker client terminated by signal")
                    else:
                        signal_source = "docker_exit_status_convention"
                    break
            if now >= deadline:
                state = "timeout"
                break
        if reader is not None:
            settle_deadline = time.monotonic() + 0.2
            while not reader.eof and time.monotonic() < settle_deadline:
                part, eof = reader.recv(MAX_IO, 0.02)
                if part:
                    chunks.append(part)
                if eof:
                    break
        output = b"".join(chunks)
        if state == "failed" and exit_code is not None:
            state, signal_number = classify_exit_code(exit_code)
    except Exception as exc:
        errors.append(str(exc))
        state = "failed"
    cleanup, cleanup_verified = _cleanup_result(sandbox, session, errors)
    if state in ("running", "failed") and exit_code is None and not errors:
        state = "failed"
        errors.append("target did not produce a terminal state")
    if state in ("exit", "crashed") and exit_code is None and session:
        code = session["process"].poll()
        if code is not None:
            exit_code = code
            state, signal_number = classify_exit_code(code)
            signal_source = "docker_exit_status_convention" if code >= 0 else "docker_client_signal"
    _settle_reader(stderr_reader)
    expected_exit = first.get("expected_exit")
    expected_signal = first.get("expected_signal")
    docker_exit_code = exit_code
    docker_client_failed = exit_code is not None and exit_code < 0
    if docker_client_failed:
        state = "failed"
        exit_code = None
        signal_number = None
        signal_source = "docker_client_signal"
        if "Docker client terminated by signal" not in errors:
            errors.append("Docker client terminated by signal")
    matches = expectation_matches(state, exit_code, expected_exit, expected_signal)
    if signal_number is None and not docker_client_failed:
        _, signal_number = classify_exit_code(exit_code)
    output_limited = bool(budget.truncated or (reader and reader.truncated))
    if cleanup_verified:
        if state == "timeout":
            outcome = "timeout"
        elif state == "cancelled":
            outcome = "cancelled"
        elif output_limited:
            outcome = "limited"
        else:
            outcome = state
    else:
        outcome = "cleanup_unverified"
    environment = _environment_manifest(sandbox, profile.get("image"))
    observation = {
        "target_state": state, "outcome": outcome, "terminal_state": state, "exit_code": exit_code,
        "signal": signal_number, "signal_source": signal_source,
        "docker_exit_code": docker_exit_code,
        "docker_client_exit_code": docker_exit_code if docker_client_failed else None,
        "expected_exit": expected_exit, "expected_signal": expected_signal,
        "matches_expectation": bool(matches),
        "output_source": session.get("output_source") if session else "target_stdout",
        "output_trusted": bool(session.get("output_trusted", True)) if session else True,
        "target_state_source": ("docker_client" if docker_client_failed
                                else "harness_process"
                                if session and session.get("output_source") == "harness_stdout"
                                else "target_process"),
        "target_exit_trusted": (not docker_client_failed
                                and not bool(session and session.get("output_source") == "harness_stdout")),
        "output_base64": encode(output), "output_bytes": len(output),
        "output_truncated": output_limited,
        "output_limited": output_limited,
        "stderr": _stderr_summary(stderr_reader),
        "errors": errors, "cleanup": cleanup, "cleanup_verified": cleanup_verified,
        "cleanup_unverified": not cleanup_verified,
        "manifest": _manifest("exec", sha, first, session, environment, duration),
    }
    if session and session.get("output_source") == "harness_stdout":
        observation["target_evidence"] = "harness_only"
    success = (expectations_satisfied(state, exit_code, signal_number, expected_exit,
                                      expected_signal, matches)
               and not errors and cleanup_verified and not output_limited)
    emit({"request_id": rid, "kind": "result", "observation": observation})
    return 0 if success else 1


class _SessionRuntime:
    """Mutable state for one debug/exec session, kept out of the protocol loop."""

    def __init__(self, first, sandbox, session, proc, mode, sha, duration_ms):
        self.first = first
        self.sandbox = sandbox
        self.session = session
        self.proc = proc
        self.mode = mode
        self.sha = sha
        self.duration_ms = duration_ms
        self.debug = mode == "debug"
        self.budget = OutputBudget(MAX_STREAM)
        self.reader = None
        self.stderr_reader = None
        self.mi = None
        if self.debug:
            self.mi = MIReader(proc.stdout)
            self.stderr_reader = ByteReader(proc.stderr, budget=self.budget)
        else:
            self.reader = ByteReader(proc.stdout, budget=self.budget)
            self.stderr_reader = ByteReader(proc.stderr, budget=self.budget)
        self.main_meta = session.get("target_metadata") or {}
        self.attached = session.get("attachments_by_container") or {}
        self.state = {
            "target_state": "ready" if self.debug else "running",
            "exit_code": None,
            "signal_name": None,
            "signal_number": None,
            "stop_info": None,
            "stop_snapshot": None,
            "stop_generation": 0,
            "last_error": None,
            "gdb_disable_randomization": None,
            "mi_async": None,
            "debug_setup": None,
            "debug_setup_error": None,
        }
        self.awaiting = {}
        self.pending = None
        self.observation_tx = None
        self.stdin_closed = False
        self.stop_requested = False
        self.stop_reply_sent = False
        self.final_reason = None
        self.errors = []
        self.token_counter = 0
        self.started = time.monotonic()
        self.mi_eof = False

    def send_mi(self, action, args=None, role=None):
        self.token_counter += 1
        token = str(self.token_counter)
        line = gdb_command(action, args or {}, token)
        if self.proc.stdin is None:
            raise ValueError("gdb control stream is unavailable")
        self.proc.stdin.write((line + "\n").encode("ascii"))
        self.proc.stdin.flush()
        self.awaiting[token] = {"action": action, "role": role, "done": False,
                                "values": None, "error": None, "record": None}
        return token

    def setup_debug(self, timeout=5.0):
        """Enable/verify GDB MI async before any execution command is allowed.

        A background Python reader alone does not make GDB asynchronous.  If
        ``set mi-async on`` or the follow-up ``show mi-async`` cannot be
        confirmed, the debug session is failed rather than advertised as
        interrupt-capable.
        """
        setup = {"mi_async_set": False, "mi_async": None, "aslr": None,
                 "ok": False, "error": None}
        if not self.debug:
            setup["ok"] = True
            self.state["debug_setup"] = setup
            return setup
        tokens = {}
        try:
            tokens["set_mi_async"] = self.send_mi("set_mi_async", {}, "set_mi_async")
            tokens["show_mi_async"] = self.send_mi("show_mi_async", {}, "show_mi_async")
            tokens["aslr_setting"] = self.send_mi("aslr_setting", {}, "aslr_setting")
        except Exception as exc:
            setup["error"] = "could not send MI setup commands: " + str(exc)
            self.state["debug_setup"] = setup
            self.state["debug_setup_error"] = setup["error"]
            return setup
        deadline = time.monotonic() + max(0.0, timeout)
        required_tokens = (tokens["set_mi_async"], tokens["show_mi_async"])
        while time.monotonic() < deadline:
            for record in self.mi.drain(limit=256):
                self.apply_record(record)
            if self.awaiting.get(tokens["set_mi_async"], {}).get("error"):
                break
            if all(self.awaiting.get(token, {}).get("done")
                   for token in required_tokens):
                break
            if self.mi.eof:
                break
            time.sleep(0.005)
        for record in self.mi.drain(limit=256):
            self.apply_record(record)
        set_entry = self.awaiting.get(tokens["set_mi_async"], {})
        show_entry = self.awaiting.get(tokens["show_mi_async"], {})
        aslr_entry = self.awaiting.get(tokens["aslr_setting"], {})
        if set_entry.get("error"):
            setup["error"] = "set mi-async failed: " + str(set_entry["error"])
        elif not set_entry.get("done"):
            setup["error"] = "set mi-async did not complete before timeout"
        if setup["error"] is None:
            if show_entry.get("error"):
                setup["error"] = "show mi-async failed: " + str(show_entry["error"])
            elif not show_entry.get("done"):
                setup["error"] = "show mi-async did not complete before timeout"
            else:
                show_values = show_entry.get("values")
                value = (show_values.get("value")
                         if isinstance(show_values, dict) else None)
                setup["mi_async"] = value
                normalized = str(value).strip().lower() if value is not None else ""
                if normalized not in ("on", "1", "true"):
                    setup["error"] = ("mi-async is not enabled (observed "
                                      + (repr(value) if value is not None else "no value") + ")")
                else:
                    setup["mi_async_set"] = True
        if not aslr_entry.get("error"):
            setup["aslr"] = self.state.get("gdb_disable_randomization")
        setup["ok"] = setup["error"] is None
        self.state["debug_setup"] = setup
        if not setup["ok"]:
            self.state["debug_setup_error"] = setup["error"]
        return setup

    def apply_record(self, record):
        if not isinstance(record, dict):
            return
        if record.get("kind") == "record":
            token = str(record.get("token", ""))
            if token and token in self.awaiting:
                entry = self.awaiting[token]
                entry["done"] = True
                entry["values"] = record.get("values")
                entry["error"] = record.get("error")
                entry["record"] = record
                if (self.observation_tx and token in self.observation_tx["tokens"]
                        and entry["role"]):
                    self.observation_tx["results"][entry["role"]] = entry["values"]
                if (self.pending is not None and entry["role"]
                        and entry.get("error") is None):
                    self.pending["results"][entry["role"]] = entry["values"]
                if entry.get("role") == "aslr_setting" and entry.get("values") is not None:
                    setting = entry["values"].get("value") if isinstance(entry["values"], dict) else None
                    if setting is not None:
                        self.state["gdb_disable_randomization"] = setting
                        if isinstance(self.state.get("debug_setup"), dict):
                            self.state["debug_setup"]["aslr"] = setting
                if entry.get("role") == "show_mi_async" and entry.get("values") is not None:
                    setting = entry["values"].get("value") if isinstance(entry["values"], dict) else None
                    if setting is not None:
                        self.state["mi_async"] = setting
            if (running_record(record)
                    or (record.get("record") == "^" and record.get("class") == "running")):
                self.state["target_state"] = "running"
                self.state["signal_name"] = None
                self.state["signal_number"] = None
                self.state["exit_code"] = None
                # Completed replies retain their own immutable-by-convention
                # snapshot; current state must not reuse historical crash data.
                self.state["stop_info"] = None
                self.state["stop_snapshot"] = None
                if self.observation_tx:
                    self.observation_tx["cancelled"] = True
                    self.observation_tx = None
            if record.get("record") == "*" and record.get("class") == "stopped":
                self._apply_stop(record)
        if record.get("kind") == "malformed":
            self.state["last_error"] = record.get("error")

    def _apply_stop(self, record):
        values = record.get("values") if isinstance(record.get("values"), dict) else {}
        reason = values.get("reason", "unknown")
        if reason in ("exited", "exited-normally"):
            self.state["target_state"] = "exit"
            self.state["exit_code"] = _exit_code_from_stop(values)
            self.state["signal_name"] = None
            self.state["signal_number"] = None
            self.state["stop_info"] = None
            self.state["stop_snapshot"] = None
            self.observation_tx = None
            self.state["stop_generation"] += 1
            return
        if reason == "exited-signal":
            self.state["target_state"] = "crashed"
            self.state["signal_name"] = values.get("signal-name")
            self.state["signal_number"] = _signal_number(values.get("signal-name"))
            self.state["exit_code"] = None
            self.state["stop_generation"] += 1
            return
        info = stop_values(record) or {"reason": reason}
        self.state["target_state"] = "stopped"
        self.state["exit_code"] = None
        self.state["stop_info"] = info
        self.state["signal_name"] = info.get("signal-name")
        self.state["signal_number"] = _signal_number(info.get("signal-name"))
        self.state["stop_generation"] += 1
        self.state["stop_snapshot"] = None
        self.start_observation()

    def start_observation(self):
        if not self.debug or self.state["target_state"] != "stopped":
            return
        if self.observation_tx:
            self.observation_tx["cancelled"] = True
        tx = {"tokens": [], "results": {}, "deadline": time.monotonic() + OBSERVATION_TIMEOUT,
              "cancelled": False}
        self.observation_tx = tx
        for action, role in (("register_names", "register_names"), ("registers", "registers"),
                             ("stack", "stack"), ("thread_groups", "thread_groups"),
                             ("modules", "modules")):
            try:
                token = self.send_mi(action, {"count": 16} if action == "stack" else {}, role)
            except Exception as exc:
                self.state["last_error"] = str(exc)
                continue
            tx["tokens"].append(token)

    def observation_done(self):
        tx = self.observation_tx
        if not tx:
            return True
        if tx.get("cancelled"):
            return True
        done = all(self.awaiting.get(token, {}).get("done") for token in tx["tokens"])
        return done or time.monotonic() >= tx["deadline"] or self.mi_eof

    def finish_observation(self):
        tx = self.observation_tx
        if not tx:
            return
        results = tx.get("results") or {}
        registers = _registers_from_results(results.get("register_names"), results.get("registers"))
        stack = _stack_from_result(results.get("stack"))
        shared = _shared_libraries_from_result(results.get("modules"))
        proc_maps = None
        pid = self._pid_from_thread_groups(results.get("thread_groups"))
        if pid:
            read_maps = getattr(self.sandbox, "read_inferior_maps", None)
            if callable(read_maps):
                try:
                    proc_maps = _parse_proc_maps(read_maps(self.session, pid))
                except Exception:
                    proc_maps = None
        self.state["stop_snapshot"] = _build_target_observation(
            self.sha, self.main_meta, self.attached, self.state.get("stop_info"),
            registers, stack, shared, proc_maps, self.debug)
        self.observation_tx = None

    def _pid_from_thread_groups(self, values):
        return _pid_from_groups(values)

    def collect_roles(self, tokens, roles):
        values = {}
        for token, role in roles.items():
            if token not in tokens:
                continue
            entry = self.awaiting.get(token)
            if entry and entry.get("done") and entry.get("error") is None:
                values[role] = entry.get("values")
        return values

    def target_observation(self, pending=None):
        if self.state.get("stop_snapshot"):
            return self.state["stop_snapshot"]
        registers = stack = shared = None
        proc_maps = None
        if pending:
            values = pending.get("results") or {}
            registers = _registers_from_results(values.get("register_names"), values.get("registers"))
            stack = _stack_from_result(values.get("stack"))
            shared = _shared_libraries_from_result(values.get("modules"))
        return _build_target_observation(
            self.sha, self.main_meta, self.attached, self.state.get("stop_info"),
            registers, stack, shared, proc_maps, self.debug)


def _debug_extras(pending, runtime):
    action = pending["action"]
    values = pending.get("results") or {}
    extras = {}
    if action == "registers":
        registers = _registers_from_results(values.get("register_names"), values.get("registers"))
        extras["registers"] = registers
    elif action == "register_names":
        extras["register_names"] = values.get("register_names", {}).get("register-names")
    elif action == "stack":
        extras["stack"] = _stack_from_result(values.get("stack"))
    elif action == "modules":
        shared = _shared_libraries_from_result(values.get("modules")) or []
        modules = []
        for library in shared:
            path = library.get("path")
            record = runtime.attached.get(path, {}) if path else {}
            modules.append({"module": path or "unknown", "path": path or "unknown",
                            "ranges": library.get("ranges", []),
                            "module_sha256": record.get("sha256"),
                            "module_build_id": record.get("build_id"),
                            "identity_known": bool(record.get("sha256") or record.get("build_id"))})
        extras["modules"] = modules
    elif action == "memory":
        memory_values = values.get("memory")
        if isinstance(memory_values, dict):
            rows = memory_values.get("memory")
        elif isinstance(memory_values, list):
            rows = memory_values
        else:
            rows = None
        data = b""
        invalid_contents = False
        truncated = False
        if isinstance(rows, list):
            for row in rows[:16]:
                if not isinstance(row, dict) or not isinstance(row.get("contents"), str):
                    continue
                try:
                    chunk = bytes.fromhex(row["contents"])
                except ValueError:
                    invalid_contents = True
                    continue
                remaining = MAX_IO - len(data)
                if remaining <= 0:
                    truncated = True
                    break
                data += chunk[:remaining]
                if len(chunk) > remaining:
                    truncated = True
                    break
        extras["address"] = pending.get("address")
        extras["bytes"] = len(data)
        extras["data_base64"] = encode(data)
        extras["memory_rows"] = len(rows) if isinstance(rows, list) else 0
        extras["invalid_contents"] = invalid_contents
        extras["truncated"] = truncated
    elif action in ("core", "core_snapshot"):
        core = runtime.sandbox.capture_core(runtime.session)
        runtime.session["core_meta"] = core
        extras["core"] = core
    elif action == "aslr_setting":
        setting = values.get("aslr_setting")
        value = setting.get("value") if isinstance(setting, dict) else setting
        extras["disable_randomization"] = value
        runtime.state["gdb_disable_randomization"] = value
    elif action == "breakpoint":
        breakpoint_values = values.get("breakpoint")
        extras["breakpoint"] = (breakpoint_values.get("bkpt")
                                if isinstance(breakpoint_values, dict) else None)
    return extras


def _complete_pending(runtime, pending, outcome, error=None):
    records = pending.get("records", [])[-MAX_MI_RESPONSE_RECORDS:]
    raw = b"\n".join(record.get("raw", "").encode("utf-8", "replace")
                     for record in records if record.get("raw"))
    extras = {}
    if error is None:
        try:
            extras = _debug_extras(pending, runtime)
        except Exception as exc:
            error = str(exc)
    observation = {"action": pending["action"],
                   "target_state": runtime.state["target_state"],
                   "state_source": "mi_async_record",
                   "records": records, "raw_base64": encode(raw),
                   "records_truncated": bool(pending.get("records_truncated")),
                   "eof": runtime.mi_eof, "timed_out": outcome == "timeout",
                   "target_observation": runtime.target_observation(pending),
                   **extras}
    if error is not None:
        observation["error"] = error
    reply = {"request_id": pending["request_id"], "kind": "result",
             "observation": observation}
    reply["_cache_key"] = (pending["request_id"], pending["fingerprint"])
    runtime.pending = None
    return reply


def _pending_progress(runtime, pending):
    now = time.monotonic()
    required = pending.get("required") or []
    for token in required:
        entry = runtime.awaiting.get(token)
        if entry and entry.get("error"):
            return True, "error", str(entry["error"])
    if pending.get("wait_stop"):
        if runtime.state["stop_generation"] > pending["start_generation"]:
            return True, "ok", None
        if runtime.state["target_state"] in ("exit", "crashed"):
            return True, "ok", None
        if runtime.state["target_state"] == "failed":
            return True, "error", runtime.state.get("last_error") or "target failed"
    else:
        if required and all(runtime.awaiting.get(token, {}).get("done") for token in required):
            return True, "ok", None
        if not required:
            return True, "ok", None
    if runtime.mi_eof:
        return True, "error", "gdb stream closed before response"
    if now >= pending["deadline"]:
        if pending.get("wait_stop") and runtime.state["target_state"] in ("running", "ready", "unknown"):
            if pending["action"] == "interrupt":
                return True, "error", "interrupt did not produce a stop"
            return True, "timeout", None
        return True, "error", "debugger response timed out"
    return False, None, None


def _start_pending(runtime, request_id, fingerprint, action, command_args, timeout_ms):
    pending = {"request_id": request_id, "fingerprint": fingerprint, "action": action,
               "records": [], "record_bytes": 0, "records_truncated": False,
               "required": [], "results": {}, "roles": {},
               "start_generation": runtime.state["stop_generation"],
               "started": time.monotonic(),
               "deadline": time.monotonic() + timeout_ms / 1000,
               "wait_stop": action in ("run", "start", "continue", "step", "interrupt"),
               "address": command_args.get("address") if isinstance(command_args, dict) else None}
    send = []
    if action in ("run", "start", "continue", "step", "interrupt"):
        send.append((action, {}, "command"))
    elif action == "registers":
        send += [("register_names", {}, "register_names"), ("registers", {}, "registers")]
    elif action == "register_names":
        send.append(("register_names", {}, "register_names"))
    elif action == "stack":
        send.append(("stack", {"count": command_args.get("count", 16)}, "stack"))
    elif action == "memory":
        send.append(("memory", {"address": command_args.get("address"),
                                "length": command_args.get("length")}, "memory"))
    elif action == "modules":
        send += [("thread_groups", {}, "thread_groups"), ("modules", {}, "modules")]
    elif action == "breakpoint":
        send.append(("breakpoint", {"address": command_args.get("address")}, "breakpoint"))
    elif action in ("core", "core_snapshot"):
        send.append(("core", {}, "core"))
    elif action == "aslr_setting":
        send.append(("aslr_setting", {}, "aslr_setting"))
    else:
        raise ValueError("unsupported debug action")
    for name, args, role in send:
        token = runtime.send_mi(name, args, role)
        pending["required"].append(token)
        pending["roles"][token] = role
    runtime.pending = pending
    return pending


def _serve_session(first, inp, sandbox, emit):
    rid = first.get("request_id", "start")
    session = None
    runtime = None
    session_id = None
    mode = first.get("mode", "exec")
    sha = None
    errors = []
    incoming = queue.Queue()

    def control_reader():
        while True:
            try:
                frame = read_frame(inp)
                incoming.put(frame)
            except Exception as exc:
                incoming.put(exc)
                return
            if frame is None:
                return

    threading.Thread(target=control_reader, daemon=True).start()
    event_seq_cache = {}
    sent = {}
    request_hashes = {}
    sent_size = 0
    deferred = []

    def emit_pending(outcome, error):
        nonlocal sent_size
        if runtime is None or runtime.pending is None:
            return
        reply = _complete_pending(runtime, runtime.pending, outcome, error)
        fingerprint = reply.pop("_cache_key")[1]
        pending_id = reply.get("request_id")
        _cache_reply(sent, request_hashes, reply, fingerprint, sent_size, emit)
        sent_size += len(json.dumps(reply, separators=(",", ":")).encode("utf-8"))
        if pending_id:
            event_seq_cache.pop(pending_id, None)
    try:
        artifact = first.get("artifact_path")
        argv = first.get("argv", [])
        mode = first.get("mode", "exec")
        duration = first.get("duration_ms", 900000)
        if not isinstance(argv, list) or len(argv) > 64 or any(
                not isinstance(x, str) or len(x) > 4096 for x in argv):
            raise ValueError("argv must be at most 64 strings")
        if mode not in ("exec", "debug"):
            raise ValueError("mode must be exec or debug")
        if isinstance(duration, bool) or not isinstance(duration, int) or duration < 1:
            raise ValueError("duration_ms must be positive")
        duration = min(duration, 900000)
        lease_ms = first.get("lease_ms", 30000)
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not 1000 <= lease_ms <= MAX_LEASE_MS:
            raise ValueError(f"lease_ms outside 1000..{MAX_LEASE_MS}")
        lease_deadline = time.monotonic() + lease_ms / 1000
        input_mode = first.get("input_mode", "stdin")
        if input_mode not in ("stdin", "file"):
            raise ValueError("input_mode must be stdin or file")
        validate_argv(argv, input_mode)
        initial_input = base64.b64decode(first.get("input_base64", "") or "", validate=True)
        if len(initial_input) > MAX_IO:
            raise ValueError("input exceeds 65536-byte limit")
        if mode == "debug" and initial_input:
            raise ValueError("debug mode does not accept target stdin input; GDB owns the control input")
        sha = sandbox.inspect_elf(artifact)
        if sha.lower() != str(first.get("sha256", "")).lower():
            raise ValueError("artifact SHA-256 mismatch")
        prof = profile_settings(first.get("profile"))
        target = first.get("target") or {}
        session = sandbox.start(artifact, sha, argv, mode, prof, duration, target,
                                input_mode, initial_input)
        proc = session["process"]
        runtime = _SessionRuntime(first, sandbox, session, proc, mode, sha, duration)
        session_id = uuid.uuid4().hex
        debug_setup = None
        if mode == "debug":
            debug_setup = runtime.setup_debug()
            if not debug_setup.get("ok"):
                errors.append("GDB mi-async setup failed: "
                              + str(debug_setup.get("error") or "unknown"))
                runtime.state["target_state"] = "failed"
                runtime.final_reason = "debug_setup_failed"
        if mode != "debug":
            try:
                if initial_input and input_mode == "stdin":
                    write_bounded(proc.stdin, initial_input)
            except BrokenPipeError:
                pass
            except Exception as exc:
                errors.append("input delivery failed: " + str(exc))
            if input_mode == "file":
                try:
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()
                except Exception:
                    pass
        environment = _environment_manifest(sandbox, prof.get("image"))
        # The lease is measured from the ready frame, not from image probing.
        lease_deadline = time.monotonic() + lease_ms / 1000
        observation = {"engine": "docker-native", "platform": "linux/x86_64",
                       "artifact_sha256": sha, "protocol_version": PROTOCOL_VERSION,
                       "mode": mode, "session_id": session_id, "lease_ms": lease_ms,
                       "lease_deadline_ms": int(time.time() * 1000 + lease_ms),
                       "target_elf": session.get("target_metadata"),
                       "attached_artifacts": session.get("attached_artifacts", []),
                       "output_source": session.get("output_source", "target_stdout"),
                       "output_trusted": bool(session.get("output_trusted", True)),
                       "target_state_source": ("harness_process"
                                               if session.get("output_source") == "harness_stdout"
                                               else "target_process"),
                       "target_exit_trusted": session.get("output_source") != "harness_stdout",
                       "input_mode": input_mode,
                       "aslr": "enabled" if mode == "debug" else "not_applicable",
                       **({"debug_setup": debug_setup,
                           "debug_available": bool(debug_setup and debug_setup.get("ok"))}
                          if mode == "debug" else {}),
                       "environment": environment,
                       "manifest": _manifest(mode, sha, first, session, environment, duration)}
        emit({"request_id": rid, "kind": "ready", "observation": observation})
        while True:
            now = time.monotonic()
            if runtime.mi:
                events = runtime.mi.drain(limit=256)
                for record in events:
                    if runtime.pending is not None:
                        raw_length = len(record.get("raw", ""))
                        if runtime.pending["record_bytes"] + raw_length <= 1024 * 1024:
                            runtime.pending["records"].append(record)
                            runtime.pending["record_bytes"] += raw_length
                        else:
                            runtime.pending["records_truncated"] = True
                    runtime.apply_record(record)
                runtime.mi_eof = runtime.mi.eof
                if runtime.mi.error and not errors:
                    errors.append("gdb MI reader failed: " + str(runtime.mi.error))
            if runtime.observation_tx and runtime.observation_done():
                runtime.finish_observation()
            if runtime.pending is not None:
                done, outcome, error = _pending_progress(runtime, runtime.pending)
                if done:
                    emit_pending(outcome, error)
                    if runtime.state["target_state"] in ("exit", "crashed"):
                        break
            if runtime.debug:
                if runtime.state["target_state"] == "exit" and runtime.pending is None:
                    break
                if runtime.state["target_state"] == "crashed" and runtime.pending is None:
                    break
            else:
                code = proc.poll()
                if code is not None:
                    try:
                        proc.wait(timeout=.2)
                    except Exception:
                        pass
                    runtime.state["target_state"], runtime.state["signal_number"] = classify_exit_code(code)
                    if code >= 0:
                        runtime.state["exit_code"] = code
                    else:
                        # Negative Popen status describes the host Docker CLI,
                        # not the inferior. Do not fabricate target crash evidence.
                        runtime.state["target_state"] = "failed"
                        runtime.state["signal_number"] = None
                        runtime.state["exit_code"] = None
                        runtime.state["docker_client_exit_code"] = code
                        runtime.final_reason = "docker_client_terminated"
                        errors.append("Docker client terminated by signal")
                    # Drain the reader before the final observation.
                    deadline = time.monotonic() + 0.5
                    while not runtime.reader.eof and time.monotonic() < deadline:
                        runtime.reader.recv(MAX_IO, 0.02)
                    break
            if runtime.state["target_state"] in ("ready", "running", "stopped"):
                if (runtime.debug and proc.poll() is not None and runtime.mi_eof
                        and not events):
                    # A stop may have occurred earlier; it does not prove that
                    # the inferior exited. Drain all queued MI batches first so
                    # an exited record racing debugger EOF wins over failure.
                    runtime.state["target_state"] = "failed"
                    runtime.final_reason = "debugger_exited_without_target_exit"
                    errors.append("GDB process exited before reporting target termination")
                    break
                if now >= session["deadline"]:
                    runtime.state["target_state"] = "timeout"
                    runtime.final_reason = "duration_timeout"
                    break
                if now >= lease_deadline:
                    runtime.state["target_state"] = "cancelled"
                    runtime.final_reason = "lease_expired"
                    break
            if runtime.stop_requested and runtime.pending is None and runtime.observation_tx is None:
                if runtime.state["target_state"] == "stopped":
                    runtime.state["target_state"] = ("crashed" if runtime.state["signal_number"]
                                                     else "cancelled")
                break
            if runtime.state["target_state"] in ("timeout", "cancelled", "failed", "cleanup_unverified"):
                break
            try:
                if runtime.pending is not None:
                    try:
                        frame = incoming.get_nowait()
                    except queue.Empty:
                        frame = _NO_FRAME
                    if isinstance(frame, dict) and frame.get("cancel") is True:
                        runtime.state["target_state"] = "cancelled"
                        runtime.final_reason = "cancel"
                        break
                    if isinstance(frame, dict) and frame.get("action") in ("heartbeat", "status"):
                        pass
                    elif frame is not _NO_FRAME:
                        command = frame.get("command") if isinstance(frame, dict) else None
                        command_action = command.get("action") if isinstance(command, dict) else None
                        execution_pending = (runtime.pending is not None
                                             and runtime.pending.get("action") in
                                             ("run", "start", "continue", "step"))
                        if (isinstance(frame, dict) and not deferred and execution_pending
                                and command_action == "interrupt"):
                            # A caller must be able to interrupt a long-running
                            # execution request; only do so when no earlier
                            # deferred requests are queued.
                            emit_pending("ok", None)
                            deferred.insert(0, frame)
                            frame = _NO_FRAME
                        elif frame is None and not deferred:
                            # Owner EOF must not wait for a long execution
                            # timeout when nothing else is queued.
                            emit_pending("ok", None)
                            deferred.insert(0, frame)
                            frame = _NO_FRAME
                        else:
                            if len(deferred) >= 512:
                                errors.append("control frame backlog exceeded")
                                runtime.state["target_state"] = "failed"
                                break
                            deferred.append(frame)
                            frame = _NO_FRAME
                elif deferred:
                    frame = deferred.pop(0)
                else:
                    frame = incoming.get(timeout=0.02)
            except queue.Empty:
                frame = _NO_FRAME
            if frame is _NO_FRAME:
                continue
            if isinstance(frame, Exception):
                errors.append("invalid control frame: " + str(frame))
                runtime.state["target_state"] = "failed"
                break
            if frame is None:
                if runtime.stop_requested and runtime.observation_tx is not None:
                    # A stop request is collecting final debugger evidence;
                    # finish that bounded collection before honoring EOF.
                    continue
                if runtime.state["target_state"] in ("exit", "crashed"):
                    break
                runtime.state["target_state"] = "cancelled"
                runtime.final_reason = "owner_eof"
                break
            if not isinstance(frame, dict):
                emit({"request_id": "invalid", "kind": "result",
                      "observation": {"error": "control frame must be an object"}})
                continue
            if frame.get("cancel") is True:
                runtime.state["target_state"] = "cancelled"
                runtime.final_reason = "cancel"
                if runtime.debug and runtime.state["target_state"] == "running":
                    try:
                        runtime.send_mi("interrupt", {}, "cancel")
                    except Exception:
                        pass
                break
            request_id = frame.get("request_id")
            if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
                emit({"request_id": "invalid", "kind": "result",
                      "observation": {"error": "request_id is required"}})
                continue
            fingerprint = hashlib.sha256(json.dumps(frame, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if request_id in sent:
                if request_hashes[request_id] != fingerprint:
                    emit({"request_id": request_id, "kind": "result",
                          "observation": {"error": "request_id was reused with different input"}})
                else:
                    replay = dict(sent[request_id])
                    replay.pop("event_seq", None)
                    emit(replay)
                continue
            if request_id in event_seq_cache:
                if event_seq_cache[request_id] != fingerprint:
                    emit({"request_id": request_id, "kind": "result",
                          "observation": {"error": "request_id was reused with different input"}})
                else:
                    emit({"request_id": request_id, "kind": "result",
                          "observation": {"error": "request already in progress"}})
                continue
            action = frame.get("action")
            reply = {"request_id": request_id, "kind": "result", "observation": {}}
            if action != "heartbeat" and (
                    len(sent) >= MAX_CACHE_ITEMS
                    or sent_size > MAX_CACHE_BYTES - 2 * MAX_IO):
                emit({"request_id": request_id, "kind": "result",
                      "observation": {"error": "session request cache limit reached"}})
                continue
            try:
                validate_session_action(action, mode)
                if action == "send":
                    if runtime.stdin_closed:
                        raise ValueError("target stdin is closed")
                    data = base64.b64decode(frame.get("data_base64", ""), validate=True)
                    if len(data) > MAX_IO:
                        raise ValueError("send exceeds 65536-byte limit")
                    write_bounded(proc.stdin, data)
                    reply["observation"] = {"accepted_bytes": len(data)}
                elif action == "close_stdin":
                    # Close only the inferior stdin, not the owner's JSONL
                    # control stream. Repeats are harmless, including new IDs.
                    if not runtime.stdin_closed:
                        if proc.stdin is not None and not proc.stdin.closed:
                            proc.stdin.close()
                        runtime.stdin_closed = True
                    reply["observation"] = {"stdin_closed": True}
                elif action == "recv":
                    if mode == "debug":
                        raise ValueError("target stdout is not available in debug mode")
                    limit = frame.get("max_bytes", MAX_IO)
                    timeout = frame.get("timeout_ms", 1000)
                    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_IO:
                        raise ValueError("max_bytes outside 1..65536")
                    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 30000:
                        raise ValueError("timeout_ms outside 0..30000")
                    which = frame.get("stream", "stdout")
                    if which not in ("stdout", "stderr"):
                        raise ValueError("stream must be stdout or stderr")
                    selected = runtime.reader if which == "stdout" else runtime.stderr_reader
                    consumed = (_consumed(runtime, which))
                    cursor = frame.get("cursor", consumed)
                    if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor != consumed:
                        raise ValueError("stream cursor mismatch")
                    remaining = max(0, MAX_STREAM - consumed)
                    data, eof = selected.recv(min(limit, remaining), timeout / 1000)
                    if which == "stdout":
                        runtime.out_bytes += len(data)
                    else:
                        runtime.stderr_out_bytes += len(data)
                    consumed = _consumed(runtime, which)
                    reply["observation"] = {"stream": which, "cursor": consumed,
                                            "data_base64": encode(data), "bytes": len(data),
                                            "eof": eof, "truncated": selected.truncated,
                                            "stream_bytes_total": selected.bytes_seen,
                                            "budget_remaining": runtime.budget.remaining}
                elif action == "heartbeat":
                    hb = frame.get("lease_ms", lease_ms)
                    if isinstance(hb, bool) or not isinstance(hb, int) or not 1000 <= hb <= MAX_LEASE_MS:
                        raise ValueError(f"heartbeat lease_ms outside 1000..{MAX_LEASE_MS}")
                    lease_ms = hb
                    lease_deadline = time.monotonic() + lease_ms / 1000
                    reply["observation"] = {"lease_ms": lease_ms,
                                            "lease_deadline_ms": int(time.time() * 1000 + lease_ms),
                                            "session_id": session_id}
                    # Heartbeats deliberately bypass the request cache.
                    reply["_no_cache"] = True
                elif action == "status":
                    state_signal = (runtime.state["signal_name"] if runtime.debug
                                    else _signal_name(runtime.state["signal_number"]))
                    reply["observation"] = {"target_state": runtime.state["target_state"],
                                            "exit_code": runtime.state["exit_code"],
                                            "signal": state_signal,
                                            "signal_number": runtime.state["signal_number"],
                                            "core": session.get("core_meta"),
                                            "lease_deadline_ms": int(time.time() * 1000 + max(
                                                0, lease_deadline - time.monotonic()) * 1000),
                                            "output_budget_remaining": runtime.budget.remaining,
                                            "target_observation": runtime.state.get("stop_snapshot")}
                elif action == "stop":
                    if runtime.debug and runtime.state["target_state"] == "stopped":
                        runtime.stop_requested = True
                        reply["observation"] = {"stopping": True,
                                                "target_state": runtime.state["target_state"]}
                        if runtime.state.get("stop_snapshot") is None and runtime.observation_tx is None:
                            runtime.start_observation()
                        if runtime.mi_eof and runtime.observation_tx is not None:
                            runtime.finish_observation()
                        if runtime.state.get("stop_snapshot") is not None and runtime.observation_tx is None:
                            runtime.state["target_state"] = ("crashed"
                                                             if runtime.state["signal_number"]
                                                             else "cancelled")
                            runtime.stop_requested = False
                    elif runtime.state["target_state"] in ("exit", "crashed"):
                        pass
                    else:
                        if runtime.debug and runtime.state["target_state"] in ("running", "ready"):
                            try:
                                runtime.send_mi("interrupt", {}, "stop")
                            except Exception:
                                pass
                        runtime.state["target_state"] = "cancelled"
                        runtime.final_reason = "stop"
                    reply["observation"]["target_state"] = runtime.state["target_state"]
                elif action == "core_read":
                    if mode != "debug":
                        raise ValueError("core_read is available only in debug mode")
                    if runtime.state["target_state"] != "stopped":
                        raise ValueError("core is available only while the target is stopped")
                    offset = frame.get("offset")
                    length = frame.get("length", MAX_IO)
                    data = sandbox.read_core(session, offset, length)
                    meta = session.get("core_meta") or {}
                    reply["observation"] = {"core": meta, "offset": offset,
                                            "data_base64": encode(data), "bytes": len(data),
                                            "eof": offset + len(data) >= meta.get("size", 0)}
                elif action == "debug":
                    if mode != "debug":
                        raise ValueError("debug action is available only in debug mode")
                    extra_fields = set(frame) - {"request_id", "action", "command", "timeout_ms"}
                    if extra_fields:
                        raise ValueError("unsupported debug request field(s): "
                                         + ", ".join(sorted(map(str, extra_fields))))
                    command = frame.get("command")
                    if not isinstance(command, dict):
                        raise ValueError("debug command must be an object")
                    debug_action = command.get("action")
                    if runtime.pending is not None:
                        raise ValueError("another debug command is still in progress")
                    # Validate the closed typed schema before constructing the
                    # transaction, so unknown address/pid/console fields are
                    # rejected rather than silently dropped.
                    gdb_command(debug_action, {key: value for key, value in command.items()
                                               if key != "action"})
                    state = runtime.state["target_state"]
                    if debug_action in ("run", "start", "continue", "step"):
                        if state not in ("ready", "stopped"):
                            raise ValueError(f"target is {state}; cannot start execution")
                    elif debug_action == "interrupt":
                        if state not in ("running", "ready"):
                            raise ValueError(f"target is {state}; interrupt requires a running target")
                    elif debug_action in ("registers", "register_names", "stack", "memory",
                                           "modules", "core", "core_snapshot"):
                        if state != "stopped":
                            raise ValueError(f"target is {state}; debugger state is available only while stopped")
                    timeout_ms = frame.get("timeout_ms", 3000)
                    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 0 <= timeout_ms <= 30000:
                        raise ValueError("timeout_ms outside 0..30000")
                    pending = _start_pending(runtime, request_id, fingerprint,
                                             debug_action, command, timeout_ms)
                    event_seq_cache[request_id] = fingerprint
                    sent.pop(request_id, None)
                    continue
                else:
                    raise ValueError("unsupported action for session mode")
            except Exception as exc:
                reply["observation"] = {"error": str(exc)}
                if isinstance(exc, TimeoutError):
                    errors.append(str(exc))
            if reply.get("_no_cache"):
                reply.pop("_no_cache", None)
                emit(reply)
                continue
            if len(sent) >= MAX_CACHE_ITEMS:
                reply = {"request_id": request_id, "kind": "result",
                         "observation": {"error": "session request limit reached"}}
            encoded_reply = json.dumps(reply, separators=(",", ":"), ensure_ascii=True)
            reply_size = len(encoded_reply.encode("utf-8"))
            if sent_size + reply_size > MAX_CACHE_BYTES:
                reply = {"request_id": request_id, "kind": "result",
                         "observation": {"error": "session response cache limit reached"}}
                encoded_reply = json.dumps(reply, separators=(",", ":"), ensure_ascii=True)
                reply_size = len(encoded_reply.encode("utf-8"))
            sent[request_id] = reply
            request_hashes[request_id] = fingerprint
            sent_size += reply_size
            emit(reply)
            if runtime.state["target_state"] == "cancelled" and runtime.final_reason == "stop":
                break
    except Exception as exc:
        errors.append(str(exc))
        if runtime:
            runtime.state["target_state"] = "failed"
    if runtime:
        if runtime.pending is not None:
            pending = runtime.pending
            done, outcome, error = _pending_progress(runtime, pending)
            if not done:
                outcome, error = "error", "session terminated before debugger response"
            reply = _complete_pending(runtime, pending, outcome, error)
            fingerprint = reply.pop("_cache_key")[1]
            sent[pending["request_id"]] = reply
            request_hashes[pending["request_id"]] = fingerprint
            emit(reply)
            runtime.pending = None
        if runtime.observation_tx:
            runtime.finish_observation()
        if runtime.state["target_state"] in ("running", "ready"):
            runtime.state["target_state"] = "cancelled"
            runtime.final_reason = runtime.final_reason or "session_closed"
        if runtime.debug and runtime.state["target_state"] == "stopped":
            runtime.state["target_state"] = ("crashed" if runtime.state["signal_number"]
                                             else "cancelled")
            runtime.final_reason = runtime.final_reason or "session_closed"
    cleanup, cleanup_verified = _cleanup_result(sandbox, session, errors)
    if runtime:
        _settle_reader(runtime.stderr_reader)
        if runtime.mi and runtime.mi.error:
            errors.append("gdb MI reader failed: " + str(runtime.mi.error))
    state = runtime.state["target_state"] if runtime else "failed"
    if (runtime and runtime.debug and not runtime.state.get("stop_snapshot")
            and (runtime.state.get("debug_setup") or {}).get("ok")):
        runtime.state["stop_snapshot"] = _build_target_observation(
            sha, runtime.main_meta, runtime.attached, runtime.state.get("stop_info"),
            None, None, None, None, True)
    output_limited = bool(runtime and (runtime.budget.truncated or
                                       (runtime.reader and runtime.reader.truncated)))
    if cleanup_verified:
        if state == "timeout":
            outcome = "timeout"
        elif state == "cancelled":
            outcome = "cancelled"
        elif output_limited:
            outcome = "limited"
        else:
            outcome = state
    else:
        outcome = "cleanup_unverified"
    environment = _environment_manifest(sandbox, profile_settings(first.get("profile") or {}).get("image"))
    if runtime and runtime.debug:
        output = {"source": "target_stdout", "captured_bytes": 0, "bytes_seen": 0,
                  "tail_base64": "", "tail_bytes": 0, "tail_truncated": False,
                  "sha256": hashlib.sha256(b"").hexdigest(),
                  "summary": "inferior stdout is /dev/null in debug mode; GDB MI is kept separate"}
        mi_summary = {"bytes_seen": runtime.mi.bytes_seen if runtime.mi else 0,
                      "records_seen": runtime.mi.records_seen if runtime.mi else 0,
                      "truncated": bool(runtime.mi and runtime.mi.truncated),
                      "eof": bool(runtime.mi and runtime.mi.eof)}
    else:
        reader = runtime.reader if runtime else None
        output = {"source": session.get("output_source", "target_stdout") if session else "target_stdout",
                  "captured_bytes": reader.accepted if reader else 0,
                  "bytes_seen": reader.bytes_seen if reader else 0,
                  "tail_base64": encode(reader.tail if reader else b""),
                  "tail_bytes": len(reader.tail) if reader else 0,
                  "tail_truncated": bool(reader and (reader.truncated or reader.accepted > len(reader.tail))),
                  "sha256": reader.hasher.hexdigest() if reader else None,
                  "truncated": bool(reader and reader.truncated),
                  "dropped_bytes": reader.dropped if reader else 0,
                  "budget_remaining": runtime.budget.remaining if runtime else MAX_STREAM,
                  "summary": "tail bytes are captured automatically; earlier bytes are available through recv frames"}
        mi_summary = None
    observation = {
        "target_state": state, "outcome": outcome, "terminal_state": state,
        "exit_code": runtime.state["exit_code"] if runtime else None,
        "signal": (runtime.state["signal_name"] if runtime and runtime.debug
                   else runtime.state["signal_number"] if runtime else None),
        "signal_number": runtime.state["signal_number"] if runtime else None,
        "signal_source": ("debugger" if runtime and runtime.debug
                          and (runtime.state.get("debug_setup") or {}).get("ok")
                          else "debugger_unavailable" if runtime and runtime.debug
                          else "docker_client_signal" if runtime and runtime.state.get("docker_client_exit_code") is not None
                          else "docker_exit_status_convention"),
        "docker_client_exit_code": runtime.state.get("docker_client_exit_code") if runtime else None,
        "target_state_source": ("debugger" if runtime and runtime.debug
                                and (runtime.state.get("debug_setup") or {}).get("ok")
                                else "debugger_unavailable" if runtime and runtime.debug
                                else "docker_client" if runtime and runtime.state.get("docker_client_exit_code") is not None
                                else "harness_process" if session and session.get("output_source") == "harness_stdout"
                                else "target_process"),
        "target_exit_trusted": (not bool(session and session.get("output_source") == "harness_stdout")
                                and not bool(runtime and runtime.state.get("docker_client_exit_code") is not None)),
        "reason": runtime.final_reason if runtime else None,
        "session_id": session_id if runtime else None,
        "output": output,
        "stderr": _stderr_summary(runtime.stderr_reader if runtime else None),
        "mi": mi_summary,
        "core": session.get("core_meta") if session else None,
        "cleanup": cleanup, "cleanup_verified": cleanup_verified,
        "cleanup_unverified": not cleanup_verified,
        "output_limited": output_limited,
        "errors": errors,
        "target_observation": (runtime.state.get("stop_snapshot") if runtime else None),
        "aslr": "enabled" if runtime and runtime.debug else "not_applicable",
        **({"debug_setup": runtime.state.get("debug_setup"),
            "debug_available": bool(runtime.state.get("debug_setup")
                                    and runtime.state["debug_setup"].get("ok"))}
           if runtime and runtime.debug else {}),
        "manifest": _manifest(mode, sha if runtime else first.get("sha256"), first, session,
                              environment, runtime.duration_ms if runtime else None),
        "environment": environment,
    }
    if runtime and runtime.state.get("gdb_disable_randomization") is not None:
        observation["gdb_disable_randomization"] = runtime.state["gdb_disable_randomization"]
    if session and session.get("output_source") == "harness_stdout":
        observation["target_evidence"] = "harness_only"
    success = (state in ("exit", "crashed", "cancelled") and not errors
               and cleanup_verified and not output_limited)
    emit({"request_id": "final", "kind": "final", "observation": observation})
    return 0 if success else 1


_NO_FRAME = object()


def _consumed(runtime, which):
    if not hasattr(runtime, "out_bytes"):
        runtime.out_bytes = 0
        runtime.stderr_out_bytes = 0
    return runtime.out_bytes if which == "stdout" else runtime.stderr_out_bytes


def _cache_reply(sent, request_hashes, reply, fingerprint, sent_size, emit):
    request_id = reply["request_id"]
    reply.pop("_cache_key", None)
    if reply.get("_no_cache"):
        reply.pop("_no_cache", None)
        emit(reply)
        return
    sent[request_id] = reply
    request_hashes[request_id] = fingerprint
    emit(reply)

if __name__ == "__main__":
    try:
        raise SystemExit(serve())
    except Exception as exc:
        # Never dump env, locals, or tracebacks to the protocol channel.
        sys.stderr.write("native runner: " + str(exc).replace("\n", " ") + "\n")
        raise SystemExit(2)
