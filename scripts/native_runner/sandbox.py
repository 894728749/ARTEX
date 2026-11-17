"""Docker-only containment, fixed-layout staging, and owned cleanup."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .elf import inspect_elf, safe_basename

MAX_ARTIFACT = 64 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
MAX_MAPS_BYTES = 4 * 1024 * 1024
_ENV_ALLOWLIST = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
                  "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT", "DOCKER_API_VERSION",
                  "XDG_RUNTIME_DIR", "LANG", "LC_ALL")


def docker_environment():
    """Only pass Docker client settings, never the caller's secret environment."""
    env = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def normalize_target(target):
    """Validate the closed target attachment schema; reject unknown fields."""
    if target is None:
        target = {}
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    unknown = set(target) - {"dependencies", "loader", "harness"}
    if unknown:
        raise ValueError("unsupported target field(s): " + ", ".join(sorted(map(str, unknown))))
    dependencies = target.get("dependencies", [])
    if not isinstance(dependencies, list) or len(dependencies) > 32:
        raise ValueError("target.dependencies must be a list of at most 32 items")
    normalized_dependencies = []
    for dep in dependencies:
        if not isinstance(dep, dict):
            raise ValueError("target.dependencies items must be objects")
        extra = set(dep) - {"artifact_path", "sha256", "name"}
        if extra:
            raise ValueError("unsupported dependency field(s): " + ", ".join(sorted(map(str, extra))))
        if not isinstance(dep.get("artifact_path"), str) or not dep["artifact_path"]:
            raise ValueError("dependency artifact_path is required")
        if not isinstance(dep.get("sha256"), str):
            raise ValueError("dependency sha256 is required")
        normalized_dependencies.append({"artifact_path": dep["artifact_path"],
                                        "sha256": dep["sha256"],
                                        "name": safe_basename(dep.get("name"))})
    loader = target.get("loader")
    if loader is not None:
        if not isinstance(loader, dict):
            raise ValueError("target.loader must be an object")
        extra = set(loader) - {"artifact_path", "sha256", "name"}
        if extra:
            raise ValueError("unsupported loader field(s): " + ", ".join(sorted(map(str, extra))))
        if not isinstance(loader.get("artifact_path"), str) or not loader["artifact_path"]:
            raise ValueError("loader artifact_path is required")
        if not isinstance(loader.get("sha256"), str):
            raise ValueError("loader sha256 is required")
        loader = {"artifact_path": loader["artifact_path"], "sha256": loader["sha256"],
                  "name": safe_basename(loader.get("name"))}
    harness = target.get("harness")
    if harness is not None:
        if not isinstance(harness, dict):
            raise ValueError("target.harness must be an object")
        extra = set(harness) - {"artifact_path", "sha256", "language"}
        if extra:
            raise ValueError("unsupported harness field(s): " + ", ".join(sorted(map(str, extra))))
        if not isinstance(harness.get("artifact_path"), str) or not harness["artifact_path"]:
            raise ValueError("harness artifact_path is required")
        if not isinstance(harness.get("sha256"), str):
            raise ValueError("harness sha256 is required")
        if harness.get("language") != "python":
            raise ValueError("only Python harnesses are supported")
        harness = {"artifact_path": harness["artifact_path"], "sha256": harness["sha256"],
                   "language": "python"}
    return {"dependencies": normalized_dependencies, "loader": loader, "harness": harness}


def validate_argv(argv, input_mode):
    if not isinstance(argv, list) or len(argv) > 64:
        raise ValueError("argv must be at most 64 strings")
    for item in argv:
        if not isinstance(item, str) or len(item) > 4096:
            raise ValueError("argv must be at most 64 strings")
    placeholders = [item for item in argv if item == "{input}"]
    if input_mode == "file":
        if not placeholders:
            raise ValueError("file input mode requires an argv element exactly '{input}'")
    elif placeholders:
        raise ValueError("'{input}' is only valid in file input mode")
    return list(argv)


class DockerSandbox:
    def __init__(self, docker="docker", popen=subprocess.Popen, run=subprocess.run):
        self.docker, self._popen, self._run = docker, popen, run
        self._versions_cache = {}
        self._versions_lock = threading.Lock()

    def inspect_elf(self, path):
        return inspect_elf(path)["sha256"]

    def _checked(self, path, expected, label, elf=True):
        if not isinstance(path, str) or not path:
            raise ValueError(f"{label} artifact_path is required")
        p = Path(path)
        if not p.is_file():
            raise ValueError(f"{label} artifact_path is not a regular file")
        size = p.stat().st_size
        if size > MAX_ARTIFACT:
            raise ValueError(f"{label} exceeds 64 MiB")
        if elf:
            meta = inspect_elf(p)
        else:
            meta = {"sha256": _sha256_file(p), "size": size, "type_name": "DATA",
                    "interpreter": None, "needed": [], "build_id": None, "loads": []}
        if meta["sha256"].lower() != str(expected or "").lower():
            raise ValueError(f"{label} SHA-256 mismatch")
        return meta

    def _check_runtime(self, image, main, meta_list, provided, custom_loader):
        interp = main.get("interpreter")
        if interp and not custom_loader:
            p = self._run([self.docker, "run", "--pull=never", "--rm", "--network=none", "--read-only",
                           "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                           "--entrypoint", "/usr/bin/test", image, "-x", interp],
                          capture_output=True, timeout=15, env=docker_environment())
            if p.returncode:
                raise ValueError("required ELF loader is missing from image: " + interp)
        needed = set()
        for meta in [main, *meta_list]:
            needed.update(meta.get("needed", []))
        if not needed:
            return
        p = self._run([self.docker, "run", "--pull=never", "--rm", "--network=none", "--read-only",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                       "--entrypoint", "/sbin/ldconfig", image, "-p"],
                      capture_output=True, text=True, timeout=15, env=docker_environment())
        if p.returncode:
            raise ValueError("cannot verify ELF dependencies: image ldconfig -p failed")
        available = set(provided)
        for line in p.stdout.splitlines():
            if "=>" in line:
                available.add(Path(line.rsplit("=>", 1)[1].strip()).name)
        missing = sorted(needed - available)
        if missing:
            raise ValueError("missing ELF dependencies: " + ", ".join(missing))

    @staticmethod
    def _check_digest_image(image):
        if not isinstance(image, str) or not (re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image)
                                              or re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", image)):
            raise ValueError("profile.image must be immutable sha256 digest")

    def start(self, artifact, sha256, argv, mode, profile, duration_ms, target=None,
              input_mode="stdin", input_data=None):
        if not isinstance(profile, dict):
            raise ValueError("profile must be an object")
        if profile.get("enabled") is False:
            raise ValueError("native profile is disabled")
        max_duration = profile.get("max_duration_ms", 900000)
        if not isinstance(max_duration, int) or not 1 <= duration_ms <= min(max_duration, 900000):
            raise ValueError("duration exceeds native profile limit")
        image = profile.get("image")
        self._check_digest_image(image)
        if mode not in ("exec", "debug"):
            raise ValueError("mode must be exec or debug")
        if input_mode not in ("stdin", "file"):
            raise ValueError("input_mode must be stdin or file")
        if input_data is not None and len(input_data) > 64 * 1024:
            raise ValueError("input exceeds 65536-byte limit")
        validate_argv(argv, input_mode)
        target = normalize_target(target)
        main = self._checked(artifact, sha256, "target")
        harness = target["harness"]
        loader = target["loader"]
        deps = target["dependencies"]
        if main["type_name"] == "ET_DYN" and not main["interpreter"] and not harness:
            raise ValueError("ET_DYN without PT_INTERP cannot run directly; provide an explicit Python harness")
        if harness and mode != "exec":
            raise ValueError("Python harness is supported only in exec mode")
        if harness and input_mode == "file":
            raise ValueError("file input mode with Python harness is unsupported")
        lname = None
        lmeta = None
        records = []
        dep_names = set()
        dep_metas = []
        total = main["size"]
        for dep in deps:
            name = dep["name"]
            if name in dep_names:
                raise ValueError("duplicate dependency basename")
            dep_names.add(name)
            meta = self._checked(dep["artifact_path"], dep["sha256"], "dependency")
            records.append({"kind": "dependency", "name": name, "path": dep["artifact_path"],
                            "meta": meta, "container_path": "/work/deps/" + name})
            dep_metas.append(meta)
            total += meta["size"]
        if loader:
            lname = loader["name"]
            lmeta = self._checked(loader["artifact_path"], loader["sha256"], "loader")
            records.append({"kind": "loader", "name": lname, "path": loader["artifact_path"],
                            "meta": lmeta, "container_path": "/work/loader/" + lname})
            total += lmeta["size"]
        if harness:
            hpath = Path(harness["artifact_path"])
            hname = safe_basename(hpath.name)
            hmeta = self._checked(hpath, harness["sha256"], "harness", elf=False)
            records.append({"kind": "harness", "name": hname, "path": str(hpath),
                            "meta": hmeta, "container_path": "/work/harness.py"})
            total += hmeta["size"]
        if total > MAX_BUNDLE:
            raise ValueError("target and attachments exceed 256 MiB total")
        provided = {r["name"] for r in records if r["kind"] in ("dependency", "loader")}
        self._check_runtime(image, main, dep_metas + ([lmeta] if lmeta else []), provided, lmeta is not None)
        if harness:
            check = self._run([self.docker, "run", "--pull=never", "--rm", "--network=none",
                               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                               "--user=65534:65534", "--entrypoint", "/usr/bin/test", image,
                               "-x", "/usr/bin/python3"],
                              capture_output=True, timeout=15, env=docker_environment())
            if check.returncode:
                raise ValueError("python3 is missing from image for Python harness")
        if mode == "debug":
            check = self._run([self.docker, "run", "--pull=never", "--rm", "--network=none",
                               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                               "--user=65534:65534", "--entrypoint", "/usr/bin/test", image,
                               "-x", "/usr/bin/gdb"],
                              capture_output=True, timeout=15, env=docker_environment())
            if check.returncode:
                raise ValueError("gdb is missing from image for native debug mode")
        staging = tempfile.mkdtemp(prefix="artex-native-")
        os.chmod(staging, 0o755)
        name = None
        try:
            sample = Path(staging) / "sample"
            shutil.copyfile(artifact, sample)
            sample.chmod(0o555)
            if self.inspect_elf(sample).lower() != main["sha256"].lower():
                raise ValueError("staged target SHA-256 changed during copy")
            mounts = [(sample, "/work/sample")]
            for index, rec in enumerate(records):
                src = Path(staging) / (f"attachment-{index}-" + rec["name"])
                shutil.copyfile(rec["path"], src)
                src.chmod(0o555 if rec["kind"] == "loader" else 0o444)
                if _sha256_file(src).lower() != rec["meta"]["sha256"].lower():
                    raise ValueError("staged " + rec["kind"] + " SHA-256 changed during copy")
                mounts.append((src, rec["container_path"]))
            staged_input = None
            if input_mode == "file":
                staged_input = Path(staging) / "input.bin"
                staged_input.write_bytes(input_data or b"")
                staged_input.chmod(0o444)
                mounts.append((staged_input, "/work/input.bin"))
            name = "artex-native-" + uuid.uuid4().hex[:16]
            cmd = [self.docker, "run", "--init", "--pull=never", "-i", "--name", name,
                   "--network=none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=512m",
                   "--cpus=1", "--user=65534:65534"]
            for src, dst in mounts:
                cmd += ["--mount", f"type=bind,src={src},dst={dst},readonly"]
            cmd += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=160m", "--workdir=/work"]
            seccomp = Path(__file__).resolve().parents[2] / "deploy" / "native-lab" / "seccomp-debug.json"
            if mode == "debug":
                if (profile.get("seccomp_profile") not in
                        ("deploy/native-lab/seccomp-debug.json", "deploy\\native-lab\\seccomp-debug.json")
                        or not seccomp.is_file()):
                    raise ValueError("required debug seccomp profile is unavailable")
                cmd += ["--security-opt", f"seccomp={seccomp}"]
            base = ["/work/sample"]
            if loader:
                base = ["/work/loader/" + lname, "--library-path", "/work/deps:/work/loader", "/work/sample"]
            run_argv = ["/work/input.bin" if x == "{input}" else x for x in argv]
            if harness:
                command = ["/usr/bin/python3", "/work/harness.py", "/work/sample", *run_argv]
            else:
                command = [*base, *run_argv]
            if mode == "debug":
                command = [*base, *run_argv]
            if not loader and provided:
                cmd += ["--env", "LD_LIBRARY_PATH=/work/deps"]
            if harness:
                cmd += ["--env", "PYTHONUNBUFFERED=1"]
            cmd += ["--entrypoint", "/usr/bin/gdb" if mode == "debug" else command[0], image]
            if mode == "debug":
                cmd += ["--quiet", "--nx", "--interpreter=mi2",
                        "--init-eval-command=set auto-load off",
                        "--eval-command=set mi-async on",
                        "--eval-command=set disable-randomization off",
                        "--eval-command=set pagination off",
                        "--eval-command=set confirm off",
                        "--eval-command=set inferior-tty /dev/null",
                        "--args", *command]
            else:
                cmd += command[1:]
            proc = self._popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=0, env=docker_environment())
            attachments = []
            for rec in records:
                attachments.append({"kind": rec["kind"], "name": rec["name"],
                                    "sha256": rec["meta"]["sha256"], "size": rec["meta"]["size"],
                                    "build_id": rec["meta"].get("build_id"),
                                    "container_path": rec["container_path"]})
            return {"name": name, "process": proc, "staging": staging,
                    "deadline": time.monotonic() + duration_ms / 1000, "mode": mode,
                    "target_metadata": main,
                    "attached_artifacts": attachments,
                    "attachments_by_container": {a["container_path"]: a for a in attachments},
                    "input_path": str(staged_input) if staged_input else None,
                    "output_source": "harness_stdout" if harness else "target_stdout",
                    "output_trusted": not bool(harness),
                    "core_path": None, "core_meta": None, "image": image,
                    "profile": profile,
                    "aslr_enabled": mode == "debug",
                    "gdb_disable_randomization": "off" if mode == "debug" else None}
        except Exception:
            proc = locals().get("proc")
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=2)
                except Exception:
                    pass
            if name:
                try:
                    self._run([self.docker, "rm", "-f", name], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5,
                              env=docker_environment())
                except Exception:
                    pass
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def environment_manifest(self, image):
        """Tool versions and immutable image identity, cached per image string."""
        with self._versions_lock:
            cached = self._versions_cache.get(image)
            if cached is not None:
                return json.loads(json.dumps(cached))
        manifest = {"image": image, "image_id": None, "architecture": None,
                    "kernel": None, "gdb": None, "loader": None, "python": None,
                    "os": None, "source": "container_probe"}
        name = "artex-env-" + uuid.uuid4().hex[:16]
        # Python is part of the runner image contract; do not depend on shell utilities.
        script = "import json, os, sys, subprocess\nfrom pathlib import Path\ndef version(argv):\n    try:\n        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=4, text=True)\n        return p.stdout.splitlines()[0][:1024] if p.returncode == 0 and p.stdout else None\n    except Exception:\n        return None\nu = os.uname()\nos_name = u.sysname\ntry:\n    for line in Path('/etc/os-release').read_text()[:16384].splitlines():\n        if line.startswith('PRETTY_NAME='):\n            os_name = line.split('=', 1)[1].strip(chr(34)); break\nexcept OSError:\n    pass\nprint(json.dumps({'architecture': u.machine, 'kernel': u.release,\n    'python': 'Python ' + sys.version.split()[0], 'os': os_name,\n    'gdb': version(['/usr/bin/gdb', '--version']),\n    'loader': version(['/lib64/ld-linux-x86-64.so.2', '--version'])}))\n"
        try:
            result = self._run([self.docker, "run", "--pull=never", "--name", name,
                                "--network=none", "--read-only", "--cap-drop=ALL",
                                "--security-opt=no-new-privileges", "--user=65534:65534",
                                "--entrypoint", "/usr/bin/python3", image, "-c", script],
                               capture_output=True, text=True, timeout=20,
                               env=docker_environment())
            if result.returncode == 0:
                values = json.loads(result.stdout)
                for key in ("architecture", "kernel", "gdb", "python", "loader", "os"):
                    value = values.get(key)
                    if isinstance(value, str):
                        manifest[key] = value[:2048]
            else:
                manifest["probe_error"] = "container environment probe failed"
        except Exception:
            pass
        finally:
            try:
                inspect = self._run([self.docker, "inspect", "--format", "{{.Id}}", image],
                                    capture_output=True, text=True, timeout=8,
                                    env=docker_environment())
                if inspect.returncode == 0:
                    manifest["image_id"] = inspect.stdout.strip()
            except Exception:
                pass
            try:
                self._run([self.docker, "rm", "-f", name], capture_output=True,
                          timeout=5, env=docker_environment())
            except Exception:
                pass
        with self._versions_lock:
            self._versions_cache[image] = manifest
        return json.loads(json.dumps(manifest))

    def read_inferior_maps(self, session, pid):
        """Read /proc/<inferior>/maps from the owned container (fixed command)."""
        if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= 2 ** 31:
            return None
        name = session.get("name") if isinstance(session, dict) else None
        if not name:
            return None
        try:
            result = self._run([self.docker, "exec", "--user=65534:65534", name,
                                "/usr/bin/python3", "-c",
                                "import sys; p='/proc/'+str(int(sys.argv[1]))+'/maps'; "
                                "f=open(p,'rb'); data=f.read(" + str(MAX_MAPS_BYTES + 1) + "); "
                                "sys.stdout.buffer.write(data)", str(pid)],
                               capture_output=True, text=True, timeout=3,
                               env=docker_environment())
            if result.returncode != 0:
                return None
            text = result.stdout or ""
            if len(text.encode("utf-8", "replace")) > MAX_MAPS_BYTES:
                return None
            return text
        except Exception:
            return None

    def capture_core(self, session):
        destination = Path(session["staging"]) / "core.bin"
        try:
            destination.unlink(missing_ok=True)
            # Read inside the live mount namespace: docker cp may not expose
            # the container's tmpfs. Never accept a caller-supplied source path.
            script = ("import os,stat,sys\n"
                      "limit=128*1024*1024\n"
                      "fd=os.open('/tmp/artex-core',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n"
                      "with os.fdopen(fd,'rb') as source:\n"
                      "    st=os.fstat(source.fileno())\n"
                      "    if not stat.S_ISREG(st.st_mode): raise ValueError('core is not a regular file')\n"
                      "    if st.st_size>limit: raise ValueError('core exceeds 128 MiB limit')\n"
                      "    total=0\n"
                      "    while True:\n"
                      "        block=source.read(min(65536,limit-total+1))\n"
                      "        if not block: break\n"
                      "        total+=len(block)\n"
                      "        if total>limit: raise ValueError('core exceeds 128 MiB limit')\n"
                      "        sys.stdout.buffer.write(block)\n"
                      "    if total!=st.st_size: raise ValueError('core changed during export')\n")
            command = [self.docker, "exec", "--user=65534:65534", session["name"],
                       "/usr/bin/python3", "-c", script]
            with destination.open("xb") as output:
                result = self._run(command, stdout=output, stderr=subprocess.PIPE,
                                   timeout=30, env=docker_environment())
            if result.returncode:
                error = result.stderr or b""
                if isinstance(error, bytes):
                    error = error.decode("utf-8", "replace")
                raise ValueError("core export failed: " + error[-2048:])
            if destination.is_symlink() or not destination.is_file():
                raise ValueError("core export is not a regular file")
            size = destination.stat().st_size
            if size > 128 * 1024 * 1024:
                raise ValueError("core exceeds 128 MiB limit")
            digest = _sha256_file(destination)
            session["core_path"] = str(destination)
            session["core_meta"] = {"size": size, "sha256": digest,
                                    "path": "/tmp/artex-core"}
            return dict(session["core_meta"])
        except Exception:
            destination.unlink(missing_ok=True)
            session["core_path"] = None
            session["core_meta"] = None
            raise

    def read_core(self, session, offset, length):
        if not session.get("core_path"):
            raise ValueError("no core snapshot is available")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("core range is invalid")
        if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= 65536:
            raise ValueError("core range is invalid")
        path = Path(session["core_path"])
        if path.is_symlink() or not path.is_file():
            raise ValueError("core snapshot is not a regular file")
        size = session["core_meta"]["size"]
        if offset >= size:
            return b""
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(min(length, size - offset))

    def cleanup(self, session):
        if not session:
            return {"owned_process_terminated": True, "container_removed": True,
                    "staging_removed": True, "core_removed": True}
        proc = session.get("process")
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        proc.kill()
                        try:
                            proc.wait(timeout=2)
                        except Exception:
                            pass
            except Exception:
                pass
        owned_terminated = bool(proc is None or proc.poll() is not None)
        name = session.get("name")
        removed = False
        try:
            result = self._run([self.docker, "rm", "-f", name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, env=docker_environment())
            removed = result.returncode == 0
        except Exception:
            removed = False
        try:
            inspect = self._run([self.docker, "inspect", "--format", "{{.Id}}", name],
                                capture_output=True, timeout=5, env=docker_environment())
            if inspect.returncode == 0:
                removed = False
            elif not removed:
                stderr = getattr(inspect, "stderr", "")
                text = stderr if isinstance(stderr, str) else ""
                removed = ("no such container" in text.lower()
                           or "no such object" in text.lower())
        except Exception:
            # Cannot prove removal; never claim success unless docker rm itself
            # completed successfully.
            pass
        if proc is not None:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
        core_path = session.get("core_path")
        if core_path:
            try:
                Path(core_path).unlink(missing_ok=True)
            except OSError:
                pass
        staging = Path(session["staging"])
        try:
            shutil.rmtree(staging)
        except OSError:
            pass
        core_removed = not core_path or not Path(core_path).exists()
        staging_removed = not staging.exists()
        return {"owned_process_terminated": owned_terminated,
                "container_removed": removed, "staging_removed": staging_removed,
                "core_removed": core_removed}
