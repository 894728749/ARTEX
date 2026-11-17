"""Strict case assertions and bounded byte-input minimization helpers.

This module is intentionally not wired into the runner: each real execution must
remain visible in the caller's run ledger.
"""
import base64
import hashlib
import math
import time


_HEX = set("0123456789abcdef")
_SIGNAL_SOURCES = {"debugger", "docker_exit_status_convention"}


def _sha256(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(c.lower() not in _HEX for c in value):
        raise ValueError(f"{label} must be a 64-character SHA-256 hex string")
    return value.lower()


def _known_int(value, label, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be a known integer >= {minimum}")
    return value


def _crash_signature(value):
    if not isinstance(value, dict):
        raise ValueError("crash_signature must be an object")
    artifact = _sha256(value.get("artifact_sha256"), "artifact_sha256")
    module_sha = value.get("module_sha256")
    build_id = value.get("module_build_id")
    if module_sha is None and build_id is None:
        raise ValueError("crash signature needs module_sha256 or module_build_id")
    if module_sha is not None:
        module_sha = _sha256(module_sha, "module_sha256")
    if build_id is not None:
        if not isinstance(build_id, str) or not build_id or build_id.lower() in {"unknown", "none", "null"}:
            raise ValueError("module_build_id must be known")
        if len(build_id) % 2 or any(c.lower() not in _HEX for c in build_id):
            raise ValueError("module_build_id must be hexadecimal")
        build_id = build_id.lower()
    offset = _known_int(value.get("module_offset"), "module_offset")
    signal = _known_int(value.get("signal"), "signal", 1)
    result = {"artifact_sha256": artifact, "module_offset": offset, "signal": signal}
    if module_sha is not None:
        result["module_sha256"] = module_sha
    if build_id is not None:
        result["module_build_id"] = build_id
    return result


def validate_assertion(assertion):
    """Validate and normalize one typed assertion, rejecting unknown evidence."""
    if not isinstance(assertion, dict):
        raise ValueError("assertion must be an object")
    kind = assertion.get("type")
    if kind == "exit_code":
        return {"type": kind, "value": _known_int(assertion.get("value"), "value")}
    if kind == "signal":
        source = assertion.get("signal_source")
        if source not in _SIGNAL_SOURCES:
            raise ValueError("signal assertion requires a recognized signal_source")
        exit_code = assertion.get("exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("signal assertion requires observed exit_code")
        return {"type": kind, "value": _known_int(assertion.get("value"), "value", 1),
                "exit_code": exit_code, "signal_source": source}
    if kind == "stdout_contains_base64":
        encoded = assertion.get("value")
        if not isinstance(encoded, str):
            raise ValueError("stdout assertion value must be base64 text")
        try:
            expected = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError("stdout assertion value is invalid base64") from exc
        if not expected:
            raise ValueError("stdout assertion must not be empty")
        return {"type": kind, "value": base64.b64encode(expected).decode("ascii")}
    if kind == "crash_signature":
        return {"type": kind, "value": _crash_signature(assertion.get("value"))}
    raise ValueError("unsupported assertion type")


def _observed_signature(observation):
    # Only a target-originated structured observation counts. A signature at the
    # top-level runner/harness envelope is deliberately insufficient.
    target = observation.get("target_observation")
    if not isinstance(target, dict) or target.get("evidence_source") != "target_debugger":
        return None
    try:
        return _crash_signature(target.get("crash_signature"))
    except ValueError:
        return None


def evaluate_assertion(observation, assertion):
    """Evaluate one assertion against an observation without trusting harness claims."""
    try:
        assertion = validate_assertion(assertion)
    except (TypeError, ValueError):
        return False
    if not isinstance(observation, dict):
        return False
    kind = assertion["type"]
    if kind == "exit_code":
        code = observation.get("exit_code")
        return not isinstance(code, bool) and isinstance(code, int) and code == assertion["value"]
    if kind == "signal":
        code, sig = observation.get("exit_code"), observation.get("signal")
        if not isinstance(sig, int) or isinstance(sig, bool):
            sig = observation.get("signal_number")
        return (not isinstance(code, bool) and isinstance(code, int) and code == assertion["exit_code"]
                and not isinstance(sig, bool) and isinstance(sig, int) and sig == assertion["value"]
                and observation.get("signal_source") == assertion["signal_source"]
                and observation.get("target_state") == "crashed")
    if kind == "stdout_contains_base64":
        # The runner labels target output as ``target_stdout``.  Harness output
        # (``harness_stdout``) is never target evidence.
        if observation.get("output_source") != "target_stdout":
            return False
        try:
            output = base64.b64decode(observation.get("output_base64", ""), validate=True)
            needle = base64.b64decode(assertion["value"], validate=True)
        except Exception:
            return False
        return needle in output
    if kind == "crash_signature":
        actual = _observed_signature(observation)
        return actual is not None and actual == assertion["value"]
    return False


def ddmin(original, check, assertion, max_runs=32, timeout=60.0):
    """Return a bounded minimized candidate; never mutates or replaces original.

    ``check(bytes)`` must launch one fresh run and return its observation dict. Crash
    reductions require a complete debugger-originated signature that is stable
    across three baseline runs and identical for every accepted candidate.
    A normal-output reduction requires an explicit assertion and three matching
    baseline runs. Attempts include every call, including baseline and candidates.
    """
    if not isinstance(original, bytes):
        raise TypeError("original must be bytes")
    if not callable(check):
        raise TypeError("check must be callable")
    if isinstance(max_runs, bool) or not isinstance(max_runs, int) or max_runs < 0:
        raise ValueError("max_runs must be a non-negative integer")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be a finite non-negative number of seconds")
    normalized = validate_assertion(assertion)
    if normalized["type"] not in {"stdout_contains_base64", "crash_signature"}:
        raise ValueError("minimization requires stdout marker or complete crash_signature")
    started = time.monotonic()
    attempts = 0
    deadline = started + timeout
    result = {"input_base64": base64.b64encode(original).decode("ascii"),
              "original_sha256": hashlib.sha256(original).hexdigest(),
              "minimized_sha256": hashlib.sha256(original).hexdigest(),
              "attempts": 0, "reproduced": False, "signature": None, "limited": False}

    def run(data):
        nonlocal attempts
        if attempts >= max_runs or time.monotonic() >= deadline:
            result["limited"] = True
            return None
        attempts += 1
        try:
            obs = check(data)
        except Exception:
            return None
        return obs if isinstance(obs, dict) else None

    baseline = []
    for _ in range(3):
        obs = run(original)
        if obs is None:
            result["attempts"] = attempts
            return result
        baseline.append(obs)
    if normalized["type"] == "crash_signature":
        signature = normalized["value"]
        good = all(evaluate_assertion(obs, normalized) for obs in baseline)
        result["signature"] = signature if good else None
    else:
        signature = None
        good = all(obs.get("target_state") == "exit" and evaluate_assertion(obs, normalized) for obs in baseline)
    if not good:
        result["attempts"] = attempts
        return result
    result["reproduced"] = True
    current = original
    granularity = 2
    while current:
        if time.monotonic() >= deadline or attempts >= max_runs:
            result["limited"] = True
            break
        chunk_size = max(1, (len(current) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size:]
            if candidate == current:
                continue
            obs = run(candidate)
            if obs is None:
                break
            if normalized:
                matches = evaluate_assertion(obs, normalized)
                candidate_signature = _observed_signature(obs)
                if normalized["type"] == "crash_signature":
                    matches = matches and candidate_signature == normalized["value"]
                else:
                    matches = matches and obs.get("target_state") == "exit"
            if matches:
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if result["limited"]:
            break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    result["input_base64"] = base64.b64encode(current).decode("ascii")
    result["minimized_sha256"] = hashlib.sha256(current).hexdigest()
    result["attempts"] = attempts
    return result
