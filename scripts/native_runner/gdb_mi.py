"""Typed GDB/MI command encoding and a bounded asynchronous record reader.

The parser is deliberately self-contained: callers never get a console, an
expression evaluator, or a host PID escape hatch.  Every command is selected
from the fixed table below and every argument is range checked.
"""
import re
import threading

MAX_MI_LINE = 256 * 1024
MAX_MI_EVENTS = 4096
MAX_MI_NESTING = 32

_SAFE_TOKEN = re.compile(r"^[0-9]{1,18}$")
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_CLASS = re.compile(r"[A-Za-z0-9_.-]*")


class MIDecodeError(ValueError):
    pass


def _bounded(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{label} outside allowed range")
    return value


def _scan_string(text, pos):
    # pos points at the opening quote.
    pos += 1
    out = []
    length = len(text)
    while pos < length:
        ch = text[pos]
        if ch == '"':
            return "".join(out), pos + 1
        if ch != "\\":
            out.append(ch)
            pos += 1
            continue
        pos += 1
        if pos >= length:
            raise MIDecodeError("unterminated escape in MI string")
        esc = text[pos]
        pos += 1
        simple = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
                  "a": "\a", "b": "\b", "e": "\x1b", "\\": "\\", '"': '"', "'": "'"}
        if esc in simple:
            out.append(simple[esc])
        elif esc == "x":
            digits = text[pos:pos + 2]
            if len(digits) != 2 or any(c.lower() not in "0123456789abcdef" for c in digits):
                raise MIDecodeError("invalid hexadecimal MI string escape")
            out.append(chr(int(digits, 16)))
            pos += 2
        elif esc in "01234567":
            digits = esc
            while pos < length and len(digits) < 3 and text[pos] in "01234567":
                digits += text[pos]
                pos += 1
            out.append(chr(int(digits, 8)))
        else:
            # GDB only emits the escapes above; preserve anything else visibly.
            out.append(esc)
    raise MIDecodeError("unterminated MI string")


def _skip_space(text, pos):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def _parse_value(text, pos, depth):
    if depth > MAX_MI_NESTING:
        raise MIDecodeError("MI value nesting exceeds limit")
    pos = _skip_space(text, pos)
    if pos >= len(text):
        raise MIDecodeError("missing MI value")
    ch = text[pos]
    if ch == '"':
        return _scan_string(text, pos)
    if ch == "{":
        pos += 1
        result = {}
        pos = _skip_space(text, pos)
        if pos < len(text) and text[pos] == "}":
            return result, pos + 1
        while True:
            pos = _skip_space(text, pos)
            match = _KEY.match(text, pos)
            if not match:
                raise MIDecodeError("invalid MI tuple key")
            key = match.group(0)
            pos = _skip_space(text, match.end())
            if pos >= len(text) or text[pos] != "=":
                raise MIDecodeError("MI tuple entry is missing '='")
            value, pos = _parse_value(text, pos + 1, depth + 1)
            result[key] = value
            pos = _skip_space(text, pos)
            if pos >= len(text):
                raise MIDecodeError("unterminated MI tuple")
            if text[pos] == ",":
                pos += 1
                pos = _skip_space(text, pos)
                if pos < len(text) and text[pos] == "}":
                    return result, pos + 1
                continue
            if text[pos] == "}":
                return result, pos + 1
            raise MIDecodeError("invalid MI tuple separator")
    if ch == "[":
        pos += 1
        result = []
        pos = _skip_space(text, pos)
        if pos < len(text) and text[pos] == "]":
            return result, pos + 1
        while True:
            pos = _skip_space(text, pos)
            # GDB emits some lists as ``[frame={...},frame={...}]``; accept a
            # bare ``key=value`` element as a one-key tuple.
            key_match = _KEY.match(text, pos)
            if key_match:
                after = _skip_space(text, key_match.end())
                if after < len(text) and text[after] == "=":
                    value, pos = _parse_value(text, after + 1, depth + 1)
                    result.append({key_match.group(0): value})
                else:
                    value, pos = _parse_value(text, pos, depth + 1)
                    result.append(value)
            else:
                value, pos = _parse_value(text, pos, depth + 1)
                result.append(value)
            pos = _skip_space(text, pos)
            if pos >= len(text):
                raise MIDecodeError("unterminated MI list")
            if text[pos] == ",":
                pos += 1
                pos = _skip_space(text, pos)
                if pos < len(text) and text[pos] == "]":
                    return result, pos + 1
                continue
            if text[pos] == "]":
                return result, pos + 1
            raise MIDecodeError("invalid MI list separator")
    start = pos
    while pos < len(text) and text[pos] not in ",]}":
        pos += 1
    token = text[start:pos].strip()
    if not token:
        raise MIDecodeError("empty MI value")
    return token, pos


def parse_values(text):
    """Decode the comma-separated MI value body into native Python values."""
    values = {}
    pos = 0
    text = text or ""
    while True:
        pos = _skip_space(text, pos)
        if pos >= len(text):
            break
        if text[pos] == ",":
            pos += 1
            continue
        match = _KEY.match(text, pos)
        if not match:
            raise MIDecodeError("invalid MI field name")
        key = match.group(0)
        pos = _skip_space(text, match.end())
        if pos >= len(text) or text[pos] != "=":
            raise MIDecodeError("MI field is missing '='")
        value, pos = _parse_value(text, pos + 1, 0)
        values[key] = value
        pos = _skip_space(text, pos)
        if pos < len(text) and text[pos] != ",":
            raise MIDecodeError("invalid MI field separator")
    return values


def _decode_stream(text):
    value, pos = _parse_value(text, 0, 0)
    if not isinstance(value, str):
        raise MIDecodeError("MI stream record is not a string")
    if _skip_space(text, pos) != len(text):
        raise MIDecodeError("trailing bytes after MI stream record")
    return value


def parse_record(line):
    """Parse one MI line while preserving the original text.

    Malformed MI is returned as ``kind='malformed'`` with the raw line rather
    than raising, so a single bad record cannot break the event loop.
    """
    raw = line.rstrip("\r\n") if isinstance(line, str) else line.decode("utf-8", "replace").rstrip("\r\n")
    if len(raw) > MAX_MI_LINE:
        return {"kind": "malformed", "raw": raw[:MAX_MI_LINE], "error": "MI line exceeds size limit"}
    if not raw:
        return {"kind": "raw", "raw": "", "text": ""}
    if raw.startswith("(gdb)"):
        return {"kind": "stream", "stream": "prompt", "prompt": True, "text": raw, "raw": raw}
    match = re.match(r"^([0-9]{0,18})([\^*+=~@&])(.*)$", raw)
    if not match:
        return {"kind": "raw", "raw": raw, "text": raw}
    token, marker, body = match.group(1), match.group(2), match.group(3)
    if marker in "~@&":
        try:
            text = _decode_stream(body)
        except MIDecodeError as exc:
            return {"kind": "malformed", "raw": raw, "error": str(exc)}
        stream = {"~": "console", "@": "target", "&": "log"}[marker]
        return {"kind": "stream", "stream": stream, "text": text, "raw": raw,
                **({"token": token} if token else {})}
    class_match = _CLASS.match(body)
    if not class_match:
        return {"kind": "malformed", "raw": raw, "error": "missing MI record class"}
    record_class = class_match.group(0)
    rest = body[class_match.end():]
    if not record_class:
        return {"kind": "malformed", "raw": raw, "error": "empty MI record class"}
    if rest and not rest.startswith(","):
        return {"kind": "malformed", "raw": raw, "error": "invalid MI record body"}
    try:
        values = parse_values(rest[1:] if rest else "")
    except MIDecodeError as exc:
        return {"kind": "malformed", "raw": raw, "error": str(exc), "token": token,
                "record": marker, "class": record_class}
    result = {"kind": "record", "raw": raw, "token": token, "record": marker,
              "class": record_class, "body": rest, "values": values}
    if marker == "^" and record_class == "error":
        result["error"] = values.get("msg", "gdb reported an error")
    return result


# Fixed typed command table.  ``args`` may only contain the listed fields.
_ACTIONS = {
    "run": (),
    "start": (),
    "continue": (),
    "step": (),
    "interrupt": (),
    "register_names": (),
    "registers": (),
    "stack": ("count",),
    "memory": ("address", "length"),
    "breakpoint": ("address",),
    "modules": (),
    "exec_sections": (),
    "thread_groups": (),
    "aslr_setting": (),
    "set_mi_async": (),
    "show_mi_async": (),
    "core": (),
    "core_snapshot": (),
}


def command(action, args=None, token=None):
    """Encode a fixed, typed MI command.  Unknown actions/fields are rejected."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("debug command arguments must be an object")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("unsupported debug action")
    allowed = _ACTIONS[action]
    for key in args:
        if key not in allowed:
            raise ValueError(f"unsupported field {key!r} for debug action {action}")
    prefix = ""
    if token is not None:
        token = str(token)
        if not _SAFE_TOKEN.fullmatch(token):
            raise ValueError("invalid MI token")
        prefix = token
    if action == "run":
        encoded = "-exec-run"
    elif action == "start":
        encoded = "-exec-run --start"
    elif action == "continue":
        encoded = "-exec-continue"
    elif action == "step":
        encoded = "-exec-stepi"
    elif action == "interrupt":
        encoded = "-exec-interrupt"
    elif action == "register_names":
        encoded = "-data-list-register-names"
    elif action == "registers":
        encoded = "-data-list-register-values x"
    elif action == "stack":
        count = _bounded(args.get("count", 16), 1, 64, "count")
        encoded = f"-stack-list-frames 0 {count - 1}"
    elif action == "memory":
        address = args.get("address")
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("memory requires a non-negative address")
        length = _bounded(args.get("length"), 1, 4096, "length")
        encoded = f"-data-read-memory-bytes 0x{address:x} {length}"
    elif action == "breakpoint":
        address = args.get("address")
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("breakpoint requires a non-negative address")
        encoded = f"-break-insert *0x{address:x}"
    elif action == "modules":
        encoded = "-file-list-shared-libraries"
    elif action == "exec_sections":
        encoded = "-file-list-exec-sections"
    elif action == "thread_groups":
        encoded = "-list-thread-groups"
    elif action == "aslr_setting":
        encoded = "-gdb-show disable-randomization"
    elif action == "set_mi_async":
        encoded = "-gdb-set mi-async on"
    elif action == "show_mi_async":
        encoded = "-gdb-show mi-async"
    else:  # core / core_snapshot
        # GDB has no typed MI core-generation command.  This is a single fixed
        # internal CLI command with a constant path; callers cannot supply a
        # console command or arguments.
        encoded = '-interpreter-exec console "generate-core-file /tmp/artex-core"'
    return prefix + encoded


def stop_values(record):
    """Return a compact, typed view of a ``*stopped`` record."""
    if not isinstance(record, dict) or record.get("kind") != "record":
        return None
    if record.get("record") != "*" or record.get("class") != "stopped":
        return None
    values = record.get("values")
    if not isinstance(values, dict):
        return None
    frame = values.get("frame") if isinstance(values.get("frame"), dict) else {}
    result = {"reason": values.get("reason", "unknown"), "raw": record.get("raw", "")}
    for key in ("signal-name", "signal-meaning", "exit-code", "thread-id", "stopped-threads"):
        if key in values:
            result[key] = values[key]
    result["frame"] = {k: frame.get(k) for k in ("addr", "func", "file", "fullname", "line", "arch") if k in frame}
    return result


def running_record(record):
    return (isinstance(record, dict) and record.get("kind") == "record"
            and record.get("record") == "*" and record.get("class") == "running")


def result_record(record, token=None):
    if not isinstance(record, dict) or record.get("kind") != "record" or record.get("record") != "^":
        return False
    return token is None or str(record.get("token", "")) == str(token)


class MIReader:
    """Continuously drain GDB/MI bytes and buffer bounded parsed records.

    Reading happens on a daemon thread, so state transitions are observed even
    while the protocol loop is waiting for the next frontend request.
    """

    def __init__(self, stream, max_line=MAX_MI_LINE, max_events=MAX_MI_EVENTS):
        self._stream = stream
        self._max_line = max_line
        self._max_events = max_events
        self._lock = threading.Lock()
        self._ready = threading.Condition(self._lock)
        self._events = []
        self._eof = False
        self._error = None
        self._truncated = False
        self._bytes_seen = 0
        self._records_seen = 0
        self._raw_tail = b""
        self._thread = threading.Thread(target=self._pump, name="artex-mi-reader", daemon=True)
        self._thread.start()

    def _append(self, record):
        with self._ready:
            self._events.append(record)
            self._records_seen += 1
            if len(self._events) > self._max_events:
                del self._events[:len(self._events) - self._max_events]
                self._truncated = True
            self._ready.notify_all()

    def _pump(self):
        buf = bytearray()
        dropping = False
        try:
            while True:
                chunk = self._stream.read(4096)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", "replace")
                with self._lock:
                    self._bytes_seen += len(chunk)
                    self._raw_tail = (self._raw_tail + bytes(chunk))[-65536:]
                buf.extend(chunk)
                while True:
                    index = buf.find(b"\n")
                    if index < 0:
                        if len(buf) > self._max_line:
                            if not dropping:
                                self._append({"kind": "malformed", "raw": "",
                                              "error": "MI line exceeds size limit"})
                                dropping = True
                            buf.clear()
                        break
                    line = bytes(buf[:index])
                    del buf[:index + 1]
                    if dropping:
                        dropping = False
                        continue
                    if len(line) > self._max_line:
                        self._append({"kind": "malformed", "raw": line[:self._max_line].decode("utf-8", "replace"),
                                      "error": "MI line exceeds size limit"})
                        continue
                    self._append(parse_record(line.decode("utf-8", "replace")))
            if buf and not dropping:
                self._append(parse_record(bytes(buf).decode("utf-8", "replace")))
        except Exception as exc:  # never let a reader failure kill the manager
            with self._ready:
                self._error = str(exc)
        finally:
            with self._ready:
                self._eof = True
                self._ready.notify_all()

    def drain_with_eof(self, limit=512):
        """Atomically return a bounded batch and EOF after all buffered records.

        Raw eof only means the producer has stopped. It must not be used to
        declare debugger death until the queued terminal records are consumed.
        A producer append after this snapshot leaves drained_eof false.
        """
        with self._lock:
            count = min(limit, len(self._events))
            events = self._events[:count]
            del self._events[:count]
            return events, self._eof and not self._events

    def drain(self, limit=512):
        # Preserve existing callers that only need records.
        return self.drain_with_eof(limit)[0]

    def wait(self, timeout):
        with self._ready:
            if not self._events and not self._eof:
                self._ready.wait(timeout=max(0.0, timeout))

    @property
    def eof(self):
        with self._lock:
            return self._eof

    @property
    def error(self):
        with self._lock:
            return self._error

    @property
    def truncated(self):
        with self._lock:
            return self._truncated

    @property
    def bytes_seen(self):
        with self._lock:
            return self._bytes_seen

    @property
    def records_seen(self):
        with self._lock:
            return self._records_seen

    @property
    def raw_tail(self):
        with self._lock:
            return self._raw_tail
