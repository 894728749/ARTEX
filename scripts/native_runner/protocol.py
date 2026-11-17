"""JSONL framing and strict protocol limits for the native runner."""
import base64
import json

PROTOCOL_VERSION = 1
MAX_IO = 64 * 1024
MAX_FRAME = 1024 * 1024


def read_frame(stream):
    line = stream.readline(MAX_FRAME + 1)
    if not line:
        return None
    newline = b"\n" if isinstance(line, bytes) else "\n"
    if len(line) > MAX_FRAME or not line.endswith(newline):
        raise ValueError("protocol frame exceeds 1048576 bytes or is unterminated")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("frame must be a JSON object")
    return value


def write_frame(stream, value):
    stream.write(json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n")
    stream.flush()


def encode(data):
    return base64.b64encode(data).decode("ascii")
