"""Asynchronous, bounded byte stream helpers."""
import hashlib
import queue
import re
import threading
import time


class OutputBudget:
    """Shared stdout+stderr budget, enforced even when nobody calls recv."""

    def __init__(self, total):
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ValueError("output budget must be a non-negative integer")
        self.total = total
        self.remaining = total
        self.truncated = False
        self._lock = threading.Lock()

    def take(self, requested):
        if requested <= 0:
            return 0
        with self._lock:
            allowed = min(requested, max(0, self.remaining))
            self.remaining -= allowed
            if allowed < requested:
                self.truncated = True
            return allowed


class ByteReader:
    def __init__(self, stream, max_bytes=16 * 1024 * 1024, budget=None):
        self.stream = stream
        self.pending = b""
        self.q = queue.Queue()
        self.eof = False
        self.error = None
        self.max_bytes = max_bytes
        self.budget = budget
        self.accepted = 0
        self.bytes_seen = 0
        self.dropped = 0
        self.truncated = False
        self.hasher = hashlib.sha256()
        self.tail = b""
        self.sanitizer = []
        threading.Thread(target=self._pump, name="artex-byte-reader", daemon=True).start()

    def _pump(self):
        try:
            while True:
                block = self.stream.read(4096)
                if not block:
                    break
                if isinstance(block, str):
                    block = block.encode("utf-8", "replace")
                self.bytes_seen += len(block)
                self.hasher.update(block)
                self.tail = (self.tail + block)[-65536:]
                if len(self.sanitizer) < 256:
                    for line in block.decode("utf-8", "replace").splitlines():
                        if re.search(r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|ERROR:.*Sanitizer", line):
                            self.sanitizer.append(line[:2048])
                allowed = max(0, min(len(block), self.max_bytes - self.accepted))
                if self.budget is not None:
                    allowed = self.budget.take(allowed)
                if allowed:
                    self.accepted += allowed
                    self.q.put(block[:allowed])
                if allowed < len(block):
                    self.dropped += len(block) - allowed
                    self.truncated = True
        except Exception as exc:  # closed pipes are normal termination
            self.error = str(exc)
        finally:
            self.q.put(None)

    def drain(self, limit):
        chunks = []
        total = 0
        while total < limit:
            try:
                if self.pending:
                    item, self.pending = self.pending, b""
                else:
                    item = self.q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self.eof = True
                break
            take = min(len(item), limit - total)
            chunks.append(item[:take])
            total += take
            if take < len(item):
                self.pending = item[take:]
                break
        return b"".join(chunks), self.eof

    def recv(self, limit, timeout):
        end = time.monotonic() + max(0, timeout)
        chunks = []
        total = 0
        while total < limit:
            try:
                if self.pending:
                    item, self.pending = self.pending, b""
                else:
                    remaining = max(0, end - time.monotonic())
                    item = self.q.get(timeout=remaining)
            except queue.Empty:
                break
            if item is None:
                self.eof = True
                break
            take = min(len(item), limit - total)
            chunks.append(item[:take])
            total += take
            if take < len(item):
                self.pending = item[take:]
                break
        return b"".join(chunks), self.eof


def write_bounded(stream, data, timeout=2):
    """A non-reading target must not block cancellation of the manager."""
    if not data:
        return 0
    finished = threading.Event()
    failure = []
    written = [0]

    def writer():
        try:
            view = memoryview(data)
            while view:
                count = stream.write(view)
                if not count:
                    raise BrokenPipeError("target stdin closed")
                written[0] += count
                view = view[count:]
            stream.flush()
        except Exception as exc:
            failure.append(exc)
        finally:
            finished.set()

    threading.Thread(target=writer, name="artex-stdin-writer", daemon=True).start()
    if not finished.wait(timeout):
        raise TimeoutError("target stdin did not accept bytes within 2 seconds")
    if failure:
        raise failure[0]
    return written[0]
