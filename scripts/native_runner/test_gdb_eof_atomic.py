"""Deterministic MI queue/EOF ordering regressions; synthetic streams only."""
import io
import json
import queue
import threading
import time
import unittest
from unittest.mock import patch

from scripts.native_runner import main as runner
from scripts.native_runner import test_native_contract as fixtures
from scripts.native_runner.gdb_mi import MIReader


class DrainedEOFTests(unittest.TestCase):
    def test_eof_is_definitive_only_after_last_bounded_batch(self):
        reader = MIReader(io.BytesIO(
            b'*running,thread-id="all"\n'
            b'*stopped,reason="exited-normally"\n'))
        reader._thread.join(1)
        self.assertFalse(reader._thread.is_alive())
        self.assertTrue(reader.eof)
        records, eof = reader.drain_with_eof(1)
        self.assertEqual(len(records), 1)
        self.assertFalse(eof)
        records, eof = reader.drain_with_eof(1)
        self.assertEqual(records[0]["class"], "stopped")
        self.assertTrue(eof)
        self.assertEqual(reader.drain_with_eof(1), ([], True))

    def test_terminal_arriving_after_empty_snapshot_wins_over_raw_eof(self):
        proc = fixtures.ScriptedProc(lambda line: None)
        normal = fixtures.mi_handler(proc)
        continuing = threading.Event()
        injected = threading.Event()

        def handler(line):
            if "-exec-continue" in line:
                continuing.set()
            else:
                normal(line)
        proc.stdin.handler = handler
        original = MIReader.drain_with_eof

        def interleaved(reader, limit=512):
            batch, eof = original(reader, limit)
            if not batch and continuing.is_set() and not injected.is_set():
                injected.set()
                # The producer appends terminal data after the snapshot and then
                # closes. Raw eof is now true, but this snapshot must stay false.
                proc.stdout.feed('*running,thread-id="all"\n'
                                 '*stopped,reason="exited-normally"\n')
                proc.returncode = 0
                proc.stdout.close()
                proc.stderr.close()
                reader._thread.join(1)
                self.assertFalse(reader._thread.is_alive())
                self.assertTrue(reader.eof)
                self.assertFalse(eof)
            return batch, eof

        first = {"operation": "session", "request_id": "start",
                 "artifact_path": "fixture", "sha256": "a" * 64,
                 "mode": "debug", "duration_ms": 2000}
        frames = [first,
                  {"request_id": "run", "action": "debug",
                   "command": {"action": "run"}},
                  {"request_id": "continue", "action": "debug",
                   "command": {"action": "continue"}}]

        class OpenFrames:
            def __init__(self):
                self.q = queue.Queue()
                for frame in frames:
                    self.q.put(json.dumps(frame) + "\n")
            def readline(self, size=-1):
                return self.q.get()

        out = io.StringIO()
        with patch.object(MIReader, "drain_with_eof", interleaved):
            rc = runner.serve(OpenFrames(), out, fixtures.ContractSandbox(proc))
        records = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertTrue(injected.is_set())
        self.assertEqual(rc, 0, records)
        self.assertEqual(records[-1]["observation"]["target_state"], "exit")
        continued = next(row for row in records if row["request_id"] == "continue")
        self.assertNotIn("error", continued["observation"])
        self.assertEqual(continued["observation"]["target_state"], "exit")

    def test_pending_terminal_outcome_precedes_drained_eof(self):
        # A final batch can contain an exit and definitive EOF together.
        class Runtime:
            awaiting = {}
            mi_eof = True
            state = {"stop_generation": 1, "target_state": "exit"}
        done, outcome, error = runner._pending_progress(
            Runtime(), {"required": [], "wait_stop": True,
                        "start_generation": 0, "deadline": time.monotonic() + 1})
        self.assertTrue(done)
        self.assertEqual(outcome, "ok")
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
