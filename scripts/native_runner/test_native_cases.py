import base64
import hashlib
import unittest

from .cases import ddmin, evaluate_assertion, validate_assertion


def crash_observation(artifact="a" * 64, offset=12, signal=11):
    return {
        "target_state": "crashed",
        "target_observation": {
            "evidence_source": "target_debugger",
            "crash_signature": {
                "artifact_sha256": artifact,
                "module_build_id": "0123abcd",
                "module_offset": offset,
                "signal": signal,
            },
        },
    }


class NativeCaseTests(unittest.TestCase):
    def test_assertion_rejects_unknown_crash_location(self):
        with self.assertRaises(ValueError):
            validate_assertion({"type": "crash_signature", "value": {
                "artifact_sha256": "a" * 64, "module_build_id": "unknown",
                "module_offset": 0, "signal": 11,
            }})

    def test_output_assertion_ignores_harness_output(self):
        assertion = {"type": "stdout_contains_base64", "value": base64.b64encode(b"IMPACT").decode()}
        self.assertFalse(evaluate_assertion({"output_source": "harness", "output_base64": assertion["value"]}, assertion))
        self.assertTrue(evaluate_assertion({"target_state": "exit", "output_source": "target_stdout",
                                            "output_base64": assertion["value"]}, assertion))

    def test_crash_minimization_keeps_same_complete_signature(self):
        original = b"prefix:CRASH:suffix"
        assertion = {"type": "crash_signature", "value": crash_observation()["target_observation"]["crash_signature"]}
        calls = []

        def check(data):
            calls.append(data)
            return crash_observation() if b"CRASH" in data else {"target_state": "exit"}

        result = ddmin(original, check, assertion, max_runs=40, timeout=5)
        self.assertTrue(result["reproduced"])
        self.assertEqual(result["attempts"], len(calls))
        self.assertEqual(hashlib.sha256(original).hexdigest(), result["original_sha256"])
        self.assertEqual(base64.b64decode(result["input_base64"]), b"CRASH")
        self.assertEqual(result["minimized_sha256"], hashlib.sha256(b"CRASH").hexdigest())
        self.assertEqual(result["signature"], assertion["value"])

    def test_normal_input_fails_three_run_baseline(self):
        assertion = {"type": "crash_signature", "value": crash_observation()["target_observation"]["crash_signature"]}
        calls = []
        result = ddmin(b"normal", lambda data: calls.append(data) or {"target_state": "exit"}, assertion, max_runs=10, timeout=5)
        self.assertFalse(result["reproduced"])
        self.assertEqual(len(calls), 3)
        self.assertEqual(base64.b64decode(result["input_base64"]), b"normal")

    def test_different_crash_signature_is_rejected(self):
        assertion = {"type": "crash_signature", "value": crash_observation(offset=12)["target_observation"]["crash_signature"]}
        result = ddmin(b"candidate", lambda _: crash_observation(offset=13), assertion, max_runs=8, timeout=5)
        self.assertFalse(result["reproduced"])
        self.assertEqual(base64.b64decode(result["input_base64"]), b"candidate")

    def test_run_budget_exhaustion_is_explicit(self):
        assertion = {"type": "crash_signature", "value": crash_observation()["target_observation"]["crash_signature"]}
        result = ddmin(b"keep", lambda _: crash_observation(), assertion, max_runs=3, timeout=5)
        self.assertTrue(result["reproduced"])
        self.assertTrue(result["limited"])
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(base64.b64decode(result["input_base64"]), b"keep")

    def test_empty_input_boundary(self):
        assertion = {"type": "crash_signature", "value": crash_observation()["target_observation"]["crash_signature"]}
        result = ddmin(b"", lambda _: crash_observation(), assertion, max_runs=8, timeout=5)
        self.assertTrue(result["reproduced"])
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["input_base64"], "")
        self.assertEqual(result["original_sha256"], hashlib.sha256(b"").hexdigest())

    def test_minimization_rejects_boolean_check_result(self):
        assertion = {"type": "crash_signature", "value": crash_observation()["target_observation"]["crash_signature"]}
        result = ddmin(b"x", lambda _: True, assertion, max_runs=8, timeout=5)
        self.assertFalse(result["reproduced"])
        self.assertEqual(result["attempts"], 1)

    def test_marker_input_can_be_minimized(self):
        original = b"prefix:IMPACT:suffix"
        assertion = {"type": "stdout_contains_base64", "value": base64.b64encode(b"IMPACT").decode()}

        def check(data):
            marker = b"IMPACT" in data
            return {"target_state": "exit", "output_source": "target_stdout",
                    "output_base64": base64.b64encode(b"IMPACT" if marker else b"normal").decode()}

        result = ddmin(original, check, assertion, max_runs=40, timeout=5)
        self.assertTrue(result["reproduced"])
        self.assertEqual(base64.b64decode(result["input_base64"]), b"IMPACT")


if __name__ == "__main__":
    unittest.main()
