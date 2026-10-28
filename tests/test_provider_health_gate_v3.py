from types import SimpleNamespace
import unittest

from experiments_v3.provider_health_gate import evaluate_provider_health, run_health_gate


class AlternatingProvider:
    def __init__(self, fail_attempt: int | None = None):
        self.call = 0
        self.fail_attempt = fail_attempt

    def complete(self, *, messages, tools):
        self.call += 1
        attempt = (self.call + 1) // 2
        if self.fail_attempt == attempt:
            raise ConnectionError("temporary outage")
        if self.call % 2:
            message = SimpleNamespace(
                content=None,
                tool_calls=[
                    SimpleNamespace(
                        id=f"call-{self.call}",
                        type="function",
                        function=SimpleNamespace(
                            name="echo_probe",
                            arguments='{"token":"native-tool-call-ok"}',
                        ),
                    )
                ],
            )
        else:
            message = SimpleNamespace(content="done", tool_calls=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)], model="expected-model"
        )


class ProviderHealthGateV3Tests(unittest.TestCase):
    def test_gate_requires_all_consecutive_native_tool_probes(self):
        payload = run_health_gate(
            provider_name="fake",
            configured_model="expected-model",
            provider=AlternatingProvider(),
            attempts=3,
        )
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(len(payload["attempts"]), 3)

        failed = run_health_gate(
            provider_name="fake",
            configured_model="expected-model",
            provider=AlternatingProvider(fail_attempt=2),
            attempts=3,
        )
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(
            failed["attempts"][1]["error_type"], "AgentRunInterruptedError"
        )

    def test_gate_rejects_returned_model_mismatch(self):
        rows = [
            {
                "status": "ok",
                "native_tool_call": True,
                "response_model_ids": ["other-model"],
            }
        ]
        result = evaluate_provider_health(
            rows, configured_model="expected-model", required_attempts=1
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("returned_model_mismatch", result["reasons"])


if __name__ == "__main__":
    unittest.main()
