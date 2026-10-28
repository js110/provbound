import json
import unittest
from dataclasses import replace

from causalguard.guard.authorization import Decision
from causalguard.integrations.core_guard import CoreGuard
from causalguard.integrations.pre_execution import CoreGuardPreExecution
from experiments_v3.dataset_runner import compile_variant
from experiments_v3.validate_dataset import load_jsonl
from pathlib import Path


DATASET = (
    Path(__file__).resolve().parents[1]
    / "experiments_v3"
    / "datasets"
    / "base_scenarios.jsonl"
)


class IntegrationEquivalenceTests(unittest.TestCase):
    def test_adapter_and_core_return_same_decision_and_sanitized_arguments(self):
        scenario = load_jsonl(DATASET)[0]
        attack = next(
            variant
            for variant in scenario["variants"]
            if variant["expected_decision"] == "block"
        )
        call, contract = compile_variant(scenario, attack)
        direct = CoreGuard().evaluate(call, contracts=[contract])
        adapter = CoreGuardPreExecution(
            contracts=[contract],
            call_factory=lambda name, arguments: replace(
                call,
                tool_name=name,
                arguments=arguments,
            ),
        )

        intercepted = adapter(call.tool_name, call.arguments)

        self.assertEqual(intercepted.decision, direct.decision.value)
        self.assertEqual(intercepted.arguments, direct.arguments)
        self.assertEqual(intercepted.execute, direct.decision == Decision.ALLOW)
        message = json.loads(intercepted.tool_message)
        self.assertEqual(message["decision"], direct.decision.value)
        self.assertEqual(message["executed"], False)

    def test_review_never_executes_without_explicit_confirmation(self):
        scenario = load_jsonl(DATASET)[0]
        boundary = next(
            variant
            for variant in scenario["variants"]
            if variant["expected_decision"] == "review"
        )
        call, contract = compile_variant(scenario, boundary)
        adapter = CoreGuardPreExecution(
            contracts=[contract],
            call_factory=lambda name, arguments: replace(
                call,
                tool_name=name,
                arguments=arguments,
            ),
        )

        intercepted = adapter(call.tool_name, call.arguments)

        self.assertEqual(intercepted.decision, "review")
        self.assertFalse(intercepted.execute)


if __name__ == "__main__":
    unittest.main()
