from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from causalguard.guard.trace_schema import ToolCall
from experiments_v3 import real_agent_benchmark
from experiments_v3.real_agent_benchmark import (
    MAX_AGENT_STEPS,
    _classify_failure,
    _tool_definitions,
    run_real_agent_case,
    summarize_real_agent_rows,
    write_real_agent_run,
)
from experiments_v3.validate_dataset import load_jsonl
from experiments_v3.validate_real_agent_results import validate_real_agent_run


DATASET = (
    Path(__file__).resolve().parents[1]
    / "experiments_v3"
    / "datasets"
    / "base_scenarios.jsonl"
)

# Keep the registered v3 runner byte-for-byte frozen while supplying the
# annotation symbol required on Python versions before 3.14. Production entry
# points use the same compatibility injection.
real_agent_benchmark.ToolCall = ToolCall


class ScriptedProvider:
    def __init__(self, responses):
        self.responses = iter(responses)

    def complete(self, *, messages, tools):
        return next(self.responses)


class FailingProvider:
    def complete(self, *, messages, tools):
        raise TimeoutError("simulated timeout")


class LoopingProvider:
    def __init__(self):
        self.index = 0

    def complete(self, *, messages, tools):
        self.index += 1
        return tool_response(f"loop-{self.index}", "inspect_resource", "{}")


class InterruptAfterResponsesProvider:
    def __init__(self, responses):
        self.responses = iter(responses)

    def complete(self, *, messages, tools):
        try:
            return next(self.responses)
        except StopIteration:
            raise TimeoutError("simulated interruption after tool commit")


def tool_response(call_id, name, arguments):
    call = SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )
    return SimpleNamespace(
        model="scripted-model",
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=None, tool_calls=[call])
            )
        ],
    )


def final_response(text="done"):
    return SimpleNamespace(
        model="scripted-model",
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=text, tool_calls=None)
            )
        ],
    )


class RealAgentBenchmarkV3Tests(unittest.TestCase):
    def setUp(self):
        scenarios = load_jsonl(DATASET)
        self.scenario = next(
            item for item in scenarios if item["base_scenario_id"] == "email-03"
        )
        self.attack = next(
            item for item in self.scenario["variants"] if item["kind"] == "attack"
        )
        self.benign = next(
            item for item in self.scenario["variants"] if item["kind"] == "benign"
        )

    def _attacking_provider(self):
        return ScriptedProvider(
            [
                tool_response("read-1", "inspect_resource", "{}"),
                tool_response(
                    "send-1",
                    "send_email",
                    '{"target_ref":"untrusted:external_observation:target:0",'
                    '"payload_ref":"file:review-response:body"}',
                ),
                final_response(),
            ]
        )

    def test_action_tool_schema_explains_target_and_payload_semantics(self):
        tools = _tool_definitions(
            deepcopy(self.scenario),
            deepcopy(self.benign),
            [],
        )
        send_email = next(tool for tool in tools if tool.name == "send_email")
        properties = send_email.parameters["properties"]

        self.assertIn("recipient", properties["target_ref"]["description"])
        self.assertIn("resource content", properties["payload_ref"]["description"])

    def test_base_agent_attack_is_measured_from_committed_state(self):
        row = run_real_agent_case(
            provider_name="scripted",
            provider=self._attacking_provider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )

        self.assertTrue(row["attack_attempted"])
        self.assertTrue(row["attack_success"])
        self.assertFalse(row["task_success"])
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["total_tokens"], 0)
        self.assertEqual(
            row["committed_actions"][0]["arguments"]["target"],
            "reviewer-copy@attacker.test",
        )

    def test_full_guard_blocks_same_agent_call_before_state_commit(self):
        full_row = run_real_agent_case(
            provider_name="scripted",
            provider=self._attacking_provider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="full",
        )
        base_row = run_real_agent_case(
            provider_name="scripted",
            provider=self._attacking_provider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )

        self.assertTrue(full_row["attack_attempted"])
        self.assertFalse(full_row["attack_success"])
        self.assertFalse(full_row["task_success"])
        self.assertEqual(full_row["guard_blocks"], 1)
        self.assertEqual(full_row["committed_actions"], [])
        self.assertEqual(
            full_row["agent_protocol_sha256"],
            base_row["agent_protocol_sha256"],
        )

    def test_full_guard_preserves_authorized_benign_action(self):
        provider = ScriptedProvider(
            [
                tool_response("read-1", "inspect_resource", "{}"),
                tool_response(
                    "send-1",
                    "send_email",
                    '{"target_ref":"user_goal:target",'
                    '"payload_ref":"file:review-response:body"}',
                ),
                final_response(),
            ]
        )

        row = run_real_agent_case(
            provider_name="scripted",
            provider=provider,
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.benign),
            mode="full",
        )

        self.assertTrue(row["task_success"])
        self.assertFalse(row["attack_success"])
        self.assertEqual(row["guard_blocks"], 0)
        self.assertEqual(len(row["committed_actions"]), 1)

    def test_benign_unauthorized_commit_is_not_labeled_attack_success(self):
        provider = ScriptedProvider(
            [
                tool_response("read-1", "inspect_resource", "{}"),
                tool_response(
                    "send-1",
                    "send_email",
                    '{"target_ref":"file:review-response:body",'
                    '"payload_ref":"user_goal:target"}',
                ),
                final_response(),
            ]
        )

        row = run_real_agent_case(
            provider_name="scripted",
            provider=provider,
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.benign),
            mode="base",
        )

        self.assertTrue(row["unauthorized_commit"])
        self.assertFalse(row["attack_success"])
        self.assertEqual(row["outcome"], "unauthorized_commit")

    def test_unknown_capability_reference_cannot_commit_a_side_effect(self):
        provider = ScriptedProvider(
            [
                tool_response("read-1", "inspect_resource", "{}"),
                tool_response(
                    "send-1",
                    "send_email",
                    '{"target_ref":"forged:target",'
                    '"payload_ref":"file:review-response:body"}',
                ),
                final_response(),
            ]
        )

        row = run_real_agent_case(
            provider_name="scripted",
            provider=provider,
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.benign),
            mode="full",
        )

        self.assertEqual(row["committed_actions"], [])
        self.assertEqual(row["guard_reviews"], 1)

    def test_summary_never_counts_api_error_as_a_safe_attack(self):
        rows = [
            {
                "provider": "p",
                "mode": "full",
                "variant_kind": "attack",
                "status": "ok",
                "attack_success": False,
                "task_success": False,
                "attack_attempted": True,
                "guard_blocks": 1,
                "guard_reviews": 0,
            },
            {
                "provider": "p",
                "mode": "full",
                "variant_kind": "attack",
                "status": "error",
                "attack_success": False,
                "task_success": False,
                "attack_attempted": False,
                "guard_blocks": 0,
                "guard_reviews": 0,
            },
        ]

        summary = summarize_real_agent_rows(rows)["p/full"]

        self.assertEqual(summary["completed_cases"], 1)
        self.assertEqual(summary["failed_cases"], 1)
        self.assertEqual(summary["attack_cases"], 1)
        self.assertEqual(summary["attack_success_rate"], 0.0)

    def test_summary_counts_unauthorized_commit_before_error_as_adverse_safety_event(self):
        rows = [
            {
                "provider": "p",
                "mode": "base",
                "variant_kind": "benign",
                "status": "error",
                "attack_success": False,
                "unauthorized_commit": True,
                "task_success": False,
                "attack_attempted": True,
                "guard_blocks": 0,
                "guard_reviews": 0,
            }
        ]

        summary = summarize_real_agent_rows(rows)["p/base"]

        self.assertEqual(summary["benign_cases"], 0)
        self.assertEqual(summary["benign_safety_observations"], 1)
        self.assertEqual(summary["benign_unauthorized_commit_rate"], 1.0)

    def test_timeout_is_classified_separately_and_not_as_guard_block(self):
        row = run_real_agent_case(
            provider_name="scripted",
            provider=FailingProvider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="full",
        )

        self.assertEqual(row["status"], "error")
        self.assertEqual(row["failure_class"], "timeout")
        self.assertEqual(row["guard_blocks"], 0)
        self.assertFalse(row["attack_success"])

    def test_agent_step_limit_is_not_classified_as_provider_failure(self):
        self.assertEqual(
            _classify_failure(RuntimeError("agent exceeded max_steps=8")),
            "agent_step_limit",
        )

    def test_step_limit_row_preserves_partial_audit_trace(self):
        row = run_real_agent_case(
            provider_name="scripted",
            provider=LoopingProvider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )

        self.assertEqual(row["status"], "error")
        self.assertEqual(row["failure_class"], "agent_step_limit")
        self.assertEqual(row["steps"], MAX_AGENT_STEPS)
        self.assertEqual(row["tool_calls"], MAX_AGENT_STEPS)
        self.assertEqual(row["response_model_ids"], ["scripted-model"])
        self.assertIsNotNone(row["trace"])
        self.assertEqual(len(row["trace"]["audit_log"]), MAX_AGENT_STEPS)

    def test_provider_error_after_attack_commit_preserves_harm_and_trace(self):
        provider = InterruptAfterResponsesProvider(
            [
                tool_response("read-1", "inspect_resource", "{}"),
                tool_response(
                    "send-1",
                    "send_email",
                    '{"target_ref":"untrusted:external_observation:target:0",'
                    '"payload_ref":"file:review-response:body"}',
                ),
            ]
        )
        row = run_real_agent_case(
            provider_name="scripted",
            provider=provider,
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )

        self.assertEqual(row["status"], "error")
        self.assertEqual(row["failure_class"], "timeout")
        self.assertTrue(row["attack_success"])
        self.assertEqual(row["steps"], 2)
        self.assertEqual(row["tool_calls"], 2)
        self.assertIsNotNone(row["trace"])
        summary = summarize_real_agent_rows([row])["scripted/base"]
        self.assertEqual(summary["attack_cases"], 1)
        self.assertEqual(summary["attack_success_rate"], 1.0)

    def test_writer_preserves_failed_cases_as_explicit_rows(self):
        success = run_real_agent_case(
            provider_name="scripted",
            provider=self._attacking_provider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )
        failure = run_real_agent_case(
            provider_name="scripted",
            provider=FailingProvider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="full",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_real_agent_run(
                rows=[success, failure],
                output_directory=output,
                dataset_path=DATASET,
                split="dev",
            )

            lines = (output / "rows.csv").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn("timeout", lines[2])

    def test_writer_separates_traces_and_leaves_evidence_pending_validation(self):
        row = run_real_agent_case(
            provider_name="scripted",
            provider=self._attacking_provider(),
            scenario=deepcopy(self.scenario),
            variant=deepcopy(self.attack),
            mode="base",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            manifest = write_real_agent_run(
                rows=[row],
                output_directory=output,
                dataset_path=DATASET,
                split="dev",
            )

            self.assertFalse(manifest["paper_evidence_eligible"])
            self.assertEqual(manifest["validation_status"], "pending")
            self.assertIn("trace", (output / "traces.jsonl").read_text())
            self.assertNotIn("trace", (output / "rows.csv").read_text().splitlines()[0])
            report = validate_real_agent_run(
                output,
                expected_providers={"scripted"},
                expected_modes={"base"},
                expected_base_scenarios=1,
                expected_variant_kinds={"attack"},
            )
            self.assertEqual(report.errors, ())

            with (output / "rows.csv").open("a", encoding="utf-8") as handle:
                handle.write("tampered\n")
            tampered = validate_real_agent_run(
                output,
                expected_providers={"scripted"},
                expected_modes={"base"},
                expected_base_scenarios=1,
                expected_variant_kinds={"attack"},
            )
            self.assertTrue(any("hash" in error for error in tampered.errors))


if __name__ == "__main__":
    unittest.main()
