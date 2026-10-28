from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from experiments_v3.merge_real_agent_runs import merge_real_agent_run_directories
from experiments_v3.real_agent_benchmark import write_real_agent_run
from experiments_v3.validate_real_agent_results import validate_real_agent_run


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "experiments_v3" / "datasets" / "base_scenarios.jsonl"


def _row(scenario_id: str, variant_id: str) -> dict:
    return {
        "provider": "p",
        "mode": "base",
        "base_scenario_id": scenario_id,
        "variant_id": variant_id,
        "domain": "email",
        "attack_family": "test",
        "variant_kind": "attack",
        "agent_protocol_sha256": "shared-protocol",
        "status": "ok",
        "error_type": None,
        "failure_class": None,
        "response_model_ids": ["model-p"],
        "attack_attempted": False,
        "unauthorized_commit": False,
        "attack_success": False,
        "task_success": True,
        "guard_blocks": 0,
        "guard_reviews": 0,
        "steps": 2,
        "tool_calls": 1,
        "committed_actions": [],
        "outcome": "task_success",
        "elapsed_seconds": 0.1,
        "prompt_tokens": 3,
        "completion_tokens": 2,
        "total_tokens": 5,
        "trace": {
            "messages": [
                {"role": "system", "content": "shared"},
                {"role": "user", "content": f"task-{scenario_id}"},
            ],
            "audit_log": [],
        },
    }


class MergeRealAgentRunsV3Tests(unittest.TestCase):
    def test_merger_rebuilds_a_unique_validated_grid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = [root / "part-a", root / "part-b"]
            for path, row in zip(
                inputs,
                [_row("email-01", "email-01-attack"), _row("email-02", "email-02-attack")],
            ):
                write_real_agent_run(
                    rows=[row],
                    output_directory=path,
                    dataset_path=DATASET,
                    split="dev",
                )

            output = root / "merged"
            manifest = merge_real_agent_run_directories(
                input_directories=inputs,
                output_directory=output,
                dataset_path=DATASET,
                split="dev",
            )

            self.assertEqual(manifest["cases"], 2)
            report = validate_real_agent_run(
                output,
                expected_providers={"p"},
                expected_modes={"base"},
                expected_base_scenarios=2,
                expected_variant_kinds={"attack"},
            )
            self.assertEqual(report.errors, ())

    def test_merger_rejects_duplicate_grid_cells(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = [root / "part-a", root / "part-b"]
            for path in inputs:
                write_real_agent_run(
                    rows=[_row("email-01", "email-01-attack")],
                    output_directory=path,
                    dataset_path=DATASET,
                    split="dev",
                )

            with self.assertRaisesRegex(ValueError, "duplicate grid cell"):
                merge_real_agent_run_directories(
                    input_directories=inputs,
                    output_directory=root / "merged",
                    dataset_path=DATASET,
                    split="dev",
                )


if __name__ == "__main__":
    unittest.main()
