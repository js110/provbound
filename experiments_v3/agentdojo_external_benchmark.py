from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
from time import perf_counter
from typing import Any

from openai import OpenAI

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.agent_pipeline.tool_execution import (
    ToolsExecutionLoop,
    ToolsExecutor,
    tool_result_to_str,
)
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from causalguard.integrations.agentdojo_guard import AgentDojoGuardedExecutor
from causalguard.integrations.agentdojo_policy import QueryScopedAgentDojoPolicy


ROOT = Path(__file__).resolve().parents[1]


class SenseNovaAgentDojoLLM(BasePipelineElement):
    """Minimal AgentDojo LLM adapter matching SenseNova's accepted payload."""

    name = "sensenova-6.7-flash-lite"

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        self.client = OpenAI(
            api_key=os.environ["OPENAI_COMPATIBLE_API_KEY"],
            base_url=os.environ["OPENAI_COMPATIBLE_BASE_URL"],
            timeout=60.0,
            max_retries=2,
        )

    def query(self, query, runtime, env, messages=(), extra_args=None):
        payload = [_to_sensenova_message(message) for message in messages]
        tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        response = self.client.chat.completions.create(
            model=self.model_id,
            messages=payload,
            tools=tools,
            tool_choice="auto",
            temperature=0,
            stream=False,
        )
        assistant = _openai_to_assistant_message(response.choices[0].message)
        return query, runtime, env, [*messages, assistant], dict(extra_args or {})


def _to_sensenova_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message["role"]
    content = message.get("content")
    if isinstance(content, list):
        content = "\n".join(str(block.get("content") or "") for block in content)
    payload: dict[str, Any] = {"role": role, "content": content or ""}
    if role == "assistant" and message.get("tool_calls"):
        payload["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function,
                    "arguments": json.dumps(call.args),
                },
            }
            for call in message["tool_calls"]
        ]
    if role == "tool":
        payload["tool_call_id"] = message["tool_call_id"]
        payload["content"] = message.get("error") or payload["content"]
    return payload


def build_pipeline(model_id: str, mode: str) -> AgentPipeline:
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=SenseNovaAgentDojoLLM(model_id),
            model_id=None,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
            tool_output_format=None,
        )
    )
    pipeline.name = f"sensenova-agentdojo-{mode}-v1"
    if mode == "base":
        return pipeline
    if mode != "full":
        raise ValueError(f"unsupported mode: {mode}")
    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.elements = [
                AgentDojoGuardedExecutor(
                    before_tool_call=QueryScopedAgentDojoPolicy(),
                    tool_output_formatter=tool_result_to_str,
                ),
                *[
                    inner
                    for inner in element.elements
                    if not isinstance(inner, ToolsExecutor)
                ],
            ]
    return pipeline


def run_benchmark(config: dict[str, Any], output_dir: Path) -> list[dict[str, Any]]:
    required = ("OPENAI_COMPATIBLE_BASE_URL", "OPENAI_COMPATIBLE_API_KEY")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError(f"missing environment variables: {', '.join(missing)}")

    suite = get_suite(config["benchmark_version"], config["suite"])
    selected_users = list(config["user_tasks"])
    selected_injections = list(config["injection_tasks"])
    _validate_ids(selected_users, suite.user_tasks, "user task")
    _validate_ids(selected_injections, suite.injection_tasks, "injection task")
    output_dir.mkdir(parents=True, exist_ok=True)
    logdir = output_dir / "official_logs"
    rows: list[dict[str, Any]] = []
    pipelines = {mode: build_pipeline(config["model_id"], mode) for mode in config["modes"]}
    attacks = {
        mode: load_attack(config["attack"], suite, pipeline)
        for mode, pipeline in pipelines.items()
    }
    with OutputLogger(str(logdir)):
        for user_id in selected_users:
            for injection_id in selected_injections:
                for mode in _ordered_modes(config["modes"], user_id, injection_id):
                    pipeline = pipelines[mode]
                    attack = attacks[mode]
                    started = perf_counter()
                    row: dict[str, Any] = {
                        "mode": mode,
                        "user_task_id": user_id,
                        "injection_task_id": injection_id,
                        "status": "ok",
                        "utility": False,
                        "security_pass": False,
                        "attack_success": False,
                        "error_type": "",
                        "error_message": "",
                    }
                    try:
                        utility, security = run_task_with_injection_tasks(
                            suite,
                            pipeline,
                            suite.get_user_task_by_id(user_id),
                            attack,
                            logdir=logdir,
                            force_rerun=False,
                            injection_tasks=[injection_id],
                            benchmark_version=config["benchmark_version"],
                        )
                        key = (user_id, injection_id)
                        row["utility"] = bool(utility[key])
                        row["security_pass"], row["attack_success"] = _official_scores(
                            bool(security[key])
                        )
                    except Exception as error:
                        row["status"] = "error"
                        row["error_type"] = type(error).__name__
                        row["error_message"] = str(error)[:500]
                    row["latency_seconds"] = round(perf_counter() - started, 6)
                    rows.append(row)
                    _write_rows(rows, output_dir / "rows.csv")
                    print(
                        f"{mode} {user_id} {injection_id} status={row['status']} "
                        f"utility={row['utility']} security={row['security_pass']}",
                        flush=True,
                    )
    _write_artifacts(rows, config, output_dir)
    return rows


def _write_rows(rows: list[dict[str, Any]], path: Path) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_artifacts(rows: list[dict[str, Any]], config: dict[str, Any], output_dir: Path) -> None:
    summary: dict[str, Any] = {}
    for mode in config["modes"]:
        selected = [row for row in rows if row["mode"] == mode]
        completed = [row for row in selected if row["status"] == "ok"]
        summary[mode] = {
            "total_cells": len(selected),
            "completed_cells": len(completed),
            "failed_cells": len(selected) - len(completed),
            "utility_rate": _rate(sum(row["utility"] for row in completed), len(completed)),
            "security_pass_rate": _rate(sum(row["security_pass"] for row in completed), len(completed)),
            "attack_success_rate": _rate(sum(row["attack_success"] for row in completed), len(completed)),
        }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    config_path = output_dir / "resolved_config.json"
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows_path = output_dir / "rows.csv"
    manifest = {
        "created_at": datetime.now().astimezone().isoformat(),
        "kind": "official_agentdojo_query_scoped_precommit_benchmark",
        "paper_evidence_eligible": False,
        "validation_status": "pending",
        "security_semantics": (
            "AgentDojo BaseInjectionTask.security=True means the injection goal "
            "was executed; attack_success=official security result and "
            "security_pass=not attack_success"
        ),
        "config": config,
        "artifacts": {
            "rows.csv": _sha256(rows_path),
            "summary.json": _sha256(summary_path),
            "resolved_config.json": _sha256(config_path),
        },
        "implementation_sha256": {
            "experiments_v3/agentdojo_external_benchmark.py": _sha256(Path(__file__)),
            "causalguard/integrations/agentdojo_guard.py": _sha256(ROOT / "causalguard/integrations/agentdojo_guard.py"),
            "causalguard/integrations/agentdojo_policy.py": _sha256(ROOT / "causalguard/integrations/agentdojo_policy.py"),
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _validate_ids(selected: list[str], available: dict[str, Any], label: str) -> None:
    unknown = sorted(set(selected) - set(available))
    if unknown:
        raise ValueError(f"unknown {label} IDs: {unknown}")


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _official_scores(injection_goal_executed: bool) -> tuple[bool, bool]:
    """Return (security_pass, attack_success) from AgentDojo's checker value."""
    return (not injection_goal_executed, injection_goal_executed)


def _ordered_modes(modes: list[str], user_id: str, injection_id: str) -> list[str]:
    ordered = list(modes)
    if len(ordered) == 2:
        digest = hashlib.sha256(f"{user_id}/{injection_id}".encode()).digest()
        if digest[0] % 2:
            ordered.reverse()
    return ordered


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    run_benchmark(config, args.output)


if __name__ == "__main__":
    main()
