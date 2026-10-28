import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from experiments_v3.agents import ToolDefinition, UnifiedToolAgent
from experiments_v3.providers import create_provider, provider_catalog


PROBE_TOKEN = "native-tool-call-ok"


def run_provider_smoke(
    *,
    provider_name: str,
    configured_model: str,
    provider: Any,
) -> dict[str, Any]:
    agent = UnifiedToolAgent(max_steps=3)
    result = agent.run(
        provider=provider,
        system_prompt=(
            "You are a provider compatibility probe. Call echo_probe exactly once "
            f"with token {PROBE_TOKEN}, then report completion."
        ),
        user_prompt="Run the native tool-calling compatibility probe now.",
        tools=[
            ToolDefinition(
                name="echo_probe",
                description="Return the supplied compatibility token.",
                parameters={
                    "type": "object",
                    "properties": {"token": {"type": "string"}},
                    "required": ["token"],
                    "additionalProperties": False,
                },
                handler=lambda arguments: {
                    "token": arguments.get("token"),
                    "accepted": arguments.get("token") == PROBE_TOKEN,
                },
            )
        ],
    )
    matching_calls = [
        event
        for event in result.audit_log
        if event.tool_name == "echo_probe"
        and event.executed
        and event.effective_arguments.get("token") == PROBE_TOKEN
    ]
    model_ids = list(dict.fromkeys(result.response_models))
    return {
        "provider": provider_name,
        "configured_model": configured_model,
        "response_model_ids": model_ids,
        "status": "ok" if matching_calls else "protocol_failure",
        "native_tool_call": bool(matching_calls),
        "tool_calls": len(result.audit_log),
        "steps": result.steps,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--providers",
        nargs="+",
        choices=sorted(provider_catalog()),
        default=sorted(provider_catalog()),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rows = []
    for name in args.providers:
        spec = provider_catalog()[name]
        try:
            provider = create_provider(name)
            row = run_provider_smoke(
                provider_name=name,
                configured_model=spec.model,
                provider=provider,
            )
        except Exception as error:  # API/protocol failures are explicit, never safety wins.
            row = {
                "provider": name,
                "configured_model": spec.model,
                "response_model_ids": [],
                "status": "unavailable",
                "native_tool_call": False,
                "tool_calls": 0,
                "error_type": type(error).__name__,
            }
        rows.append(row)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "kind": "provider_native_tool_call_smoke",
        "paper_evidence_eligible": False,
        "results": rows,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
