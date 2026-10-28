from ast import literal_eval
from collections.abc import Callable, Sequence
import inspect
import json
from typing import Any


class AgentDojoGuardedExecutor:
    """Drop-in AgentDojo pipeline element that guards every pre-commit call."""

    def __init__(
        self,
        *,
        before_tool_call: Callable[[str, dict[str, Any]], Any],
        tool_output_formatter: Callable[[Any], str] | None = None,
    ) -> None:
        self.before_tool_call = before_tool_call
        self.output_formatter = tool_output_formatter

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        extra = dict(extra_args or {})
        audit = list(extra.get("causalguard_audit", []))
        extra["causalguard_audit"] = audit
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra
        calls = messages[-1].get("tool_calls") or []
        if not calls:
            return query, runtime, env, messages, extra

        formatter = self.output_formatter or _format_tool_result
        results = []
        for call in calls:
            name = call.function
            proposed = _normalize_arguments(dict(call.args))
            if name not in runtime.functions:
                error = f"Invalid tool {name} provided."
                results.append(_tool_result_message(call, "", error))
                audit.append(
                    {
                        "tool_call_id": call.id,
                        "tool_name": name,
                        "decision": "invalid_tool",
                        "executed": False,
                        "error": error,
                    }
                )
                continue

            try:
                interception = _invoke_interceptor(
                    self.before_tool_call,
                    name,
                    proposed,
                    query,
                    messages,
                )
            except Exception as error:
                interception = _FailedClosedInterception(type(error).__name__)
            if not interception.execute:
                results.append(
                    _tool_result_message(
                        call,
                        interception.tool_message,
                        f"CausalGuard decision: {interception.decision}",
                    )
                )
                audit.append(
                    {
                        "tool_call_id": call.id,
                        "tool_name": name,
                        "decision": interception.decision,
                        "executed": False,
                    }
                )
                continue

            tool_result, error = runtime.run_function(
                env,
                name,
                interception.arguments,
            )
            results.append(_tool_result_message(call, formatter(tool_result), error))
            audit.append(
                {
                    "tool_call_id": call.id,
                    "tool_name": name,
                    "decision": interception.decision,
                    "executed": error is None,
                    "error": error,
                }
            )
        return query, runtime, env, [*messages, *results], extra


class _FailedClosedInterception:
    def __init__(self, error_type: str):
        self.execute = False
        self.arguments: dict[str, Any] = {}
        self.tool_message = (
            '{"decision":"review","executed":false,'
            f'"adapter_error":"{error_type}"}}'
        )
        self.decision = "review"


def _invoke_interceptor(
    interceptor: Callable[..., Any],
    name: str,
    arguments: dict[str, Any],
    query: str,
    messages: Sequence[Any],
) -> Any:
    """Call either the legacy two-argument or contextual four-argument hook."""
    parameters = inspect.signature(interceptor).parameters.values()
    accepts_context = any(
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        for parameter in parameters
    ) or len(tuple(parameters)) >= 4
    if accepts_context:
        return interceptor(name, arguments, query, messages)
    return interceptor(name, arguments)


def _normalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    for key, value in list(arguments.items()):
        if not isinstance(value, str):
            continue
        try:
            parsed = literal_eval(value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed, list):
            arguments[key] = parsed
    return arguments


def _tool_result_message(call: Any, content: str, error: str | None) -> dict[str, Any]:
    return {
        "role": "tool",
        "content": [{"type": "text", "content": content}],
        "tool_call_id": call.id,
        "tool_call": call,
        "error": error,
    }


def _format_tool_result(result: Any) -> str:
    if hasattr(result, "model_dump"):
        result = result.model_dump()
    if isinstance(result, list):
        result = [item.model_dump() if hasattr(item, "model_dump") else item for item in result]
    if isinstance(result, (dict, list)):
        return json.dumps(result, ensure_ascii=False, sort_keys=True)
    return str(result)
