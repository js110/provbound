from dataclasses import dataclass
import json
from typing import Any, Callable, Protocol


class CompletionProvider(Protocol):
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> Any: ...


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class AgentRunResult:
    final_text: str
    messages: list[dict[str, Any]]
    steps: int
    audit_log: tuple["ToolAuditEvent", ...] = ()
    response_models: tuple[str, ...] = ()
    response_usage: tuple[dict[str, int], ...] = ()


class AgentStepLimitError(RuntimeError):
    """Raised with the complete partial run when the agent exhausts its step budget."""

    def __init__(self, *, max_steps: int, result: AgentRunResult):
        super().__init__(f"agent exceeded max_steps={max_steps}")
        self.max_steps = max_steps
        self.result = result


class AgentRunInterruptedError(RuntimeError):
    """Provider failure with the complete agent trace recorded before interruption."""

    def __init__(self, *, original_error: Exception, result: AgentRunResult):
        super().__init__(
            f"agent provider interrupted: {type(original_error).__name__}"
        )
        self.original_error = original_error
        self.result = result


@dataclass(frozen=True)
class ToolInterception:
    execute: bool
    arguments: dict[str, Any]
    tool_message: str
    decision: str


@dataclass(frozen=True)
class ToolAuditEvent:
    tool_call_id: str
    tool_name: str
    proposed_arguments: dict[str, Any]
    effective_arguments: dict[str, Any]
    decision: str
    executed: bool
    error_type: str | None = None


class UnifiedToolAgent:
    """One provider-independent multi-turn function-calling loop."""

    def __init__(self, *, max_steps: int = 8):
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self.max_steps = max_steps

    def run(
        self,
        *,
        provider: CompletionProvider,
        system_prompt: str,
        user_prompt: str,
        tools: list[ToolDefinition],
        before_tool_call: Callable[
            [str, dict[str, Any]], ToolInterception
        ]
        | None = None,
    ) -> AgentRunResult:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        tool_schemas = [tool.schema() for tool in tools]
        tool_map = {tool.name: tool for tool in tools}
        audit_log: list[ToolAuditEvent] = []
        response_models: list[str] = []
        response_usage: list[dict[str, int]] = []

        for step in range(1, self.max_steps + 1):
            try:
                response = provider.complete(messages=messages, tools=tool_schemas)
            except Exception as error:
                raise AgentRunInterruptedError(
                    original_error=error,
                    result=AgentRunResult(
                        final_text="",
                        messages=messages,
                        steps=step - 1,
                        audit_log=tuple(audit_log),
                        response_models=tuple(response_models),
                        response_usage=tuple(response_usage),
                    ),
                ) from error
            response_models.append(str(getattr(response, "model", "unknown")))
            response_usage.append(_response_usage(response))
            message = response.choices[0].message
            messages.append(_assistant_message(message))
            tool_calls = getattr(message, "tool_calls", None) or []
            if not tool_calls:
                return AgentRunResult(
                    final_text=getattr(message, "content", None) or "",
                    messages=messages,
                    steps=step,
                    audit_log=tuple(audit_log),
                    response_models=tuple(response_models),
                    response_usage=tuple(response_usage),
                )

            for tool_call in tool_calls:
                name = tool_call.function.name
                if name not in tool_map:
                    raise ValueError(f"model requested unknown tool: {name}")
                proposed_arguments = json.loads(
                    tool_call.function.arguments or "{}"
                )
                interception = (
                    before_tool_call(name, dict(proposed_arguments))
                    if before_tool_call is not None
                    else ToolInterception(
                        execute=True,
                        arguments=dict(proposed_arguments),
                        tool_message="",
                        decision="allow",
                    )
                )
                if not interception.execute:
                    audit_log.append(
                        ToolAuditEvent(
                            tool_call_id=tool_call.id,
                            tool_name=name,
                            proposed_arguments=dict(proposed_arguments),
                            effective_arguments=dict(interception.arguments),
                            decision=interception.decision,
                            executed=False,
                        )
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": interception.tool_message,
                        }
                    )
                    continue
                try:
                    output = tool_map[name].handler(interception.arguments)
                except Exception as error:
                    audit_log.append(
                        ToolAuditEvent(
                            tool_call_id=tool_call.id,
                            tool_name=name,
                            proposed_arguments=dict(proposed_arguments),
                            effective_arguments=dict(interception.arguments),
                            decision=interception.decision,
                            executed=False,
                            error_type=type(error).__name__,
                        )
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": (
                                "TOOL_ERROR: local sandbox execution failed "
                                f"({type(error).__name__})"
                            ),
                        }
                    )
                    continue
                audit_log.append(
                    ToolAuditEvent(
                        tool_call_id=tool_call.id,
                        tool_name=name,
                        proposed_arguments=dict(proposed_arguments),
                        effective_arguments=dict(interception.arguments),
                        decision=interception.decision,
                        executed=True,
                    )
                )
                content = output if isinstance(output, str) else json.dumps(
                    output,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": content,
                    }
                )

        final_content = ""
        if messages and messages[-1].get("role") == "assistant":
            final_content = messages[-1].get("content") or ""
        raise AgentStepLimitError(
            max_steps=self.max_steps,
            result=AgentRunResult(
                final_text=final_content,
                messages=messages,
                steps=self.max_steps,
                audit_log=tuple(audit_log),
                response_models=tuple(response_models),
                response_usage=tuple(response_usage),
            ),
        )


def _assistant_message(message: Any) -> dict[str, Any]:
    if hasattr(message, "model_dump"):
        payload = message.model_dump(mode="json", exclude_none=True)
        payload["role"] = "assistant"
        return payload

    payload: dict[str, Any] = {
        "role": "assistant",
        "content": getattr(message, "content", None),
    }
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        payload["tool_calls"] = [
            {
                "id": call.id,
                "type": getattr(call, "type", "function"),
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                },
            }
            for call in tool_calls
        ]
    for reasoning_field in ("reasoning_content", "reasoning"):
        value = getattr(message, reasoning_field, None)
        if value is not None:
            payload[reasoning_field] = value
    return payload


def _response_usage(response: Any) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        payload = usage.model_dump(exclude_none=True)
    else:
        payload = {
            name: getattr(usage, name, None)
            for name in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
            )
        }
    return {
        name: int(value)
        for name, value in payload.items()
        if value is not None and isinstance(value, (int, float))
    }
