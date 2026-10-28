from dataclasses import dataclass, field
from time import perf_counter
import re

from causalguard.guard.causal_graph import CausalGraph
from causalguard.guard.explainer import ExplanationBuilder
from causalguard.guard.policy import GuardDecision, GuardPolicy
from causalguard.guard.trace_schema import SourceTrust, ToolCall, TraceEvent
from causalguard.tools.mock_email import MockEmailTool
from causalguard.tools.mock_memory import MockMemoryTool


@dataclass
class RunResult:
    final_answer: str
    events: list[TraceEvent]
    decisions: list[GuardDecision] = field(default_factory=list)
    explanations: list[dict] = field(default_factory=list)
    blocked_calls: list[str] = field(default_factory=list)
    audit_latency_ms: float = 0.0


class ReactAgent:
    def __init__(
        self,
        policy: GuardPolicy,
        email_tool: MockEmailTool | None = None,
        memory_tool: MockMemoryTool | None = None,
        guard_enabled: bool = True,
    ):
        self.policy = policy
        self.email_tool = email_tool
        self.memory_tool = memory_tool
        self.explainer = ExplanationBuilder()
        self.guard_enabled = guard_enabled

    def run(self, task: dict[str, str]) -> RunResult:
        user_goal = task["user_goal"]
        events = [
            TraceEvent(
                event_id="goal-1",
                kind="user_goal",
                content=user_goal,
                trust=SourceTrust.TRUSTED,
            )
        ]

        observation = self._read_entry_tool(task["entry_tool"], events)
        final_answer = self._summarize(observation.content)
        decisions: list[GuardDecision] = []
        explanations: list[dict] = []
        blocked_calls: list[str] = []
        audit_latency_ms = 0.0

        recipient = self._select_recipient(user_goal, observation.content)
        if recipient:
            send_event = TraceEvent(
                event_id="call-2",
                kind="tool_call",
                content=f"send_email(to='{recipient}')",
                trust=SourceTrust.DERIVED,
                parents=[observation.event_id],
            )
            events.append(send_event)
            graph = CausalGraph(events)
            call = ToolCall(
                event_id=send_event.event_id,
                tool_name="send_email",
                arguments={"to": recipient, "body": final_answer},
                user_goal=user_goal,
            )

            if not self.guard_enabled:
                self._send_email(recipient, final_answer)
                return RunResult(
                    final_answer=final_answer,
                    events=events,
                    decisions=decisions,
                    explanations=explanations,
                    blocked_calls=blocked_calls,
                )

            audit_started = perf_counter()
            decision = self.policy.evaluate(call, graph)
            decisions.append(decision)

            if decision.decision == "allowed":
                self._send_email(recipient, final_answer)
            else:
                blocked_calls.append("send_email")
                explanations.append(self.explainer.build(call, decision, graph))
            audit_latency_ms += (perf_counter() - audit_started) * 1000

        return RunResult(
            final_answer=final_answer,
            events=events,
            decisions=decisions,
            explanations=explanations,
            blocked_calls=blocked_calls,
            audit_latency_ms=audit_latency_ms,
        )

    def _read_entry_tool(self, entry_tool: str, events: list[TraceEvent]) -> TraceEvent:
        call_id = "call-1"
        obs_id = "obs-1"
        events.append(
            TraceEvent(
                event_id=call_id,
                kind="tool_call",
                content=entry_tool,
                trust=SourceTrust.DERIVED,
                parents=["goal-1"],
            )
        )

        if entry_tool == "read_email":
            if self.email_tool is None:
                raise ValueError("read_email task requires an email tool")
            content = self.email_tool.read_email()
        elif entry_tool == "read_memory":
            if self.memory_tool is None:
                raise ValueError("read_memory task requires a memory tool")
            content = self.memory_tool.read_memory()
        else:
            raise ValueError(f"unsupported entry tool: {entry_tool}")

        observation = TraceEvent(
            event_id=obs_id,
            kind="tool_observation",
            content=content,
            trust=SourceTrust.UNTRUSTED,
            parents=[call_id],
        )
        events.append(observation)
        return observation

    def _send_email(self, recipient: str, body: str) -> None:
        if self.email_tool is None:
            raise ValueError("send_email requires an email tool")
        self.email_tool.send_email(to=recipient, body=body)

    def _extract_send_email_recipient(self, text: str) -> str | None:
        upper_text = text.upper()
        if "SEND_EMAIL" not in upper_text and "FORWARD" not in upper_text:
            return None
        match = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", text)
        if not match:
            return None
        return match.group(0)

    def _select_recipient(self, user_goal: str, observation: str) -> str | None:
        observation_recipient = self._extract_send_email_recipient(observation)
        if observation_recipient:
            return observation_recipient
        if not self._goal_requests_send(user_goal):
            return None
        goal_match = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", user_goal)
        return goal_match.group(0) if goal_match else None

    def _goal_requests_send(self, text: str) -> bool:
        lowered = text.lower()
        return "send email" in lowered or "reply to email" in lowered

    def _summarize(self, text: str) -> str:
        first_line = text.strip().splitlines()[0] if text.strip() else ""
        first_sentence = first_line.split(".")[0].strip()
        if not first_sentence:
            return "Summary: no content."
        return f"Summary: {first_sentence}."
