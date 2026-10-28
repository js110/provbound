from dataclasses import dataclass, field
import re

from causalguard.guard.causal_graph import CausalGraph
from causalguard.guard.trace_schema import ToolCall


@dataclass(frozen=True)
class ToolSpec:
    name: str
    side_effect: bool
    risk_level: str
    allowed_intents: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class GuardDecision:
    decision: str
    risks: list[str]
    reason: str


@dataclass(frozen=True)
class Authorization:
    action: str
    targets: set[str] = field(default_factory=set)
    scope: str = "current_task"
    allowed_sources: set[str] = field(default_factory=lambda: {"user_goal", "selected_observation"})
    duration: str = "single_turn"

    def allows(self, call: ToolCall) -> bool:
        target = str(call.arguments.get("to", "")).lower()
        if self.action != action_for_tool(call.tool_name):
            return False
        if self.targets and target not in self.targets:
            return False
        return True


def extract_authorizations(user_goal: str) -> list[Authorization]:
    lowered = user_goal.lower()
    if "send email" not in lowered and "reply to email" not in lowered:
        return []
    targets = {item.lower() for item in re.findall(r"[\w.\-+]+@[\w.\-]+\.\w+", user_goal)}
    return [Authorization(action="send_email", targets=targets)]


def action_for_tool(tool_name: str) -> str:
    return tool_name


class GuardPolicy:
    def __init__(self, tools: dict[str, ToolSpec]):
        self.tools = tools

    def evaluate(self, call: ToolCall, graph: CausalGraph) -> GuardDecision:
        spec = self.tools.get(call.tool_name)
        if spec is None:
            return GuardDecision("blocked", ["unknown_tool"], "unknown tool cannot be audited")

        user_goal = call.user_goal.lower()
        goal_allows_tool = any(intent.lower() in user_goal for intent in spec.allowed_intents)
        auth_allows_call = any(auth.allows(call) for auth in extract_authorizations(call.user_goal))
        has_untrusted_context = graph.has_untrusted_influence(call.event_id)
        target_mismatch = self._target_mismatch(call)

        if spec.side_effect and spec.risk_level == "high" and has_untrusted_context and not goal_allows_tool:
            return GuardDecision(
                decision="blocked",
                risks=["goal_hijacking", "tool_misuse"],
                reason="high-risk side-effect tool call is driven by untrusted context outside the user goal",
            )

        if spec.side_effect and spec.risk_level == "high" and has_untrusted_context and (target_mismatch or not auth_allows_call):
            return GuardDecision(
                decision="blocked",
                risks=["parameter_pollution", "untrusted_parameter_source"],
                reason="high-risk tool target is supplied by untrusted context and differs from user authorization",
            )

        if spec.side_effect and spec.risk_level == "high" and not goal_allows_tool:
            return GuardDecision(
                decision="review",
                risks=["tool_misuse"],
                reason="high-risk side-effect tool call is not explicitly supported by the user goal",
            )

        return GuardDecision("allowed", [], "tool call is consistent with trusted user intent")

    def _target_mismatch(self, call: ToolCall) -> bool:
        recipient = str(call.arguments.get("to", "")).lower()
        if not recipient:
            return False
        return recipient not in call.user_goal.lower()
