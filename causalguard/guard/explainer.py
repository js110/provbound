from causalguard.guard.causal_graph import CausalGraph
from causalguard.guard.policy import GuardDecision
from causalguard.guard.trace_schema import ToolCall


class ExplanationBuilder:
    def build(self, call: ToolCall, decision: GuardDecision, graph: CausalGraph) -> dict:
        path = graph.shortest_untrusted_path_to(call.event_id)
        return {
            "decision": decision.decision,
            "tool": call.tool_name,
            "risks": decision.risks,
            "reason": decision.reason,
            "causal_path": [
                {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "trust": event.trust.value,
                    "content": event.content,
                }
                for event in path
            ],
            "explanation": self._explain(call, decision, bool(path)),
        }

    def _explain(self, call: ToolCall, decision: GuardDecision, has_untrusted_path: bool) -> str:
        if decision.decision == "blocked" and has_untrusted_path:
            return (
                f"工具 {call.tool_name} 被阻断，因为该危险调用受到外部不可信内容影响，"
                "且用户原始目标未明确授权该外部副作用。"
            )
        if decision.decision == "review":
            return f"工具 {call.tool_name} 需要人工确认，因为用户目标未明确授权该高风险操作。"
        return f"工具 {call.tool_name} 被放行，因为调用与可信用户意图一致。"
