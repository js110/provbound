from dataclasses import dataclass, field
import json
from typing import Any, Callable, Iterable, Mapping

from causalguard.guard.authorization import AuthorizationContract, DataCategory, Decision
from causalguard.guard.disclosure import DisclosureStrategy
from causalguard.guard.trace_schema import ToolCall
from causalguard.integrations.core_guard import CoreGuard


@dataclass(frozen=True)
class PreExecutionResult:
    execute: bool
    arguments: dict[str, Any]
    tool_message: str
    decision: str


@dataclass
class CoreGuardPreExecution:
    """Framework-neutral pre-commit adapter around the single CoreGuard policy."""

    contracts: Iterable[AuthorizationContract]
    call_factory: Callable[[str, dict[str, Any]], ToolCall]
    disclosure_strategies: Mapping[
        DataCategory, DisclosureStrategy
    ] | None = None
    human_confirmed: bool = False
    guard: CoreGuard = field(default_factory=CoreGuard)

    def __post_init__(self) -> None:
        self.contracts = tuple(self.contracts)

    def __call__(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> PreExecutionResult:
        call = self.call_factory(tool_name, dict(arguments))
        result = self.guard.evaluate(
            call,
            contracts=self.contracts,
            disclosure_strategies=self.disclosure_strategies,
            human_confirmed=self.human_confirmed,
        )
        execute = result.decision == Decision.ALLOW
        feedback = {
            "decision": result.decision.value,
            "executed": execute,
            "violations": [
                {
                    "predicate": violation.predicate,
                    "field": violation.field,
                }
                for violation in result.authorization.violations
            ],
            "certificate": result.certificate,
        }
        return PreExecutionResult(
            execute=execute,
            arguments=dict(result.arguments),
            tool_message=json.dumps(
                feedback,
                ensure_ascii=False,
                sort_keys=True,
            ),
            decision=result.decision.value,
        )
