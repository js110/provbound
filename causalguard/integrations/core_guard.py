from dataclasses import dataclass, replace
from typing import Iterable, Mapping

from causalguard.guard.authorization import (
    AuthorizationContract,
    AuthorizationDecision,
    DataCategory,
    Decision,
    evaluate_authorization,
)
from causalguard.guard.disclosure import (
    DisclosureDisposition,
    DisclosureResult,
    DisclosureStrategy,
    minimize_disclosure,
)
from causalguard.guard.certificate import build_decision_certificate
from causalguard.guard.trace_schema import ToolCall


@dataclass(frozen=True)
class CoreGuardResult:
    decision: Decision
    arguments: dict[str, object]
    authorization: AuthorizationDecision
    disclosure: DisclosureResult
    certificate: dict[str, object] | None = None


class CoreGuard:
    def evaluate(
        self,
        call: ToolCall,
        *,
        contracts: Iterable[AuthorizationContract],
        disclosure_strategies: Mapping[
            DataCategory, DisclosureStrategy
        ] | None = None,
        human_confirmed: bool = False,
    ) -> CoreGuardResult:
        available = tuple(contracts)
        authorization = evaluate_authorization(
            call,
            available,
            human_confirmed=human_confirmed,
        )
        pass_disclosure = DisclosureResult(
            disposition=DisclosureDisposition.PASS,
            arguments=dict(call.arguments),
        )
        predicates = {
            violation.predicate for violation in authorization.violations
        }
        if authorization.decision != Decision.BLOCK or predicates != {
            "data_category_not_authorized"
        }:
            return _core_result(
                call=call,
                decision=authorization.decision,
                arguments=dict(call.arguments),
                authorization=authorization,
                disclosure=pass_disclosure,
                contracts=available,
            )

        candidates = [
            contract
            for contract in available
            if contract.action == call.tool_name
            and _target(call) in {target.lower() for target in contract.targets}
        ]
        if not candidates:
            return _core_result(
                call=call,
                decision=authorization.decision,
                arguments=dict(call.arguments),
                authorization=authorization,
                disclosure=pass_disclosure,
                contracts=available,
            )
        allowed_categories = {
            category
            for contract in candidates
            for category in contract.data_categories
        }
        disclosure = minimize_disclosure(
            call,
            allowed_categories=allowed_categories,
            strategies=disclosure_strategies or {},
        )
        if disclosure.disposition == DisclosureDisposition.BLOCKED:
            return _core_result(
                call=call,
                decision=Decision.BLOCK,
                arguments={},
                authorization=authorization,
                disclosure=disclosure,
                contracts=available,
            )

        remaining = set(disclosure.arguments)
        sanitized_call = replace(
            call,
            arguments=disclosure.arguments,
            argument_provenance={
                key: value
                for key, value in call.argument_provenance.items()
                if key in remaining
            },
            argument_trust={
                key: value
                for key, value in call.argument_trust.items()
                if key in remaining
            },
            argument_data_categories={
                key: value
                for key, value in call.argument_data_categories.items()
                if key in remaining
            },
        )
        sanitized_authorization = evaluate_authorization(
            sanitized_call,
            available,
            human_confirmed=human_confirmed,
        )
        return _core_result(
            call=sanitized_call,
            decision=sanitized_authorization.decision,
            arguments=disclosure.arguments,
            authorization=sanitized_authorization,
            disclosure=disclosure,
            contracts=available,
        )


def _target(call: ToolCall) -> str:
    return str(
        call.arguments.get("to")
        or call.arguments.get("target")
        or call.arguments.get("url")
        or call.arguments.get("file_id")
        or ""
    ).strip().lower()


def _core_result(
    *,
    call: ToolCall,
    decision: Decision,
    arguments: dict[str, object],
    authorization: AuthorizationDecision,
    disclosure: DisclosureResult,
    contracts: tuple[AuthorizationContract, ...],
) -> CoreGuardResult:
    certificate = (
        build_decision_certificate(
            call,
            authorization,
            contracts=contracts,
        )
        if decision != Decision.ALLOW
        else None
    )
    return CoreGuardResult(
        decision=decision,
        arguments=arguments,
        authorization=authorization,
        disclosure=disclosure,
        certificate=certificate,
    )
