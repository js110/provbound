from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable

from causalguard.guard.trace_schema import SourceTrust, ToolCall


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


class DataCategory(str, Enum):
    GENERAL = "general"
    IDENTITY = "identity"
    CONTACT = "contact"
    FINANCIAL = "financial"
    CREDENTIAL = "credential"
    HEALTH = "health"
    PROJECT_CONFIDENTIAL = "project_confidential"


@dataclass(frozen=True)
class AuthorizationContract:
    contract_id: str
    action: str
    targets: frozenset[str]
    data_categories: frozenset[DataCategory]
    purpose: str
    scope: frozenset[str]
    allowed_sources: frozenset[str]
    valid_from: datetime
    expires_at: datetime
    session_id: str


@dataclass(frozen=True)
class Violation:
    predicate: str
    field: str
    expected: object = None
    actual: object = None


@dataclass(frozen=True)
class AuthorizationDecision:
    decision: Decision
    violations: tuple[Violation, ...]
    matched_contract_id: str | None = None


def evaluate_authorization(
    call: ToolCall,
    contracts: Iterable[AuthorizationContract],
    *,
    human_confirmed: bool = False,
) -> AuthorizationDecision:
    available = tuple(contracts)
    if not available:
        return AuthorizationDecision(
            decision=Decision.BLOCK,
            violations=(
                Violation(
                    predicate="missing_authorization",
                    field="contract",
                    expected="an applicable authorization contract",
                    actual=None,
                ),
            ),
        )
    missing_provenance = sorted(
        argument
        for argument in call.arguments
        if argument not in call.argument_provenance
        or not call.argument_provenance[argument]
    )
    if missing_provenance and not human_confirmed:
        return AuthorizationDecision(
            decision=Decision.REVIEW,
            violations=(
                Violation(
                    predicate="provenance_unknown",
                    field="argument_provenance",
                    expected="at least one origin for every argument",
                    actual=missing_provenance,
                ),
            ),
        )
    unknown_trust = sorted(
        argument
        for argument, trust in call.argument_trust.items()
        if trust == SourceTrust.UNKNOWN
    )
    if unknown_trust and not human_confirmed:
        return AuthorizationDecision(
            decision=Decision.REVIEW,
            violations=(
                Violation(
                    predicate="argument_trust_unknown",
                    field="argument_trust",
                    expected="trusted, untrusted, or derived provenance",
                    actual=unknown_trust,
                ),
            ),
        )
    routing_arguments = {"to", "target", "url", "file_id"}
    missing_categories = sorted(
        argument
        for argument in call.arguments
        if argument not in routing_arguments
        and (
            argument not in call.argument_data_categories
            or not call.argument_data_categories[argument]
        )
    )
    if missing_categories and not human_confirmed:
        return AuthorizationDecision(
            decision=Decision.REVIEW,
            violations=(
                Violation(
                    predicate="data_categories_unknown",
                    field="argument_data_categories",
                    expected="at least one category for every disclosed payload",
                    actual=missing_categories,
                ),
            ),
        )
    known_categories = {category.value for category in DataCategory}
    invalid_categories = sorted(
        {
            category
            for categories in call.argument_data_categories.values()
            for category in categories
            if category not in known_categories
        }
    )
    if invalid_categories:
        return AuthorizationDecision(
            decision=Decision.REVIEW,
            violations=(
                Violation(
                    predicate="data_category_invalid",
                    field="argument_data_categories",
                    expected=sorted(known_categories),
                    actual=invalid_categories,
                ),
            ),
        )
    if call.timestamp is None and not human_confirmed:
        return AuthorizationDecision(
            decision=Decision.REVIEW,
            violations=(
                Violation(
                    predicate="timestamp_unknown",
                    field="timestamp",
                    expected="an execution timestamp",
                    actual=None,
                ),
            ),
        )
    for contract in available:
        if _covers(contract, call):
            return AuthorizationDecision(
                decision=Decision.ALLOW,
                violations=(),
                matched_contract_id=contract.contract_id,
            )
    action_matches = [contract for contract in available if contract.action == call.tool_name]
    if action_matches:
        target = _call_target(call)
        target_matches = [
            contract
            for contract in action_matches
            if target in {item.lower() for item in contract.targets}
        ]
        if not target_matches:
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="target_not_authorized",
                        field="target",
                        expected=sorted(
                            {
                                item.lower()
                                for contract in action_matches
                                for item in contract.targets
                            }
                        ),
                        actual=target,
                    ),
                ),
            )
        categories = _call_categories(call)
        category_matches = [
            contract
            for contract in target_matches
            if categories.issubset(contract.data_categories)
        ]
        if not category_matches:
            authorized_categories = {
                category
                for contract in target_matches
                for category in contract.data_categories
            }
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="data_category_not_authorized",
                        field="data_categories",
                        expected=sorted(
                            category.value for category in authorized_categories
                        ),
                        actual=sorted(
                            category.value
                            for category in categories - authorized_categories
                        ),
                    ),
                ),
            )
        purpose = (call.purpose or "").strip().lower()
        purpose_matches = [
            contract
            for contract in category_matches
            if purpose == contract.purpose.strip().lower()
        ]
        if not purpose_matches:
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="purpose_not_authorized",
                        field="purpose",
                        expected=sorted(
                            {
                                contract.purpose.strip().lower()
                                for contract in category_matches
                            }
                        ),
                        actual=purpose,
                    ),
                ),
            )
        scope_matches = [
            contract
            for contract in purpose_matches
            if call.scope.issubset(contract.scope)
        ]
        if not scope_matches:
            authorized_scope = {
                item for contract in purpose_matches for item in contract.scope
            }
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="scope_not_authorized",
                        field="scope",
                        expected=sorted(authorized_scope),
                        actual=sorted(call.scope - authorized_scope),
                    ),
                ),
            )
        sources = _call_sources(call)
        source_matches = [
            contract
            for contract in scope_matches
            if _sources_authorized(sources, contract.allowed_sources)
        ]
        if not source_matches:
            authorized_sources = {
                source
                for contract in scope_matches
                for source in contract.allowed_sources
            }
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="source_not_authorized",
                        field="argument_provenance",
                        expected=sorted(authorized_sources),
                        actual=sorted(
                            source
                            for source in sources
                            if not _source_authorized(source, authorized_sources)
                        ),
                    ),
                ),
            )
        time_matches = source_matches
        if call.timestamp is not None:
            time_matches = [
                contract
                for contract in source_matches
                if contract.valid_from <= call.timestamp <= contract.expires_at
            ]
            if not time_matches and all(
                call.timestamp > contract.expires_at for contract in source_matches
            ):
                return AuthorizationDecision(
                    decision=Decision.BLOCK,
                    violations=(
                        Violation(
                            predicate="authorization_expired",
                            field="timestamp",
                            expected=max(
                                contract.expires_at for contract in source_matches
                            ).isoformat(),
                            actual=call.timestamp.isoformat(),
                        ),
                    ),
                )
            if not time_matches and all(
                call.timestamp < contract.valid_from for contract in source_matches
            ):
                return AuthorizationDecision(
                    decision=Decision.BLOCK,
                    violations=(
                        Violation(
                            predicate="authorization_not_yet_valid",
                            field="timestamp",
                            expected=min(
                                contract.valid_from for contract in source_matches
                            ).isoformat(),
                            actual=call.timestamp.isoformat(),
                        ),
                    ),
                )
        session_matches = [
            contract
            for contract in time_matches
            if call.session_id == contract.session_id
        ]
        if not session_matches:
            return AuthorizationDecision(
                decision=Decision.BLOCK,
                violations=(
                    Violation(
                        predicate="session_not_authorized",
                        field="session_id",
                        expected=sorted(
                            {contract.session_id for contract in time_matches}
                        ),
                        actual=call.session_id,
                    ),
                ),
            )
    else:
        return AuthorizationDecision(
            decision=Decision.BLOCK,
            violations=(
                Violation(
                    predicate="action_not_authorized",
                    field="action",
                    expected=sorted({contract.action for contract in available}),
                    actual=call.tool_name,
                ),
            ),
        )
    return AuthorizationDecision(
        decision=Decision.BLOCK,
        violations=(
            Violation(
                predicate="contract_mismatch",
                field="contract",
                expected="a contract covering every call dimension",
                actual=call.tool_name,
            ),
        ),
    )


def _covers(contract: AuthorizationContract, call: ToolCall) -> bool:
    target = _call_target(call)
    categories = _call_categories(call)
    sources = _call_sources(call)
    return all(
        (
            contract.action == call.tool_name,
            target in {item.lower() for item in contract.targets},
            categories.issubset(contract.data_categories),
            (call.purpose or "").strip().lower() == contract.purpose.strip().lower(),
            call.scope.issubset(contract.scope),
            _sources_authorized(sources, contract.allowed_sources),
            call.timestamp is not None,
            call.timestamp is not None and contract.valid_from <= call.timestamp <= contract.expires_at,
            call.session_id == contract.session_id,
        )
    )


def _call_target(call: ToolCall) -> str:
    return str(
        call.arguments.get("to")
        or call.arguments.get("target")
        or call.arguments.get("url")
        or call.arguments.get("file_id")
        or ""
    ).strip().lower()


def _call_categories(call: ToolCall) -> set[DataCategory]:
    return {
        DataCategory(category)
        for values in call.argument_data_categories.values()
        for category in values
    }


def _call_sources(call: ToolCall) -> set[str]:
    return {
        source
        for values in call.argument_provenance.values()
        for source in values
    }


def _sources_authorized(
    sources: set[str],
    allowed_sources: frozenset[str] | set[str],
) -> bool:
    return all(_source_authorized(source, allowed_sources) for source in sources)


def _source_authorized(
    source: str,
    allowed_sources: frozenset[str] | set[str],
) -> bool:
    return any(
        source == allowed or source.startswith(f"{allowed}:")
        for allowed in allowed_sources
    )
