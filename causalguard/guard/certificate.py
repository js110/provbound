from dataclasses import dataclass
from datetime import datetime
from copy import deepcopy
from typing import Any, Iterable

from causalguard.guard.authorization import (
    AuthorizationContract,
    AuthorizationDecision,
    DataCategory,
)
from causalguard.guard.trace_schema import SourceTrust, ToolCall


ROUTING_ARGUMENTS = ("to", "target", "url", "file_id")


@dataclass(frozen=True)
class CertificateVerification:
    valid: bool
    proved_predicates: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CertificateMinimality:
    minimal: bool
    removable_evidence_paths: tuple[str, ...] = ()


def build_decision_certificate(
    call: ToolCall,
    decision: AuthorizationDecision,
    *,
    contracts: Iterable[AuthorizationContract] = (),
) -> dict[str, Any]:
    predicates = {violation.predicate for violation in decision.violations}
    argument_evidence: dict[str, dict[str, Any]] = {}
    context_evidence: dict[str, Any] = {}
    available = tuple(contracts)

    if "missing_authorization" in predicates:
        context_evidence["contract_ids"] = sorted(
            contract.contract_id for contract in available
        )
    if "provenance_unknown" in predicates:
        context_evidence["call_argument_names"] = sorted(call.arguments)
        context_evidence["provenance_argument_names"] = sorted(
            name
            for name, origins in call.argument_provenance.items()
            if origins
        )
    if "argument_trust_unknown" in predicates:
        violation = _violation(decision, "argument_trust_unknown")
        for name in violation.actual or []:
            argument_evidence[name] = {
                "trust": call.argument_trust.get(name, SourceTrust.UNKNOWN).value,
                "origin_ids": sorted(call.argument_provenance.get(name, ())),
            }
    if "data_categories_unknown" in predicates:
        payload_names = sorted(
            name for name in call.arguments if name not in ROUTING_ARGUMENTS
        )
        context_evidence["payload_argument_names"] = payload_names
        context_evidence["categorized_argument_names"] = sorted(
            name
            for name in payload_names
            if call.argument_data_categories.get(name)
        )
    if "data_category_invalid" in predicates:
        violation = _violation(decision, "data_category_invalid")
        invalid = set(violation.actual or [])
        _add_category_argument_evidence(
            call,
            argument_evidence,
            selected_categories=invalid,
        )
    if "timestamp_unknown" in predicates:
        context_evidence["timestamp"] = (
            call.timestamp.isoformat() if call.timestamp is not None else None
        )
    if "target_not_authorized" in predicates:
        target_argument = next(
            (name for name in ROUTING_ARGUMENTS if name in call.arguments),
            None,
        )
        if target_argument is not None:
            argument_evidence[target_argument] = {
                "value": call.arguments[target_argument],
                "origin_ids": sorted(
                    call.argument_provenance.get(target_argument, ())
                ),
            }
    if "data_category_not_authorized" in predicates:
        violation = _violation(decision, "data_category_not_authorized")
        _add_category_argument_evidence(
            call,
            argument_evidence,
            selected_categories=set(violation.actual or []),
        )
    if "purpose_not_authorized" in predicates:
        context_evidence["purpose"] = call.purpose
    if "scope_not_authorized" in predicates:
        context_evidence["scope"] = sorted(call.scope)
    if "source_not_authorized" in predicates:
        violation = _violation(decision, "source_not_authorized")
        unauthorized = set(violation.actual or [])
        for name, origins in call.argument_provenance.items():
            relevant = set(origins) & unauthorized
            if relevant:
                argument_evidence[name] = {"origin_ids": sorted(relevant)}
    if predicates & {"authorization_expired", "authorization_not_yet_valid"}:
        context_evidence["timestamp"] = (
            call.timestamp.isoformat() if call.timestamp is not None else None
        )
    if "session_not_authorized" in predicates:
        context_evidence["session_id"] = call.session_id
    if "action_not_authorized" in predicates:
        context_evidence["action"] = call.tool_name

    return {
        "schema_version": "1.0",
        "decision": decision.decision.value,
        "tool": call.tool_name,
        "contract_id": decision.matched_contract_id,
        "violations": [
            {
                "predicate": violation.predicate,
                "field": violation.field,
                "expected": violation.expected,
                "actual": violation.actual,
            }
            for violation in decision.violations
        ],
        "argument_evidence": argument_evidence,
        "context_evidence": context_evidence,
    }


def verify_decision_certificate(
    certificate: dict[str, Any],
) -> CertificateVerification:
    errors: list[str] = []
    proved: list[str] = []
    if certificate.get("schema_version") != "1.0":
        errors.append("unsupported schema_version")
    if certificate.get("decision") not in {"allow", "block", "review"}:
        errors.append("invalid decision")
    if not isinstance(certificate.get("tool"), str) or not certificate.get("tool"):
        errors.append("tool must be a non-empty string")

    violations = certificate.get("violations")
    argument_evidence = certificate.get("argument_evidence")
    context_evidence = certificate.get("context_evidence")
    if not isinstance(violations, list):
        errors.append("violations must be a list")
        violations = []
    if not isinstance(argument_evidence, dict):
        errors.append("argument_evidence must be an object")
        argument_evidence = {}
    if not isinstance(context_evidence, dict):
        errors.append("context_evidence must be an object")
        context_evidence = {}

    verifiers = {
        "missing_authorization": _verify_missing_authorization,
        "provenance_unknown": _verify_provenance_unknown,
        "argument_trust_unknown": _verify_argument_trust_unknown,
        "data_categories_unknown": _verify_data_categories_unknown,
        "data_category_invalid": _verify_data_category_invalid,
        "timestamp_unknown": _verify_timestamp_unknown,
        "target_not_authorized": _verify_target_not_authorized,
        "data_category_not_authorized": _verify_data_category_not_authorized,
        "purpose_not_authorized": _verify_purpose_not_authorized,
        "scope_not_authorized": _verify_scope_not_authorized,
        "source_not_authorized": _verify_source_not_authorized,
        "authorization_expired": _verify_authorization_expired,
        "authorization_not_yet_valid": _verify_authorization_not_yet_valid,
        "session_not_authorized": _verify_session_not_authorized,
        "action_not_authorized": _verify_action_not_authorized,
    }
    for violation in violations:
        predicate = violation.get("predicate") if isinstance(violation, dict) else None
        verifier = verifiers.get(predicate)
        if verifier is None:
            errors.append(f"unsupported predicate: {predicate}")
            continue
        before = len(errors)
        verifier(violation, argument_evidence, context_evidence, errors)
        if len(errors) == before:
            proved.append(predicate)

    if certificate.get("decision") in {"block", "review"} and not violations:
        errors.append("non-allow certificate requires a proved predicate")
    if len(proved) != len(violations):
        errors.append("not every violation was proved")
    return CertificateVerification(
        valid=not errors,
        proved_predicates=tuple(proved) if not errors else (),
        errors=tuple(errors),
    )


def verify_certificate_minimality(
    certificate: dict[str, Any],
) -> CertificateMinimality:
    if not verify_decision_certificate(certificate).valid:
        return CertificateMinimality(
            minimal=False,
            removable_evidence_paths=("<certificate-invalid>",),
        )
    candidates: list[tuple[str, tuple[str, ...]]] = []
    for key in certificate.get("context_evidence", {}):
        candidates.append((f"context_evidence.{key}", ("context_evidence", key)))
    for argument, item in certificate.get("argument_evidence", {}).items():
        candidates.append(
            (
                f"argument_evidence.{argument}",
                ("argument_evidence", argument),
            )
        )
        if isinstance(item, dict):
            for key in item:
                candidates.append(
                    (
                        f"argument_evidence.{argument}.{key}",
                        ("argument_evidence", argument, key),
                    )
                )

    removable: list[str] = []
    for label, path in candidates:
        reduced = deepcopy(certificate)
        parent: Any = reduced
        for segment in path[:-1]:
            parent = parent[segment]
        del parent[path[-1]]
        if verify_decision_certificate(reduced).valid:
            removable.append(label)
    return CertificateMinimality(
        minimal=not removable,
        removable_evidence_paths=tuple(removable),
    )


def explain_verified_certificate(certificate: dict[str, Any]) -> str:
    verification = verify_decision_certificate(certificate)
    if not verification.valid:
        raise ValueError(
            "cannot explain an invalid certificate: "
            + "; ".join(verification.errors)
        )
    violation = certificate["violations"][0]
    predicate = violation["predicate"]
    if predicate == "target_not_authorized":
        expected = "、".join(violation["expected"])
        return (
            f"工具 {certificate['tool']} 被阻断：实际目标 {violation['actual']} "
            f"不在授权目标集合 {expected} 中，且该目标具有可核验的参数来源。"
        )
    labels = {
        "missing_authorization": "缺少适用授权",
        "provenance_unknown": "参数来源不完整",
        "argument_trust_unknown": "参数信任状态未知",
        "data_categories_unknown": "披露数据类别未知",
        "data_category_invalid": "数据类别标签无效",
        "timestamp_unknown": "执行时间未知",
        "data_category_not_authorized": "数据类别超出授权",
        "purpose_not_authorized": "使用目的超出授权",
        "scope_not_authorized": "资源范围超出授权",
        "source_not_authorized": "参数来源超出授权",
        "authorization_expired": "授权已经过期",
        "authorization_not_yet_valid": "授权尚未生效",
        "session_not_authorized": "授权不属于当前会话",
        "action_not_authorized": "动作未获授权",
    }
    return (
        f"工具 {certificate['tool']} 的决策为 {certificate['decision']}："
        f"{labels[predicate]}；实际证据为 {violation['actual']}，"
        f"授权约束为 {violation['expected']}。"
    )


def _violation(
    decision: AuthorizationDecision,
    predicate: str,
) -> Any:
    return next(item for item in decision.violations if item.predicate == predicate)


def _add_category_argument_evidence(
    call: ToolCall,
    evidence: dict[str, dict[str, Any]],
    *,
    selected_categories: set[str],
) -> None:
    for name, categories in call.argument_data_categories.items():
        relevant = set(categories) & selected_categories
        if relevant:
            evidence[name] = {
                "data_categories": sorted(relevant),
                "origin_ids": sorted(call.argument_provenance.get(name, ())),
            }


def _verify_missing_authorization(v, a, c, errors):
    if v.get("field") != "contract" or v.get("actual") is not None:
        errors.append("malformed missing authorization violation")
    if c != {"contract_ids": []}:
        errors.append("missing authorization requires an empty contract set")


def _verify_provenance_unknown(v, a, c, errors):
    actual = _nonempty_string_list(v.get("actual"), "missing provenance", errors)
    call_names = _string_list(c.get("call_argument_names"), "call arguments", errors)
    provenance_names = _string_list(
        c.get("provenance_argument_names"), "provenance arguments", errors
    )
    if set(actual) != set(call_names) - set(provenance_names):
        errors.append("missing provenance set does not match context evidence")


def _verify_argument_trust_unknown(v, a, c, errors):
    actual = _nonempty_string_list(v.get("actual"), "unknown trust arguments", errors)
    if set(a) != set(actual):
        errors.append("trust evidence arguments do not match violation")
    for name in actual:
        item = a.get(name, {})
        if item.get("trust") != SourceTrust.UNKNOWN.value:
            errors.append(f"argument is not marked unknown: {name}")
        if not _is_nonempty_string_list(item.get("origin_ids")):
            errors.append(f"unknown trust argument lacks origins: {name}")


def _verify_data_categories_unknown(v, a, c, errors):
    actual = _nonempty_string_list(v.get("actual"), "uncategorized arguments", errors)
    payload = _string_list(c.get("payload_argument_names"), "payload arguments", errors)
    categorized = _string_list(
        c.get("categorized_argument_names"), "categorized arguments", errors
    )
    if set(actual) != set(payload) - set(categorized):
        errors.append("uncategorized argument set does not match context evidence")


def _verify_data_category_invalid(v, a, c, errors):
    expected = _nonempty_string_list(v.get("expected"), "known categories", errors)
    actual = _nonempty_string_list(v.get("actual"), "invalid categories", errors)
    evidenced = _verified_category_evidence(a, errors)
    if set(actual) & set(expected):
        errors.append("invalid categories overlap known categories")
    if set(actual) != evidenced:
        errors.append("invalid category evidence does not match violation")


def _verify_timestamp_unknown(v, a, c, errors):
    if v.get("field") != "timestamp" or v.get("actual") is not None:
        errors.append("malformed unknown timestamp violation")
    if c != {"timestamp": None}:
        errors.append("unknown timestamp evidence must be null and minimal")


def _verify_target_not_authorized(v, a, c, errors):
    expected = _nonempty_string_list(v.get("expected"), "authorized targets", errors)
    actual = v.get("actual")
    if v.get("field") != "target" or not isinstance(actual, str) or not actual:
        errors.append("malformed target violation")
    if actual in expected:
        errors.append("actual target is authorized")
    target_names = [name for name in ROUTING_ARGUMENTS if name in a]
    if len(target_names) != 1:
        errors.append("certificate must contain exactly one target argument")
        return
    item = a[target_names[0]]
    if set(item) != {"value", "origin_ids"}:
        errors.append("target evidence is not minimal")
    if item.get("value") != actual:
        errors.append("target evidence does not match actual target")
    if not _is_nonempty_string_list(item.get("origin_ids")):
        errors.append("target origin evidence is missing")


def _verify_data_category_not_authorized(v, a, c, errors):
    expected = _string_list(v.get("expected"), "allowed categories", errors)
    actual = _nonempty_string_list(v.get("actual"), "unauthorized categories", errors)
    evidenced = _verified_category_evidence(a, errors)
    if set(actual) & set(expected):
        errors.append("unauthorized categories overlap allowed categories")
    if set(actual) != evidenced:
        errors.append("unauthorized category evidence does not match violation")


def _verify_purpose_not_authorized(v, a, c, errors):
    expected = _nonempty_string_list(v.get("expected"), "authorized purposes", errors)
    actual = v.get("actual")
    if v.get("field") != "purpose" or not isinstance(actual, str) or not actual:
        errors.append("malformed purpose violation")
    if actual in expected:
        errors.append("actual purpose is authorized")
    if c != {"purpose": actual}:
        errors.append("purpose evidence is absent, inconsistent, or non-minimal")


def _verify_scope_not_authorized(v, a, c, errors):
    expected = _string_list(v.get("expected"), "authorized scope", errors)
    actual = _nonempty_string_list(v.get("actual"), "scope expansion", errors)
    scope = _nonempty_string_list(c.get("scope"), "actual scope", errors)
    if v.get("field") != "scope":
        errors.append("scope violation must name scope field")
    if set(actual) != set(scope) - set(expected):
        errors.append("scope expansion does not match context evidence")


def _verify_source_not_authorized(v, a, c, errors):
    expected = _string_list(v.get("expected"), "authorized sources", errors)
    actual = _nonempty_string_list(v.get("actual"), "unauthorized sources", errors)
    evidenced: set[str] = set()
    for name, item in a.items():
        origins = item.get("origin_ids")
        if not _is_nonempty_string_list(origins):
            errors.append(f"source evidence lacks origins: {name}")
            continue
        evidenced.update(origins)
    if set(actual) != evidenced:
        errors.append("source evidence does not match violation")
    for source in actual:
        if any(source == allowed or source.startswith(f"{allowed}:") for allowed in expected):
            errors.append("claimed unauthorized source is authorized")


def _verify_authorization_expired(v, a, c, errors):
    _verify_time_order(v, c, errors, relation="expired")


def _verify_authorization_not_yet_valid(v, a, c, errors):
    _verify_time_order(v, c, errors, relation="not_yet_valid")


def _verify_time_order(v, c, errors, *, relation: str):
    expected = _parse_datetime(v.get("expected"), "authorization boundary", errors)
    actual = _parse_datetime(v.get("actual"), "execution timestamp", errors)
    if v.get("field") != "timestamp":
        errors.append("time violation must name timestamp field")
    if c != {"timestamp": v.get("actual")}:
        errors.append("timestamp evidence is absent, inconsistent, or non-minimal")
    if expected is not None and actual is not None:
        if relation == "expired" and not actual > expected:
            errors.append("execution timestamp is not after expiration")
        if relation == "not_yet_valid" and not actual < expected:
            errors.append("execution timestamp is not before valid_from")


def _verify_session_not_authorized(v, a, c, errors):
    expected = _nonempty_string_list(v.get("expected"), "authorized sessions", errors)
    actual = v.get("actual")
    if v.get("field") != "session_id" or not isinstance(actual, str) or not actual:
        errors.append("malformed session violation")
    if actual in expected:
        errors.append("actual session is authorized")
    if c != {"session_id": actual}:
        errors.append("session evidence is absent, inconsistent, or non-minimal")


def _verify_action_not_authorized(v, a, c, errors):
    expected = _nonempty_string_list(v.get("expected"), "authorized actions", errors)
    actual = v.get("actual")
    if v.get("field") != "action" or not isinstance(actual, str) or not actual:
        errors.append("malformed action violation")
    if actual in expected:
        errors.append("actual action is authorized")
    if c != {"action": actual}:
        errors.append("action evidence is absent, inconsistent, or non-minimal")


def _verified_category_evidence(a, errors) -> set[str]:
    evidenced: set[str] = set()
    if not a:
        errors.append("category argument evidence is missing")
    for name, item in a.items():
        if set(item) != {"data_categories", "origin_ids"}:
            errors.append(f"category evidence is not minimal: {name}")
        categories = item.get("data_categories")
        origins = item.get("origin_ids")
        if not _is_nonempty_string_list(categories):
            errors.append(f"category evidence is missing: {name}")
        else:
            evidenced.update(categories)
        if not _is_nonempty_string_list(origins):
            errors.append(f"category origin evidence is missing: {name}")
    return evidenced


def _parse_datetime(value, label, errors):
    if not isinstance(value, str):
        errors.append(f"{label} must be an ISO timestamp")
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        errors.append(f"{label} is not a valid ISO timestamp")
        return None


def _nonempty_string_list(value, label, errors) -> list[str]:
    result = _string_list(value, label, errors)
    if not result:
        errors.append(f"{label} must not be empty")
    return result


def _string_list(value, label, errors) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{label} must be a string list")
        return []
    return value


def _is_nonempty_string_list(value) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item for item in value)
    )
