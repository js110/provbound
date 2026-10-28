from datetime import datetime
import re
from typing import Any

from causalguard.guard.authorization import AuthorizationContract, DataCategory
from causalguard.guard.capability_registry import CapabilityRegistry, CapabilityValue
from causalguard.guard.trace_schema import SourceTrust, ToolCall


def build_scenario_capabilities(
    scenario: dict[str, Any],
    variant: dict[str, Any],
) -> CapabilityRegistry:
    state = scenario["initial_state"]
    payload_field = state["payload_field"]
    resource_ref = f"{state['resource']}:{payload_field}"
    registry = CapabilityRegistry()
    registry.issue(
        "user_goal:target",
        value=state["authorized_target"],
        origin="user_goal:target",
        trust=SourceTrust.TRUSTED,
        data_categories=(),
    )
    registry.issue(
        resource_ref,
        value=state["payload"],
        origin=resource_ref,
        trust=SourceTrust.DERIVED,
        data_categories=scenario["data_category_gold"].get(
            payload_field, ["general"]
        ),
    )
    registry.issue(
        "untrusted:external_observation",
        value=variant["untrusted_observation"],
        origin="untrusted:external_observation",
        trust=SourceTrust.UNTRUSTED,
        data_categories=("general",),
    )
    for index, target in enumerate(
        _extract_external_targets(variant["untrusted_observation"])
    ):
        ref = f"untrusted:external_observation:target:{index}"
        registry.issue(
            ref,
            value=target,
            origin=ref,
            trust=SourceTrust.UNTRUSTED,
            data_categories=(),
        )
    return registry


def compile_runtime_tool_call(
    tool_name: str,
    generic: dict[str, Any],
    scenario: dict[str, Any],
    registry: CapabilityRegistry,
) -> ToolCall:
    state = scenario["initial_state"]
    auth = scenario["authorization_gold"]
    payload_field = state["payload_field"]
    target_ref = str(generic.get("target_ref", ""))
    payload_ref = str(generic.get("payload_ref", ""))
    target_capability = _resolve_optional(registry, target_ref)
    payload_capability = _resolve_optional(registry, payload_ref)
    arguments: dict[str, Any] = {
        "target": (
            target_capability.value
            if target_capability is not None
            else f"unknown-ref:{target_ref}"
        ),
        payload_field: (
            payload_capability.value
            if payload_capability is not None
            else f"unknown-ref:{payload_ref}"
        ),
    }
    provenance = {
        "target": (
            target_capability.origins
            if target_capability is not None
            else frozenset()
        ),
        payload_field: (
            payload_capability.origins
            if payload_capability is not None
            else frozenset()
        ),
    }
    trust = {
        "target": (
            target_capability.trust
            if target_capability is not None
            else SourceTrust.UNKNOWN
        ),
        payload_field: (
            payload_capability.trust
            if payload_capability is not None
            else SourceTrust.UNKNOWN
        ),
    }
    categories = {
        payload_field: (
            payload_capability.data_categories
            if payload_capability is not None
            else frozenset()
        )
    }
    return ToolCall(
        event_id=f"runtime:{scenario['base_scenario_id']}",
        tool_name=tool_name,
        arguments=arguments,
        user_goal=scenario["user_goal"],
        argument_provenance=provenance,
        argument_trust=trust,
        argument_data_categories=categories,
        purpose=auth["purpose"],
        scope=frozenset(auth["scope"]),
        timestamp=datetime.fromisoformat("2026-07-18T12:00:00+00:00"),
        session_id=auth["session_id"],
    )


def build_scenario_contract(scenario: dict[str, Any]) -> AuthorizationContract:
    auth = scenario["authorization_gold"]
    return AuthorizationContract(
        contract_id=f"runtime-auth:{scenario['base_scenario_id']}",
        action=auth["action"],
        targets=frozenset(auth["targets"]),
        data_categories=frozenset(
            DataCategory(item) for item in auth["data_categories"]
        ),
        purpose=auth["purpose"],
        scope=frozenset(auth["scope"]),
        allowed_sources=frozenset(auth["allowed_sources"]),
        valid_from=datetime.fromisoformat(auth["validity"]["valid_from"]),
        expires_at=datetime.fromisoformat(auth["validity"]["expires_at"]),
        session_id=auth["session_id"],
    )


def _extract_external_targets(text: str) -> list[str]:
    candidates = re.findall(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|https?://[^\s,;]+|"
        r"(?<![\w@])(?:[A-Za-z0-9-]+\.)+(?:test|invalid|example|com|org|net)(?![\w@])",
        text,
    )
    return list(dict.fromkeys(item.rstrip(".\")']}") for item in candidates))


def _resolve_optional(
    registry: CapabilityRegistry,
    ref: str,
) -> CapabilityValue | None:
    try:
        return registry.resolve(ref)
    except KeyError:
        return None
