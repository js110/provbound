from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


DOMAINS = {"email", "calendar", "files", "memory", "network"}
DECISIONS = {"allow", "block", "review"}
REQUIRED_FIELDS = {
    "base_scenario_id",
    "domain",
    "semantic_cluster",
    "split",
    "attack_family",
    "tool",
    "user_goal",
    "initial_state",
    "authorization_gold",
    "provenance_gold",
    "data_category_gold",
    "variants",
    "checkers",
}
SCHEMA_PATH = Path(__file__).resolve().parent / "datasets" / "schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_VALIDATOR = Draft202012Validator(
    SCHEMA,
    format_checker=FormatChecker(),
)


@dataclass(frozen=True)
class DatasetValidationReport:
    scenario_count: int
    domain_counts: dict[str, int]
    attack_families: tuple[str, ...]
    errors: tuple[str, ...]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"scenario at {path}:{line_number} must be an object")
            scenarios.append(value)
    return scenarios


def validate_base_scenarios(
    scenarios: list[dict[str, Any]],
) -> DatasetValidationReport:
    errors: list[str] = []
    ids: set[str] = set()
    clusters_by_split: dict[str, set[str]] = {"dev": set(), "test": set()}
    goals: set[str] = set()
    domains: Counter[str] = Counter()
    families: set[str] = set()

    for index, scenario in enumerate(scenarios, start=1):
        label = scenario.get("base_scenario_id", f"row-{index}")
        for schema_error in sorted(
            SCHEMA_VALIDATOR.iter_errors(scenario),
            key=lambda item: list(item.absolute_path),
        ):
            location = ".".join(str(item) for item in schema_error.absolute_path)
            errors.append(
                f"{label}: schema {location or '<root>'}: {schema_error.message}"
            )
        missing = REQUIRED_FIELDS - set(scenario)
        if missing:
            errors.append(f"{label}: missing fields {sorted(missing)}")
            continue
        scenario_id = scenario["base_scenario_id"]
        if scenario_id in ids:
            errors.append(f"{label}: duplicate base_scenario_id")
        ids.add(scenario_id)
        domain = scenario["domain"]
        if domain not in DOMAINS:
            errors.append(f"{label}: unsupported domain {domain}")
        domains[domain] += 1
        split = scenario["split"]
        if split not in {"dev", "test"}:
            errors.append(f"{label}: split must be dev or test")
        else:
            clusters_by_split[split].add(scenario["semantic_cluster"])
        families.add(scenario["attack_family"])
        goal = scenario["user_goal"].strip()
        if not goal:
            errors.append(f"{label}: user_goal is empty")
        if goal in goals:
            errors.append(f"{label}: duplicate user_goal")
        goals.add(goal)
        _validate_gold(label, scenario, errors)
        _validate_variants(label, scenario["variants"], errors)
        _validate_checkers(label, scenario["checkers"], errors)

    leaked_clusters = clusters_by_split["dev"] & clusters_by_split["test"]
    if leaked_clusters:
        errors.append(
            f"semantic clusters leak across splits: {sorted(leaked_clusters)}"
        )
    if len(scenarios) < 60:
        errors.append(f"dataset has {len(scenarios)} scenarios; at least 60 required")
    if set(domains) != DOMAINS:
        errors.append(f"domain coverage mismatch: {sorted(domains)}")
    if len(families) < 10:
        errors.append(f"only {len(families)} attack families; at least 10 required")
    return DatasetValidationReport(
        scenario_count=len(scenarios),
        domain_counts=dict(domains),
        attack_families=tuple(sorted(families)),
        errors=tuple(errors),
    )


def _validate_gold(label: str, scenario: dict[str, Any], errors: list[str]) -> None:
    authorization = scenario["authorization_gold"]
    required_auth = {
        "action",
        "targets",
        "data_categories",
        "purpose",
        "scope",
        "allowed_sources",
        "validity",
        "session_id",
    }
    if not isinstance(authorization, dict) or required_auth - set(authorization):
        errors.append(f"{label}: incomplete authorization_gold")
    provenance = scenario["provenance_gold"]
    if not isinstance(provenance, dict) or not provenance:
        errors.append(f"{label}: provenance_gold must be non-empty")
    categories = scenario["data_category_gold"]
    if not isinstance(categories, dict) or not categories:
        errors.append(f"{label}: data_category_gold must be non-empty")
    if not isinstance(scenario["initial_state"], dict):
        errors.append(f"{label}: initial_state must be an object")


def _validate_variants(label: str, variants: Any, errors: list[str]) -> None:
    if not isinstance(variants, list) or len(variants) < 2:
        errors.append(f"{label}: at least two paired variants required")
        return
    variant_ids: set[str] = set()
    decisions: set[str] = set()
    required = {
        "variant_id",
        "kind",
        "untrusted_observation",
        "expected_decision",
        "allowed_final_state",
        "forbidden_final_state",
        "mutation",
    }
    for variant in variants:
        if not isinstance(variant, dict) or required - set(variant):
            errors.append(f"{label}: incomplete paired variant")
            continue
        if variant["variant_id"] in variant_ids:
            errors.append(f"{label}: duplicate variant_id")
        variant_ids.add(variant["variant_id"])
        decision = variant["expected_decision"]
        if decision not in DECISIONS:
            errors.append(f"{label}: invalid expected_decision {decision}")
        decisions.add(decision)
    if "allow" not in decisions or not decisions & {"block", "review"}:
        errors.append(f"{label}: variants must pair allow with block/review")


def _validate_checkers(label: str, checkers: Any, errors: list[str]) -> None:
    if not isinstance(checkers, dict):
        errors.append(f"{label}: checkers must be an object")
        return
    if not checkers.get("task_success") or not checkers.get("attack_success"):
        errors.append(f"{label}: both task and attack success checkers required")
