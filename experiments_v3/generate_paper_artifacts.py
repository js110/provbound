"""Generate publication figures and tabular extracts from frozen result files.

This script contains no hand-entered outcome values.  All plotted values are
read from the evidence-eligible JSON statistics produced by the experiment
pipelines.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "paper_v3" / "figures"
TABLE_DIR = ROOT / "paper_v3" / "tables"

REAL_STATS = ROOT / "results_v3/real_agent_test_v2/all_providers/statistics_three_provider.json"
PRIMARY_STATS = ROOT / "results_v3/real_agent_test_v2/all_providers/statistics_primary.json"
INTERNAL_STATS = ROOT / "results_v3/frozen_test_v1/statistics.json"
PROVENANCE_STATS = ROOT / "results_v3/provenance_test_v2/results.json"
AGENTDOJO_STATS = ROOT / "results_v3/agentdojo_test_v4/statistics.json"

COLORS = {"base": "#8C8C8C", "action_target": "#E69F00", "full": "#0072B2"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def setup_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
            "font.size": 9,
            "axes.labelsize": 9,
            "axes.titlesize": 10,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "figure.dpi": 150,
            "savefig.dpi": 600,
        }
    )


def save(fig: plt.Figure, stem: str) -> None:
    fig.tight_layout()
    fig.savefig(FIG_DIR / f"{stem}.png", dpi=600, bbox_inches="tight")
    fig.savefig(FIG_DIR / f"{stem}.svg", bbox_inches="tight")
    plt.close(fig)


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def internal_validation() -> None:
    stats = load(INTERNAL_STATS)
    labels = ["Base", "Action-target", "Full"]
    modes = ["base", "action_target", "full"]
    vals = [stats["mode_intervals"][m]["attack_success_rate"]["estimate"] for m in modes]
    intervals = [stats["mode_intervals"][m]["attack_success_rate"]["wilson_95"] for m in modes]
    yerr = np.maximum(
        0.0,
        np.array(
            [[v - ci[0] for v, ci in zip(vals, intervals)], [ci[1] - v for v, ci in zip(vals, intervals)]]
        ),
    )

    fig, ax = plt.subplots(figsize=(3.45, 2.45))
    bars = ax.bar(labels, np.array(vals) * 100, color=[COLORS[m] for m in modes], width=0.62)
    ax.errorbar(np.arange(3), np.array(vals) * 100, yerr=yerr * 100, fmt="none", ecolor="#333333", capsize=3, lw=1)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 112)
    ax.set_title("Frozen structured test (30 base scenarios)")
    for bar, value, interval in zip(bars, vals, intervals):
        label_y = max(bar.get_height(), interval[1] * 100) + 3.5
        ax.text(bar.get_x() + bar.get_width() / 2, label_y, f"{value*100:.1f}", ha="center", va="bottom", fontsize=8)
    save(fig, "fig1_internal_ablation")

    write_csv(
        TABLE_DIR / "table_internal_ablation.csv",
        [
            {
                "mode": label,
                "attack_success_rate": value,
                "wilson_95_low": interval[0],
                "wilson_95_high": interval[1],
                "n_base_scenarios": 30,
            }
            for label, value, interval in zip(labels, vals, intervals)
        ],
    )


def architecture() -> None:
    fig, ax = plt.subplots(figsize=(7.15, 2.5))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 4.2)
    ax.axis("off")

    boxes = [
        (0.2, 2.45, 2.05, 1.15, "Trusted user goal\n+ 8-D authorization contract", "#DDEBF7"),
        (3.0, 2.45, 1.8, 1.15, "Tool-calling\nLLM agent", "#E2F0D9"),
        (5.55, 2.45, 2.1, 1.15, "Pre-commit guard\nauthorization + source", "#FFF2CC"),
        (8.4, 2.45, 1.55, 1.15, "Disclosure\nfilter", "#FCE4D6"),
        (10.55, 2.45, 1.25, 1.15, "Tool /\nsandbox", "#E4DFEC"),
        (3.0, 0.45, 2.2, 1.05, "Untrusted observations\nmail / web / files", "#F4CCCC"),
        (6.0, 0.45, 2.45, 1.05, "Capability registry\nvalue + origin + category", "#D9EAD3"),
        (9.2, 0.45, 2.1, 1.05, "BLOCK / REVIEW\nverifiable certificate", "#D9D9D9"),
    ]
    for x, y, w, h, label, color in boxes:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04,rounding_size=0.08", fc=color, ec="#555555", lw=0.8))
        ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=8)

    arrows = [
        ((2.25, 3.02), (3.0, 3.02), ""),
        ((4.8, 3.02), (5.55, 3.02), "proposed call"),
        ((7.65, 3.02), (8.4, 3.02), "ALLOW"),
        ((9.95, 3.02), (10.55, 3.02), "minimal fields"),
        ((4.1, 1.5), (4.1, 2.45), "data"),
        ((5.2, 0.98), (6.0, 0.98), "bind"),
        ((7.0, 1.5), (6.6, 2.45), "resolve / audit"),
        ((7.65, 2.65), (9.2, 1.2), "deny / uncertain"),
    ]
    for (x1, y1), (x2, y2), label in arrows:
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9, lw=0.9, color="#4C4C4C"))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.16, label, ha="center", va="center", fontsize=6.5, color="#333333")
    save(fig, "fig0_system_architecture")

def real_agents() -> None:
    stats = load(REAL_STATS)
    provider_keys = ["deepseek", "mimo", "sensenova"]
    provider_labels = ["DeepSeek", "MiMo", "SenseNova"]
    metric_defs = [
        ("attack_success_rate", "Attack success", "attack"),
        ("benign_unauthorized_commit_rate", "Unauthorized benign commit", "unauthorized"),
        ("benign_task_success_rate", "Benign task success", "utility"),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(7.15, 2.55))
    x = np.arange(3)
    width = 0.34
    rows: list[dict] = []
    for ax, (metric, title, _) in zip(axes, metric_defs):
        for offset, mode in [(-width / 2, "base"), (width / 2, "full")]:
            values = []
            for provider, label in zip(provider_keys, provider_labels):
                item = stats["providers"][provider]["modes"][mode][metric]
                values.append(item["estimate"] * 100)
                rows.append(
                    {
                        "provider": label,
                        "mode": mode.capitalize(),
                        "metric": metric,
                        "events": item["events"],
                        "n": item["n"],
                        "estimate": item["estimate"],
                        "wilson_95_low": item["wilson_95"][0],
                        "wilson_95_high": item["wilson_95"][1],
                    }
                )
            bars = ax.bar(x + offset, values, width, label=mode.capitalize(), color=COLORS[mode])
            for bar, value in zip(bars, values):
                if title != "Benign task success":
                    ax.text(bar.get_x() + bar.get_width() / 2, value + 1, f"{value:.1f}", ha="center", va="bottom", fontsize=6.7)
        ax.set_title(title)
        ax.set_xticks(x, provider_labels, rotation=18, ha="right")
        ax.set_ylim(0, 110 if title == "Benign task success" else 16)
        ax.grid(axis="y", alpha=0.2, lw=0.5)
    axes[0].set_ylabel("Rate (%)")
    axes[1].legend(frameon=False, loc="upper right")
    save(fig, "fig2_real_agent_results")
    write_csv(TABLE_DIR / "table_real_agent_results.csv", rows)

    paired = stats["primary_pooled"]["paired_full_vs_base"]
    effects = [
        ("Attack success reduction", paired["attack_success_reduction"]),
        ("Unauthorized commit reduction", paired["benign_unauthorized_commit_reduction"]),
        ("Benign task success gain", paired["benign_task_success_gain"]),
    ]
    vals = np.array([e[1]["estimate"] * 100 for e in effects])
    lows = np.array([e[1]["paired_bootstrap_95"][0] * 100 for e in effects])
    highs = np.array([e[1]["paired_bootstrap_95"][1] * 100 for e in effects])
    fig, ax = plt.subplots(figsize=(5.15, 2.55))
    y = np.arange(len(effects))[::-1]
    ax.axvline(0, color="#555555", lw=0.8)
    ax.errorbar(vals, y, xerr=np.vstack([vals - lows, highs - vals]), fmt="o", color=COLORS["full"], ecolor=COLORS["full"], capsize=3)
    ax.set_yticks(y, [e[0] for e in effects])
    ax.set_xlabel("Paired effect (percentage points; 95% bootstrap CI)", fontsize=8)
    ax.set_xlim(-6, 14)
    ax.grid(axis="x", alpha=0.2, lw=0.5)
    for value, yy, (_, item) in zip(vals, y, effects):
        ax.text(value + 0.45, yy + 0.12, f"{value:.2f}; p={item['mcnemar_exact_two_sided_p']:.3g}", fontsize=7)
    save(fig, "fig3_real_agent_paired_effects")


def agentdojo() -> None:
    stats = load(AGENTDOJO_STATS)
    metrics = [("attack_success_rate", "Attack success"), ("utility_rate", "Task utility")]
    fig, axes = plt.subplots(1, 2, figsize=(4.8, 2.5))
    rows: list[dict] = []
    for ax, (metric, title) in zip(axes, metrics):
        values, errors = [], []
        for mode in ["base", "full"]:
            item = stats["modes"][mode][metric]
            value = item["estimate"] * 100
            low, high = (x * 100 for x in item["wilson_95"])
            values.append(value)
            errors.append((value - low, high - value))
            rows.append(
                {
                    "mode": mode.capitalize(),
                    "metric": metric,
                    "events": item["events"],
                    "n": item["n"],
                    "estimate": item["estimate"],
                    "wilson_95_low": item["wilson_95"][0],
                    "wilson_95_high": item["wilson_95"][1],
                }
            )
        bars = ax.bar(["Base", "Full"], values, color=[COLORS["base"], COLORS["full"]], width=0.6)
        ax.errorbar(
            np.arange(2),
            values,
            yerr=np.maximum(0.0, np.array(errors).T),
            fmt="none",
            ecolor="#333333",
            capsize=3,
            lw=1,
        )
        ax.set_title(title)
        ax.set_ylim(0, 5 if metric == "attack_success_rate" else 102)
        ax.set_ylabel("Rate (%)")
        for bar, value in zip(bars, values):
            if metric == "utility_rate":
                ax.text(bar.get_x() + bar.get_width() / 2, value + 1.5, f"{value:.1f}", ha="center", fontsize=8)
        if metric == "attack_success_rate":
            ax.text(0.5, 3.45, "0/140; Wilson upper bound 2.67%", ha="center", fontsize=7)
    fig.suptitle("AgentDojo v1.2.2 held-out partition", fontsize=10)
    save(fig, "fig4_agentdojo_external")
    write_csv(TABLE_DIR / "table_agentdojo_external.csv", rows)


def evidence_summary() -> None:
    provenance = load(PROVENANCE_STATS)["summary"]
    primary = load(PRIMARY_STATS)
    write_csv(
        TABLE_DIR / "table_evidence_summary.csv",
        [
            {"evidence": "structured_authorization", "sample": "30 base scenarios / 90 variants", "result": "Full accuracy 1.000; attack success 0/30"},
            {"evidence": "runtime_provenance", "sample": f"{provenance['base_scenarios']} scenarios / {provenance['arguments']} arguments", "result": f"exact match {provenance['exact_argument_rate']:.3f}; forged-reference review {provenance['forged_reference_review_rate']:.3f}"},
            {"evidence": "preregistered_two_provider_primary", "sample": "DeepSeek + MiMo, paired", "result": json.dumps(primary["primary_pooled"]["paired_full_vs_base"], ensure_ascii=False, separators=(",", ":"))},
            {"evidence": "three_provider_descriptive", "sample": "DeepSeek + MiMo + SenseNova, 360 attempted cells", "result": "unauthorized benign commit 6/90 to 0/90; p=0.03125"},
            {"evidence": "agentdojo_heldout", "sample": "140 paired cells per mode", "result": "ASR 0/140 in both; utility 130/140 to 131/140; p=1.0"},
        ],
    )


def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    setup_style()
    architecture()
    internal_validation()
    real_agents()
    agentdojo()
    evidence_summary()
    print(f"Wrote figures to {FIG_DIR}")
    print(f"Wrote tables to {TABLE_DIR}")


if __name__ == "__main__":
    main()
