"""Turn check results into a score, a Markdown report and JSON."""

from __future__ import annotations

import json

from .checks import Result

WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ICON = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "unknown": "UNKNOWN"}


def score(results: list[Result]) -> int:
    """Weighted percentage of checks passed. Warn counts half; unknown counts zero."""
    total = sum(WEIGHT[r.severity] for r in results)
    got = sum(WEIGHT[r.severity] * (1 if r.status == "pass" else 0.5 if r.status == "warn" else 0) for r in results)
    return round(100 * got / total) if total else 0


def to_markdown(results: list[Result], tenant_label: str) -> str:
    ordered = sorted(results, key=lambda r: (r.status == "pass", SEVERITY_ORDER[r.severity]))
    fails = [r for r in ordered if r.status != "pass"]
    passed = sum(r.status == "pass" for r in results)
    lines = [
        f"# Microsoft 365 / Entra ID posture: {tenant_label}",
        "",
        f"**Score: {score(results)}/100**  ({passed} of {len(results)} checks passed)",
        "",
        "| Status | Severity | Check | Evidence |",
        "|---|---|---|---|",
    ]
    for r in ordered:
        lines.append(f"| {ICON[r.status]} | {r.severity} | {r.title} | {r.evidence.replace('|', '/')} |")
    if fails:
        lines += ["", "## Fixes, most severe first", ""]
        for r in fails:
            lines += [
                f"### {r.title} ({r.severity}, {ICON[r.status]})",
                "",
                r.fix,
                "",
                "References: " + "; ".join(r.references),
                "",
            ]
    return "\n".join(lines) + "\n"


def to_json(results: list[Result], tenant_label: str) -> str:
    return json.dumps(
        {
            "tenant": tenant_label,
            "score": score(results),
            "results": [r.to_dict() for r in results],
        },
        indent=2,
    )
