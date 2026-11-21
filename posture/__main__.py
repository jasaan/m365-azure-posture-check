"""Command line: python -m posture --fixtures fixtures/contoso-risky   or   python -m posture --live

Exit code is 1 when any critical or high check fails, so it can gate a pipeline.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from .checks import run_all
from .report import to_json, to_markdown
from .sources import FixtureSource, GraphSource


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only Microsoft 365 / Entra ID security posture check.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--fixtures",
        type=Path,
        help="Folder of recorded Graph responses (no sign-in needed)",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Sign in and read your tenant through Microsoft Graph",
    )
    parser.add_argument("--tenant", default="organizations", help="Tenant ID or domain for --live")
    parser.add_argument(
        "--today",
        help="Override today's date (YYYY-MM-DD) for reproducible fixture runs",
    )
    parser.add_argument("--out", type=Path, help="Folder to write report.md and results.json")
    args = parser.parse_args()

    if args.fixtures:
        src, label = (
            FixtureSource(args.fixtures),
            f"{args.fixtures.name} (recorded sample data)",
        )
    else:
        src, label = GraphSource(args.tenant), args.tenant

    today = dt.date.fromisoformat(args.today) if args.today else None
    results = run_all(src, today=today)
    markdown = to_markdown(results, label)
    print(markdown)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(markdown, encoding="utf-8")
        (args.out / "results.json").write_text(to_json(results, label), encoding="utf-8")

    serious = [r for r in results if r.status == "fail" and r.severity in ("critical", "high")]
    sys.exit(1 if serious else 0)


if __name__ == "__main__":
    main()
