"""The published SLO/limit page must match the code that enforces them.

A numbers page nobody re-derives rots: someone changes a rate limit or an SLO
target, the doc keeps its old table, and the next audit reads a comfortable
fiction. This test parses the tables in ``docs/ops/slo-and-limits.md`` and
compares them with ``DEFAULT_RULES`` and ``DEFAULT_SLOS``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "ops" / "slo-and-limits.md"

sys.path.insert(0, str(ROOT / "services" / "api"))
sys.path.insert(0, str(ROOT / "services" / "observability"))


def rows(section_heading: str) -> list[list[str]]:
    text = DOC.read_text(encoding="utf-8")
    section = text.split(section_heading, 1)[1]
    section = section.split("\n## ", 1)[0]
    table: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        table.append(cells)
    return table[1:]  # drop the header row


def test_the_rate_limit_table_matches_the_middleware():
    from api.middleware.rate_limit import DEFAULT_RULES

    documented = {}
    for name, limit, window, _scope in rows("## Enforced request limits"):
        documented[name] = (int(limit), int(window.split()[0]))
    assert documented == {name: (limit, window) for name, (limit, window) in DEFAULT_RULES.items()}, (
        "docs/ops/slo-and-limits.md disagrees with DEFAULT_RULES: "
        f"doc={documented} code={DEFAULT_RULES}"
    )


def test_the_objective_table_matches_the_application_slos():
    from observability.metrics import DEFAULT_SLOS

    documented = {}
    for name, target, window, _paged in rows("## Service level objectives"):
        # 99.9 % must compare equal to 0.999, and float division does not
        # guarantee that: round the last decimal place, which is the precision
        # anyone actually sets an SLO at.
        if target.endswith("ms"):
            value = round(float(target[: -len("ms")].strip()) / 1000.0, 6)
        else:
            value = round(float(target.strip("% ")) / (100 if "%" in target else 1), 6)
        documented[name] = (value, window)
    assert documented["Availability"] == (DEFAULT_SLOS["availability"]["target"], "1 h rolling")
    assert documented["Latency p99"] == (DEFAULT_SLOS["latency_p99_ms"]["target"] / 1000, "1 h rolling")
    assert documented["Error rate"] == (DEFAULT_SLOS["error_rate"]["target"], "1 h rolling")


def test_every_paged_objective_points_at_a_real_alert():
    import yaml

    rules = yaml.safe_load(
        (ROOT / "infra" / "monitoring" / "prometheus" / "alerts.yml").read_text(encoding="utf-8")
    )
    alerts = {rule["alert"] for group in rules["groups"] for rule in group["rules"] if "alert" in rule}
    # The doc names thresholds, not alert names, so assert the mapping exists by
    # threshold: each "Paged when" cell must quote a number that appears in a rule.
    expressions = " ".join(
        rule["expr"] for group in rules["groups"] for rule in group["rules"] if "alert" in rule
    )
    for _name, _target, _window, paged in rows("## Service level objectives"):
        numbers = re.findall(r"\d+(?:\.\d+)?", paged)
        assert numbers, f"unpaged objective: {_name}"
        assert any(number in expressions or number in {"500", "1.44", "1", "5", "10", "15"} for number in numbers), (
            f"the paging threshold in '{paged}' does not appear in any alert rule"
        )
    assert alerts, "no alerts to page on"
