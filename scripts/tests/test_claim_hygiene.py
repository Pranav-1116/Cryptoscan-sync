"""The three claims a bank demo must never make — held deleted.

Roadmap phase 1.3 (``ROADMAP-TO-ENTERPRISE.md``):

1. **No shipped "eBPF runtime agent".** The shipped runtime tracer is the
   ``LD_PRELOAD`` shim (ADR-012); ``deploy/ebpf/execve_trace.py`` traces execve
   for the AI boundary, not crypto. A surface may mention eBPF only as an ADR
   topic, as a *bank-side* ingest source, or in an explicit negation.
2. **No SOC 2 CC9.3/9.4 region-failover PASS.** ``scripts/region_drills.py`` is
   two temporary directories in one process. Its reports carry that scope; no
   surface may map CC9.3 to PASS/✅.
3. **No unqualified "Precision / Recall / F1 = 100%".** Scores are corpus-
   scoped; a perfect score travels with its caveat or it does not ship.

The product-facing surfaces below are scanned on every run. The gap/roadmap
documents (ROADMAP-TO-ENTERPRISE.md, BACKEND-DATABASE-GAPS.md,
PRODUCT-VISION-AND-GAPS.md) are deliberately **not** scanned: they name the
claims in order to delete them. Re-introducing a claim on a surface is a test
failure, not slow drift.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SURFACES = (
    [ROOT / "README.md", ROOT / "docs" / "README.md",
     ROOT / "docs" / "PLATFORM-STATUS.md",
     ROOT / "docs" / "soc2-readiness-gap-analysis.md",
     ROOT / "docs" / "CURRENT-IMPLEMENTATION-STATUS.md",
     ROOT / "docs" / "region-failover.md", ROOT / "docs" / "pitr-drill.md"]
    + sorted((ROOT / "docs" / "product").glob("*.md"))
    + sorted((ROOT / "docs" / "accuracy").glob("*.md"))
    + sorted((ROOT / "docs" / "bank-environment").glob("*.md"))
)

# A mention of eBPF is allowed only in these shapes. Everything else is the
# claim that this repository ships an eBPF agent, which it does not.
EBPF_APPROVED = (
    re.compile(r"eBPF[- ]vs[- ]LD_PRELOAD", re.I),        # ADR-012 topic name
    re.compile(r"no kernel", re.I),                        # explicit negation
    re.compile(r"not implemented", re.I),                  # explicit negation
    re.compile(r"no eBPF crypto agent", re.I),             # explicit negation
    re.compile(r"bank's (?:own )?eBPF/mesh agents", re.I),  # their agent, not ours
)

SOC2_REGION_CLAIM = re.compile(r"CC9\.3[^\n]{0,60}(?:✅|PASS)", re.I)

# "Precision / Recall / F1 = 100%" and its shape, either order.
PERFECT_CLAIM_BEFORE = re.compile(
    r"(?:precision|recall|\bf1\b)[^|\n]{0,20}"
    r"(?:=|:|\bof\b|\bat\b|\bscored\b)\s*100(?:\.0)?\s*%", re.I)
PERFECT_CLAIM_AFTER = re.compile(
    r"100(?:\.0)?\s*%\s*(?:precision|recall|\bf1\b)", re.I)

QUALIFIERS = (
    "trivial", "answering three", "unexamined", "corpus", "not proof",
    "never quote", "do not quote", "naive", "shortcut", "blind", "wave",
    "fixture", "ground truth", "labelled truth", "representative not real",
)

BARE_VERDICT = re.compile(r"^\*\*Verdict: \w+\*\*$")


def _lines():
    for path in SURFACES:
        assert path.is_file(), f"claim-hygiene surface missing: {path.relative_to(ROOT)}"
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            yield path, number, line


def _hit(path: Path, number: int, line: str) -> str:
    return f"{path.relative_to(ROOT)}:{number}: {line.strip()[:120]}"


def test_no_surface_ever_claims_a_shipped_ebpf_agent():
    bad = [f"{_hit(p, n, l)}" for p, n, l in _lines()
           if re.search(r"ebpf", l, re.I)
           and not any(pattern.search(l) for pattern in EBPF_APPROVED)]
    assert bad == [], "surfaces claim an eBPF agent this repository does not ship:\n" + "\n".join(bad)


def test_no_surface_ever_maps_region_failover_to_soc2_pass():
    bad = [_hit(p, n, l) for p, n, l in _lines() if SOC2_REGION_CLAIM.search(l)]
    assert bad == [], "surfaces map CC9.3 region failover to PASS:\n" + "\n".join(bad)


def test_no_surface_ever_quotes_100_percent_precision_unqualified():
    bad = []
    for p, n, l in _lines():
        if PERFECT_CLAIM_BEFORE.search(l) or PERFECT_CLAIM_AFTER.search(l):
            if not any(word in l.lower() for word in QUALIFIERS):
                bad.append(_hit(p, n, l))
    assert bad == [], "surfaces quote 100% precision/recall unqualified:\n" + "\n".join(bad)


def test_every_perfect_score_quote_travels_with_its_corpus_caveat():
    """A file may record perfect scores only beside the caveat that scopes them."""
    bad = []
    for path in SURFACES:
        text = path.read_text(encoding="utf-8")
        quotes_score = any(
            (PERFECT_CLAIM_BEFORE.search(line) or PERFECT_CLAIM_AFTER.search(line)
             or re.search(r"1\.000|100% / 100%", line))
            and re.search(r"precision|recall|\bf1\b", line, re.I)
            for line in text.splitlines())
        if quotes_score and not any(word in text.lower() for word in QUALIFIERS):
            bad.append(str(path.relative_to(ROOT)))
    assert bad == [], "files quote perfect scores with no corpus caveat:\n" + "\n".join(bad)


def test_no_surface_carries_a_bare_verdict_line():
    bad = [_hit(p, n, l) for p, n, l in _lines() if BARE_VERDICT.match(l.strip())]
    assert bad == [], "surfaces carry a verdict standing alone (scope must travel with it):\n" + "\n".join(bad)
