"""Cryptographic facts — the pure read model (advanced/48 + 51 P0#1, round 31).

Report 51's verdict: facts, locations, and evidence links are FUSED in
the ``crypto_assets`` row; splitting the write side is a rearchitecture
of the core inventory. What ships today is the read-side half of that
separation: a **pure fact projection over the evidence records**, where
a fact is

    (algorithm, purpose, location, parameters) observed N times,
    by these scanners, first seen then, last seen now,
    backed by these exact evidence ids

— with no risk score, no asset identity, no dedup-model coupling.
Nothing writes to it and nothing downstream consumes it yet: this is
the first, explicitly-scoped step of the 51 rearchitecture, and the
projection stays honest about its inputs (soft-deleted evidence is
excluded by default and the exclusion is reported).
"""

from api.facts.projection import (
    fact_key,
    project_facts,
    summarize_facts,
)

__all__ = ["fact_key", "project_facts", "summarize_facts"]
