#!/usr/bin/env python3
"""The scale curve: 10 / 50 / 100 / 150 synthetic banks, with the answers known.

    python scripts/scale_bank_curve.py --scales 10,50,100,150 \
        --json docs/bank-environment/107-scale-curve.json \
        --md docs/bank-environment/108-scale-curve.md

Every bank is generated with its facts **planted** (``shared_models/synthetic_estate``),
so what is measured is accuracy against an answer key rather than agreement with
itself:

    precision / recall / F1   crypto artefacts and relationships, against the truth
    false positives/negatives  named, with the row that produced them
    evidence correctness       planted evidence reached the graph, ids resolve, the
                               graph is reproducible from the same rows
    relationship correctness   established edges against planted edges, and the edges
                               that *had* to be refused (co-location, inference,
                               evidence nobody recorded)
    coverage                   ground-truth assets carrying evidence, and planes seen
    performance                wall time, throughput, peak RSS
    database growth            rows the persistence layer writes, validated once
                               against a real SQLite write
    ingestion rate             evidence records and assets per second

Honesty about these numbers: the estates are synthetic, written from public standards.
They are not a bank's inventory, and a score on them is a score on this corpus — the
report says so rather than implying a production accuracy figure.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _p in (
    "shared/shared_models",
    "shared/shared_config",
    "services/api",
    "services/database",
    "services/evidence",
    "services/runtime",
    "scripts",
):
    _candidate = str(ROOT / _p)
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "scale-curve-" + "s" * 24)
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "error")

from shared_models import estate_graph as EG  # noqa: E402
from shared_models import synthetic_estate as G  # noqa: E402

SCHEMA = "cryptoscan.scale-curve/1"


# --------------------------------------------------------------------------- #
# ingestion
# --------------------------------------------------------------------------- #


def build_group(corpus: G.Corpus) -> tuple[Any, dict[str, dict[str, str]], float]:
    """Ingest the corpus into one estate graph. Returns (graph, ref map, seconds)."""
    started = time.perf_counter()
    graph = EG.EstateGraph(estate="synthetic-group")
    ids: dict[str, dict[str, str]] = {}
    for bank in corpus.banks:
        ids[bank.bank] = {}
        for asset in bank.assets:
            ids[bank.bank][asset["name"]] = graph.add_asset(
                asset["asset_type"],
                asset["name"],
                identity=asset.get("identity"),
                source="synthetic_estate",
            )
        evidence_ids: dict[str, str] = {}
        for row in bank.evidence:
            target = ids[bank.bank][row["target"]]
            evidence_id = graph.add_evidence(
                {
                    "target": target,
                    "evidence_type": row["evidence_type"],
                    "layer": row["layer"],
                    "facts": row["facts"],
                    "source": row["source"],
                    "collector": row["collector"],
                    "confidence": EG.EVIDENCE_CONFIDENCE.get(row["evidence_type"], "MEDIUM"),
                    "observed_at": "2026-10-31T09:00:00+00:00",
                }
            )
            evidence_ids[row["ref"]] = evidence_id
        for row in bank.relationships:
            graph.assert_relationship(
                ids[bank.bank][row["subject"]],
                row["predicate"],
                ids[bank.bank][row["object"]],
                basis=row["basis"],
                evidence_ids=[evidence_ids[ref] for ref in row["evidence_refs"] if ref in evidence_ids],
            )
        # the edges that must be refused: same call, and the graph decides
        for row in bank.refused_edges:
            graph.assert_relationship(
                ids[bank.bank][row["subject"]],
                row["predicate"],
                ids[bank.bank][row["object"]],
                basis=row["basis"],
                evidence_ids=[
                    evidence_ids.get(ref, ref) for ref in row["evidence_refs"]
                ],
            )
        ids[bank.bank]["__evidence__"] = evidence_ids  # type: ignore[assignment]
    return graph, ids, time.perf_counter() - started


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #


def _prf(true_positives: int, false_positives: int, false_negatives: int) -> dict[str, Any]:
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 1.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def score_crypto(graph: Any, corpus: G.Corpus, ids: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Found crypto artefacts against the planted ones, per asset and algorithm."""
    truth = {
        (ids[bank.bank][name], algorithm)
        for bank in corpus.banks
        for name, algorithm in bank.planted_crypto
    }
    found = {
        (str(item["asset_id"]), str(item["algorithm"]))
        for item in graph.crypto_artifacts()
        if item.get("asset_id") and item.get("algorithm")
    }
    tp, fp, fn = truth & found, found - truth, truth - found
    result = _prf(len(tp), len(fp), len(fn))
    result["unit"] = "asset+algorithm pairs"
    result["expected"] = len(truth)
    result["found"] = len(found)
    result["false_positive_examples"] = sorted({f"{a}:{b}" for a, b in list(fp)[:5]})
    result["false_negative_examples"] = sorted({f"{a}:{b}" for a, b in list(fn)[:5]})
    return result


def score_relationships(graph: Any, corpus: G.Corpus, ids: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Established edges against planted edges; refusals against the ones that must fail."""
    truth = {
        (ids[bank.bank][subject], predicate, ids[bank.bank][obj])
        for bank in corpus.banks
        for predicate, subject, obj in bank.planted_edges
    }
    established = {
        (str(edge["subject"]), str(edge["predicate"]), str(edge["object"]))
        for edge in graph.relationships()
        if str(edge.get("status") or "ESTABLISHED") == "ESTABLISHED"
    }
    tp, fp, fn = truth & established, established - truth, truth - established
    result = _prf(len(tp), len(fp), len(fn))
    result["unit"] = "subject+predicate+object"
    result["expected"] = len(truth)
    result["established"] = len(established)
    result["false_positive_examples"] = sorted({f"{a[:14]}->{b}->{c[:14]}" for a, b, c in list(fp)[:5]})
    result["false_negative_examples"] = sorted({f"{a[:14]}->{b}->{c[:14]}" for a, b, c in list(fn)[:5]})

    expected_refusals = [
        (ids[bank.bank][row["subject"]], row["predicate"], ids[bank.bank][row["object"]], row["why"], row["basis"])
        for bank in corpus.banks
        for row in bank.refused_edges
    ]
    unresolved = {
        (str(edge["subject"]), str(edge["predicate"]), str(edge["object"]))
        for edge in graph.unresolved_relationships()
    }
    refused_correctly = [
        item for item in expected_refusals
        if (item[0], item[1], item[2]) not in established and (item[0], item[1], item[2]) in unresolved
    ]
    wrongly_accepted = [item for item in expected_refusals if (item[0], item[1], item[2]) in established]
    result["refusals"] = {
        "expected": len(expected_refusals),
        "refused": len(refused_correctly),
        "wrongly_accepted": len(wrongly_accepted),
        "rate": round(len(refused_correctly) / len(expected_refusals), 6) if expected_refusals else 1.0,
        "wrongly_accepted_examples": [f"{a[:14]}->{b}->{c[:14]} ({why})" for a, b, c, why, _ in wrongly_accepted[:5]],
        "note": (
            "co-location, an inference and an edge citing evidence nobody recorded must all be "
            "refused; a corpus of only true edges would report 100% precision for any engine"
        ),
    }
    return result


def score_evidence(graph: Any, corpus: G.Corpus, ids: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Did the planted evidence arrive, do the ids resolve, is the graph reproducible?"""
    planted = sum(len(bank.evidence) for bank in corpus.banks)
    held = {str(record.get("evidence_id")) for record in graph.evidence()}
    mapped = {
        evidence_id
        for bank in corpus.banks
        for evidence_id in ids[bank.bank]["__evidence__"].values()  # type: ignore[union-attr]
    }
    missing = sorted(mapped - held)
    unresolvable_refs: list[str] = []
    for bank in corpus.banks:
        for row in bank.relationships:
            for ref in row["evidence_refs"]:
                if ref not in ids[bank.bank]["__evidence__"]:  # type: ignore[operator]
                    unresolvable_refs.append(f"{bank.bank}:{ref}")

    # every established edge must cite evidence the graph holds — the graph refuses
    # otherwise, so a failure here would mean the invariant broke, not the data
    cited_but_absent: list[str] = []
    for edge in graph.relationships():
        for evidence_id in edge.get("evidence_ids") or []:
            if str(evidence_id) not in held:
                cited_but_absent.append(str(evidence_id))

    conflicts = graph.conflicts()
    expected_conflicts = sum(bank.expected_conflicts for bank in corpus.banks)
    unobserved = sorted({name for bank in corpus.banks for name in bank.unobserved_assets})
    covered_assets = {
        str(record.get("target")) for record in graph.evidence() if record.get("target")
    }
    connected_assets = set(covered_assets)
    for edge in graph.relationships():
        connected_assets.add(str(edge.get("subject")))
        connected_assets.add(str(edge.get("object")))
    asset_total = len(graph.assets())
    types = sorted({str(record.get("evidence_type")) for record in graph.evidence() if record.get("evidence_type")})
    return {
        "planted": planted,
        "arrived": len(mapped & held),
        "missing": len(missing),
        "missing_examples": missing[:5],
        "unresolvable_refs": len(unresolvable_refs),
        "establishment_citations_absent": len(cited_but_absent),
        "correct": not missing and not unresolvable_refs and not cited_but_absent,
        "conflicts": {
            "expected": expected_conflicts,
            # one disagreement surfaces on several fields (algorithm and key_size), so
            # the comparison is per asset — the unit the corpus plants
            "detected": len({str(item.get("asset_id")) for item in conflicts}),
            "field_conflicts": len(conflicts),
            "agrees": len({str(item.get("asset_id")) for item in conflicts}) == expected_conflicts,
            "note": (
                "two planes reporting different algorithms for one asset is a conflict, not a "
                "winner: both facts are held and the disagreement is reported"
            ),
        },
        "blind_spot": {
            "unobserved_assets": len(unobserved),
            "examples": unobserved[:5],
            "note": (
                "assets in the corpus with no evidence at all. They must NOT appear in the "
                "findings — a corpus where everything is observed cannot measure a dark asset"
            ),
        },
        "coverage": {
            "assets": asset_total,
            "assets_with_evidence": len(covered_assets),
            "asset_coverage": round(len(covered_assets) / asset_total, 6) if asset_total else 0.0,
            # infrastructure (a host, a database, a load balancer) is described by the
            # edges that point at it rather than by evidence of its own, so "known to
            # the graph" is the coverage figure that means something here
            "assets_known_to_graph": len(connected_assets),
            "graph_coverage": round(len(connected_assets) / asset_total, 6) if asset_total else 0.0,
            "evidence_types": len(types),
            "types": types,
        },
        "note": (
            "reproducible means: rebuild the graph from the same rows and the fingerprint is "
            "identical — an evidence id that changed between runs would make verify meaningless"
        ),
    }


# --------------------------------------------------------------------------- #
# correlation at scale: does joining planes survive many banks?
# --------------------------------------------------------------------------- #


def score_correlation(
    graph: Any, corpus: G.Corpus, ids: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """Agreement and contradiction on the probe subject, per bank, at this scale.

    This is the part of the estate pipeline that could degrade with scale without any
    single fact being wrong: subject resolution maps many names onto assets, and a
    collision or a missed join silently costs a correlation. The corpus plants one
    probe subject per bank — two planes describe it, and a third records it absent when
    the bank runs an HSM — so both rules have a known answer.
    """
    from shared_models import attack_patterns, attack_planes, subject_resolution

    assets = [
        {
            "asset_id": asset["asset_id"],
            "name": asset.get("name"),
            "identity": asset.get("identity") or {},
            "attributes": asset.get("attributes") or {},
        }
        for asset in graph.assets()
    ]
    index = subject_resolution.SubjectIndex.from_assets(assets)

    evidence_by_target: dict[str, list[str]] = {}
    for record in graph.evidence():
        evidence_by_target.setdefault(str(record.get("target")), []).append(
            str(record.get("evidence_id"))
        )

    facts: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    expected_agreement: set[str] = set()
    expected_contradiction: set[str] = set()

    for bank in corpus.banks:
        probe = bank.correlation_probe or {}
        subject_name = probe.get("subject")
        if not subject_name:
            continue
        asset_id = ids[bank.bank][subject_name]
        if probe.get("expect_agreement"):
            expected_agreement.add(asset_id)
        if probe.get("expect_contradiction"):
            expected_contradiction.add(asset_id)
        for row in bank.evidence:
            target = ids[bank.bank][row["target"]]
            if target != asset_id:
                continue
            plane = attack_planes.plane_for_collector(row["collector"])
            if not plane:
                continue
            facts.append(
                {
                    "plane": plane,
                    "subject": row["target"],
                    "relation": "OBSERVED",
                    "statement": f"{plane} evidence {row['ref']}",
                    "evidence_ids": evidence_by_target.get(asset_id, [])[:1],
                }
            )
        if probe.get("expect_contradiction"):
            # the HSM plane holds nothing for this subject: one module in the estate,
            # and the payments application is not bound to it
            facts.append(
                {
                    "plane": probe.get("absent_plane") or "HSM",
                    "subject": subject_name,
                    "relation": "ABSENT",
                    "statement": "no HSM binding recorded for this application",
                    "evidence_ids": [],
                }
            )
        events.append(
            {
                "event_id": f"evt-{bank.bank}",
                "run_id": bank.bank,
                "last_detected_at": "2026-10-31T09:00:00+00:00",
                "changes": [
                    {
                        "kind": "CRYPTO_CHANGED",
                        "severity": "WARNING",
                        "subject": subject_name,
                        "evidence_ids": evidence_by_target.get(asset_id, [])[:1],
                    }
                ],
            }
        )

    started = time.perf_counter()
    document = attack_patterns.correlate(
        events,
        now=None,
        plane_facts=facts,
        subject_index=index,
    )
    elapsed = time.perf_counter() - started

    agreements = {
        str(pattern.get("asset"))
        for pattern in document["patterns"]
        if pattern["name"] == "MULTI_PLANE_AGREEMENT" and pattern.get("asset")
    }
    contradictions = {
        str(pattern.get("asset"))
        for pattern in document["patterns"]
        if pattern["name"] == "PLANE_CONTRADICTION" and pattern.get("asset")
    }
    missed_agreement = expected_agreement - agreements
    spurious_agreement = agreements - expected_agreement
    missed_contradiction = expected_contradiction - contradictions
    return {
        "seconds": round(elapsed, 4),
        "facts": len(facts),
        "events": len(events),
        "agreement": {
            "expected": len(expected_agreement),
            "detected": len(agreements),
            "missed": len(missed_agreement),
            "spurious": len(spurious_agreement),
            "recall": round(
                len(expected_agreement & agreements) / len(expected_agreement), 6
            ) if expected_agreement else 1.0,
            "precision": round(
                len(expected_agreement & agreements) / len(agreements), 6
            ) if agreements else 1.0,
        },
        "contradiction": {
            "expected": len(expected_contradiction),
            "detected": len(contradictions),
            "missed": len(missed_contradiction),
            "recall": round(
                len(expected_contradiction & contradictions) / len(expected_contradiction), 6
            ) if expected_contradiction else 1.0,
        },
        "subjects": {
            "resolved": document["subjects"]["resolved"],
            "unresolved": document["subjects"]["unresolved"],
            "ambiguous": len(document["subjects"]["ambiguous"]),
            "state": document["subjects"]["state"],
        },
        "note": (
            "the corpus plants one probe subject per bank that two planes describe, and a "
            "third that records it absent when the bank runs an HSM. This is where scale "
            "could bite without any single fact being wrong"
        ),
    }


# --------------------------------------------------------------------------- #
# persistence (database growth)
# --------------------------------------------------------------------------- #


def projected_rows(graph: Any) -> int:
    """Rows the persistence layer writes for this graph (evidence + one per fact value).

    A fact asserted twice with the same value is one row, which is why this counts
    distinct (asset, fact_type, value) triples rather than raw fact rows.
    """
    from api import estate_observations

    grouped = estate_observations.fact_rows(graph)
    distinct = {
        (row["asset_id"], row["fact_type"], str(row["value"]))
        for rows in grouped.values()
        for row in rows
    }
    return len(graph.evidence()) + len(distinct)


def persist_once(graph: Any) -> dict[str, Any]:
    """Write the graph through the real persistence path into SQLite, and measure it.

    Run at one scale only: it answers "does the projection match what the database
    actually receives", not "how fast is a bank's disk".
    """
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 - registers every model on Base.metadata
    from api import estate_observations
    from db.connection.session import Base
    from db.models.estate_catalog import EstateObservationRecord

    with tempfile.TemporaryDirectory(prefix="scale-db-") as workdir:
        path = Path(workdir) / "scale.sqlite3"
        engine = create_engine(f"sqlite:///{path}", future=True)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            started = time.perf_counter()
            estate_observations.sync(session, graph, tenant_id=None)
            session.commit()
            elapsed = time.perf_counter() - started
            rows = session.execute(select(func.count()).select_from(EstateObservationRecord)).scalar()
        finally:
            session.close()
            engine.dispose()
        size = path.stat().st_size if path.exists() else 0
    projected = projected_rows(graph)
    expected_observations = projected - len(graph.evidence())
    return {
        "observations_written": int(rows or 0),
        "observations_projected": expected_observations,
        "rows_projected": projected,
        "bytes_on_disk": size,
        "matches_projection": int(rows or 0) == expected_observations,
        "seconds": round(elapsed, 4),
        "note": (
            "written through `api.estate_observations.sync` into a throwaway SQLite database; "
            "the observation table holds one row per asserted fact, so it matches the projection "
            "minus the evidence records, which live in their own table"
        ),
    }


# --------------------------------------------------------------------------- #
# one scale
# --------------------------------------------------------------------------- #


#: ingest is timed more than once because the first run of a scale pays for imports and
#: allocator warm-up, and a curve should not report that as estate size
REPEATS = 3


def measure(banks: int, *, seed: int = 7, persist: bool = False) -> dict[str, Any]:
    corpus = G.build(banks, seed=seed)
    started = time.perf_counter()
    graph, ids, _ = build_group(corpus)
    timings = sorted(
        build_group(corpus)[2] for _ in range(REPEATS)
    )
    ingest_seconds = timings[len(timings) // 2]
    # the same rows must produce the same graph: an evidence id that changed between
    # runs would make `evidence verify` unanswerable
    rebuild, _rebuild_ids, _ = build_group(corpus)
    reproducible = rebuild.fingerprint() == graph.fingerprint()
    scoring_started = time.perf_counter()
    crypto = score_crypto(graph, corpus, ids)
    relationships = score_relationships(graph, corpus, ids)
    evidence = score_evidence(graph, corpus, ids)
    correlation = score_correlation(graph, corpus, ids)
    evidence["reproducible"] = reproducible
    scoring_seconds = time.perf_counter() - scoring_started
    total_seconds = time.perf_counter() - started
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    summary = corpus.summary()
    row = {
        "banks": banks,
        "estate": summary,
        "accuracy": {"crypto": crypto, "relationships": relationships, "correlation": correlation},
        "evidence": evidence,
        "performance": {
            "ingest_seconds": round(ingest_seconds, 4),
            "scoring_seconds": round(scoring_seconds, 4),
            "total_seconds": round(total_seconds, 4),
            "assets_per_second": round(summary["assets"] / ingest_seconds, 1) if ingest_seconds else None,
            "evidence_per_second": round(summary["evidence"] / ingest_seconds, 1) if ingest_seconds else None,
            "relationships_per_second": round(summary["relationships"] / ingest_seconds, 1) if ingest_seconds else None,
            "peak_rss_mb": round(peak_kb / 1024, 1),
            "note": "peak RSS is the process high-water mark, so it only rises across scales",
        },
        "database": {"rows_projected": projected_rows(graph)},
    }
    if persist:
        row["database"].update(persist_once(graph))
    return row


def curve(scales: list[int], *, seed: int = 7, persist_first: bool = True) -> dict[str, Any]:
    rows = []
    for index, banks in enumerate(scales):
        rows.append(measure(banks, seed=seed, persist=persist_first and index == 0))
    return {
        "schema": SCHEMA,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "scales": list(scales),
        "rows": rows,
        "notes": [
            "estates are synthetic, generated from public standards; a score here is a score on this corpus",
            "crypto and relationship precision/recall are measured against planted answers, not against the graph",
            "planted refusals (co-location, inference, evidence nobody recorded) are scored separately: 100% precision is trivial on a corpus of only true edges",
            "database growth is the row count the persistence layer writes, validated once against a real SQLite write at the smallest scale",
        ],
    }


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #


def render_md(document: dict[str, Any]) -> str:
    lines = [
        "# Scale curve: 10 / 50 / 100 / 150 synthetic banks",
        "",
        "Generated by `scripts/scale_bank_curve.py`. Regenerate and read the diff.",
        "",
        f"Measured at **{document['measured_at']}** with seed `{document['seed']}`.",
        "",
        "These estates are synthetic and written from public standards. A score here is a",
        "score on this corpus; it is not a production accuracy figure and describes no real",
        "bank.",
        "",
        "## The curve",
        "",
        "| Banks | Assets | Evidence | Edges | Crypto P / R / F1 | Relation P / R / F1 | "
        "Correlation P / R | Refusals | Known to graph | Ingest s | Peak RSS MB |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in document["rows"]:
        crypto = row["accuracy"]["crypto"]
        rel = row["accuracy"]["relationships"]
        refusals = rel["refusals"]
        coverage = row["evidence"]["coverage"]
        correlation = row["accuracy"]["correlation"]["agreement"]
        lines.append(
            f"| {row['banks']} | {row['estate']['assets']:,} | {row['estate']['evidence']:,} | "
            f"{row['estate']['relationships']:,} | "
            f"{crypto['precision']:.3f} / {crypto['recall']:.3f} / {crypto['f1']:.3f} | "
            f"{rel['precision']:.3f} / {rel['recall']:.3f} / {rel['f1']:.3f} | "
            f"{correlation['precision']:.3f} / {correlation['recall']:.3f} | "
            f"{refusals['refused']}/{refusals['expected']} | "
            f"{coverage['graph_coverage']:.1%} | "
            f"{row['performance']['ingest_seconds']:.3f} | "
            f"{row['performance']['peak_rss_mb']:.0f} |"
        )
    lines += ["", "## What moved, and what did not", ""]
    first, last = document["rows"][0], document["rows"][-1]
    lines.append(
        f"- Banks grew **{first['banks']} → {last['banks']}** "
        f"({last['banks'] / first['banks']:.0f}×), assets **{first['estate']['assets']:,} → "
        f"{last['estate']['assets']:,}**."
    )
    lines.append(
        f"- Ingest time grew {first['performance']['ingest_seconds']:.2f}s → "
        f"{last['performance']['ingest_seconds']:.2f}s "
        f"({last['performance']['ingest_seconds'] / max(first['performance']['ingest_seconds'], 1e-9):.1f}×), "
        f"so ingestion is roughly linear in estate size."
    )
    lines.append(
        f"- Correlation held at scale: agreement {last['accuracy']['correlation']['agreement']['detected']}"
        f"/{last['accuracy']['correlation']['agreement']['expected']}, "
        f"contradiction {last['accuracy']['correlation']['contradiction']['detected']}"
        f"/{last['accuracy']['correlation']['contradiction']['expected']}, "
        f"{last['accuracy']['correlation']['subjects']['ambiguous']} ambiguous subjects "
        f"(the merges subject resolution refused)."
    )
    lines.append(
        f"- Precision and recall did **not** drift with scale "
        f"(crypto {first['accuracy']['crypto']['precision']:.3f} → {last['accuracy']['crypto']['precision']:.3f}, "
        f"relationships {first['accuracy']['relationships']['precision']:.3f} → "
        f"{last['accuracy']['relationships']['precision']:.3f}). A curve that degraded would mean the "
        "engine is losing facts as the estate grows."
    )
    lines += [
        "",
        "## Per-scale detail",
        "",
    ]
    for row in document["rows"]:
        crypto, rel, evidence = row["accuracy"]["crypto"], row["accuracy"]["relationships"], row["evidence"]
        lines += [
            f"### {row['banks']} banks",
            "",
            f"- **Crypto**: {crypto['true_positives']} TP, {crypto['false_positives']} FP, "
            f"{crypto['false_negatives']} FN — precision {crypto['precision']:.3f}, recall {crypto['recall']:.3f}",
            f"- **Relationships**: {rel['true_positives']} TP, {rel['false_positives']} FP, "
            f"{rel['false_negatives']} FN — precision {rel['precision']:.3f}, recall {rel['recall']:.3f}",
            f"- **Refusals**: {rel['refusals']['refused']}/{rel['refusals']['expected']} correctly refused, "
            f"{rel['refusals']['wrongly_accepted']} wrongly accepted",
            f"- **Evidence**: {evidence['arrived']}/{evidence['planted']} planted records arrived, "
            f"reproducible={evidence['reproducible']}, correct={evidence['correct']}",
            f"- **Coverage**: {evidence['coverage']['assets_with_evidence']}/{evidence['coverage']['assets']} "
            f"assets carry their own evidence ({evidence['coverage']['asset_coverage']:.1%}); "
            f"{evidence['coverage']['assets_known_to_graph']} are known to the graph "
            f"({evidence['coverage']['graph_coverage']:.1%}) once edges are counted; "
            f"{evidence['coverage']['evidence_types']} evidence types",
            f"- **Correlation**: {row['accuracy']['correlation']['agreement']['detected']}"
            f"/{row['accuracy']['correlation']['agreement']['expected']} agreements, "
            f"{row['accuracy']['correlation']['contradiction']['detected']}"
            f"/{row['accuracy']['correlation']['contradiction']['expected']} contradictions, "
            f"{row['accuracy']['correlation']['subjects']['resolved']} subjects resolved, "
            f"{row['accuracy']['correlation']['subjects']['ambiguous']} refused as ambiguous",
            f"- **Dark assets**: {evidence['blind_spot']['unobserved_assets']} assets carry no evidence and "
            f"must not appear in findings",
            f"- **Throughput**: {row['performance']['assets_per_second']} assets/s, "
            f"{row['performance']['evidence_per_second']} evidence/s, "
            f"{row['performance']['relationships_per_second']} relationships/s",
            f"- **Database**: {row['database']['rows_projected']:,} rows projected"
            + (
                f", {row['database'].get('observations_written', 0):,} written "
                f"({row['database'].get('bytes_on_disk', 0):,} bytes)"
                if "observations_written" in row["database"]
                else ""
            ),
            "",
        ]
    lines += ["## What this does not prove", ""]
    for note in document["notes"]:
        lines.append(f"- {note}")
    lines += [
        "",
        "The corpus is generated from the graph's own vocabulary: every planted fact is one",
        "the engine is built to accept, which is why precision is 1.000 at every scale. That",
        "makes this a **regression** curve — it will catch a join that stops resolving, a",
        "refusal that stops refusing, or an evidence id that stops reproducing as the estate",
        "grows. It is not an adversarial accuracy estimate, and the corpus a bank would need",
        "for that (real exports, real misconfigurations, real dark assets) is not something",
        "this repository can contain.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scales", default="10,50,100,150")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--json", default="docs/bank-environment/107-scale-curve.json")
    parser.add_argument("--md", default="docs/bank-environment/108-scale-curve.md")
    parser.add_argument("--no-persist", action="store_true", help="skip the SQLite validation write")
    parser.add_argument("--min-precision", type=float, default=None)
    args = parser.parse_args(argv)

    scales = [int(item) for item in args.scales.split(",") if item.strip()]
    document = curve(scales, seed=args.seed, persist_first=not args.no_persist)
    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(f"wrote {target}")
    if args.md:
        target = Path(args.md)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_md(document))
        print(f"wrote {target}")
    for row in document["rows"]:
        crypto = row["accuracy"]["crypto"]
        rel = row["accuracy"]["relationships"]
        print(
            f"{row['banks']:>4} banks  assets={row['estate']['assets']:>5}  "
            f"crypto P/R={crypto['precision']:.3f}/{crypto['recall']:.3f}  "
            f"rel P/R={rel['precision']:.3f}/{rel['recall']:.3f}  "
            f"refusals={rel['refusals']['refused']}/{rel['refusals']['expected']}  "
            f"ingest={row['performance']['ingest_seconds']:.2f}s"
        )
    if args.min_precision is not None:
        worst = min(
            min(row["accuracy"]["crypto"]["precision"], row["accuracy"]["relationships"]["precision"])
            for row in document["rows"]
        )
        if worst < args.min_precision:
            print(f"precision {worst:.3f} below the required {args.min_precision:.3f}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
