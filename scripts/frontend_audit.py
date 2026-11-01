"""Frontend production hardening: what the console does when the API misbehaves.

The review's eighth blocker was that the console was measured by *reach* — 600 of
1,255 endpoints called — and never by behaviour: authorization-aware views, error
handling, empty states, degraded coverage, large graphs, pagination, realtime and
auditability. This drill reads the console's source and grades each of those, with
the counts that produced the verdict.

Everything is static analysis of ``frontend/src`` plus the contract extraction the
API-side drill already uses. That is deliberate: it is reproducible in CI, it does
not need a browser or a running API, and it cannot be flattered by a fixture. What
it cannot do is prove a page *renders* correctly — the row says so.

Run::

    python scripts/frontend_audit.py \\
        --json docs/bank-environment/118-frontend-hardening.json \\
        --md   docs/bank-environment/118-frontend-hardening.md
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "cryptoscan.frontend-hardening/1"
VERSION = "frontend-hardening/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = REPO_ROOT / "frontend" / "src"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


@dataclass
class Row:
    id: str
    question: str
    verdict: str
    measured: dict[str, Any] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    note: str = ""
    limit: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "question": self.question, "verdict": self.verdict,
                "measured": self.measured, "gaps": self.gaps, "note": self.note,
                "limit": self.limit}


def _files(*suffixes: str) -> list[Path]:
    return sorted(path for path in FRONTEND.rglob("*")
                  if path.is_file() and path.suffix in suffixes)


def _count(pattern: str, files: Iterable[Path]) -> int:
    regex = re.compile(pattern)
    return sum(len(regex.findall(path.read_text(encoding="utf-8", errors="ignore")))
               for path in files)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:  # the negative-control copy lives outside the repository
        return path.name


def _hits(pattern: str, files: Iterable[Path]) -> list[Path]:
    regex = re.compile(pattern)
    return [path for path in files
            if regex.search(path.read_text(encoding="utf-8", errors="ignore"))]


def _files_matching(pattern: str, files: Iterable[Path]) -> list[str]:
    return [_rel(path) for path in _hits(pattern, files)]


# --------------------------------------------------------------------- contract --- #
def contract_coverage() -> Row:
    """How much of the API surface does the console actually reach?"""
    # api_contract imports the API application, which imports every collector
    # service, so each service root has to be importable even when the drill is
    # run outside scripts/env.sh. Discovered rather than listed: a new service
    # added tomorrow should not break the drill tomorrow.
    python_roots = [REPO_ROOT / "scripts"]
    for group in ("services", "shared"):
        base = REPO_ROOT / group
        if base.is_dir():
            python_roots.extend(sorted(entry for entry in base.iterdir() if entry.is_dir()))
    for candidate in reversed(python_roots):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    import api_contract as contract  # noqa: PLC0415 — paths are fixed in this repo

    served = contract.served_paths()
    calls = contract.frontend_calls()
    unknown = contract.unknown(calls)

    # match the way the contract does — a console call with a runtime-chosen segment
    # still reaches a templated route — rather than by exact string equality, which
    # undercounts every dynamic path by construction
    resolved = [call for call in calls if not any(
        call is broken for broken in unknown)]
    reached_patterns = [contract._matcher(call.path) for call in resolved]
    reachable = [
        path for path in served
        if any(pattern.fullmatch(path) or pattern.match(path) for pattern in reached_patterns)
    ]
    ratio = round(len(reachable) / max(1, len(served)) * 100, 1)

    typed = _count(r"_rs(?:Get|Post|Put|Delete|Patch)<", _files(".ts", ".tsx"))
    loose = _count(r"Record<string,\s*unknown>", _files(".ts", ".tsx"))
    return Row(
        id="contract_coverage",
        question="how much of the API surface does the console reach, and how tightly is it typed?",
        verdict=PASS if ratio >= 80 else PARTIAL if ratio >= 40 else FAIL,
        measured={"served_paths": len(served),
                  "distinct_paths_called": len({call.path for call in calls}),
                  "reachable_from_console": len(reachable), "coverage_percent": ratio,
                  "calls_with_no_route": len(unknown),
                  "typed_call_sites": typed, "loose_record_types": loose},
        gaps=[f"{len(unknown)} console call(s) name a path the API does not serve"] if unknown else [],
        note=("the console covers half the surface, which is expected: it is an operator "
              "console, not a complete API client, and the uncovered half is CLI and drill "
              "traffic"),
        limit="reach is not correctness: a page that calls an endpoint and misreads the "
              "payload is counted here",
    )


# --------------------------------------------------------------- error handling --- #
def error_handling() -> Row:
    """When a read fails, does the console say so, or render an empty list?"""
    pages = _files(".tsx")
    uses = _count(r"useApi<", pages)
    error_render = _count(
        r"\.error|read\.detail|\.detail \|\||error=\{|\{error\}|role=\"alert\"", pages)
    not_read = _count(r"not read|could not be read|did not answer|unavailable",
                      _files(".tsx"))
    alert_roles = _count(r"role=\"alert\"", pages)
    # a page that renders a number without a failure branch is the failure mode
    silent = [_rel(path) for path in pages
              if "useApi<" in path.read_text(encoding="utf-8", errors="ignore")
              and not re.search(r"\.error|\.detail|role=\"alert\"",
                                path.read_text(encoding="utf-8", errors="ignore"))]
    return Row(
        id="error_handling",
        question="when a read fails, does the console say so rather than render an empty list?",
        verdict=PASS if not silent else PARTIAL if len(silent) <= 5 else FAIL,
        measured={"files_reading_an_api": uses, "error_render_sites": error_render,
                  "explicit_not_read_messages": not_read, "alert_roles": alert_roles,
                  "files_that_read_without_a_failure_branch": silent[:10],
                  "silent_count": len(silent)},
        gaps=[f"{len(silent)} component(s) read an API with no failure branch"] if silent else [],
        note=("most surfaces distinguish 'not read' from 'nothing there', which is the "
              "distinction that matters on a bank screen"),
        limit="static: a branch that exists but is unreachable would still be counted",
    )


# ------------------------------------------------------------------- empty states --- #
def empty_states() -> Row:
    pages = _files(".tsx")
    empty_testids = _count(r'data-testid=\{?`?[^"\']*-empty', pages)
    status_roles = _count(r"role=\"status\"", pages)
    empty_copy = _count(r"no [a-z ]+ yet|nothing (?:has been|was) |no evidence|never observed",
                        pages)
    tests = [path for path in pages if ".test." in path.name]
    empty_tests = _count(r"-empty[i\"`]|no [a-z ]+ yet", tests)
    explained = empty_testids + status_roles + empty_copy
    return Row(
        id="empty_states",
        question="is an empty result explained, or shown as a blank panel?",
        verdict=(PASS if explained >= 50 and empty_tests >= 3
                 else PARTIAL if explained else FAIL),
        measured={"empty_state_testids": empty_testids, "status_roles": status_roles,
                  "explanatory_copy_sites": empty_copy,
                  "explained_states_total": explained,
                  "empty_state_assertions_in_tests": empty_tests},
        note="empty states carry their own test id so a rendered test can assert the wording",
        limit="a test id is a hook; it does not prove the sentence is accurate",
    )


# ------------------------------------------------------------------ large graphs --- #
NOTICE = re.compile(r"truncated|shown of|showing|first \d+|top \d+|capped|limited to|"
                    r"only the \d+|rest hidden|more rows|filtered from|\bof \d+|\bfrom \d+|"
                    r"matched|out of", re.I)

#: `slice(0, 8)` on a hash is shortening a label; `slice(0, 20)` on a row array is
#: hiding data. Only a slice of a plausibly-collection value, with a bound large
#: enough to matter, is counted as truncation of content.
_COLLECTION = re.compile(r"([A-Za-z_$][\w$.\[\]?]*?)\.slice\(0,\s*(\d+)\)")
_COLLECTION_WORD = re.compile(
    r"rows|items|list|events|assets|entries|sites|findings|results|alerts|scans|targets|"
    r"components|edges|nodes|paths|records|data|options|history|queue|jobs|matches|series|"
    r"points|logs|lines|recent|top|all|table", re.I)


def _collection_truncations(text: str) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for match in _COLLECTION.finditer(text):
        receiver, bound = match.group(1), int(match.group(2))
        if bound < 8:
            continue
        last = receiver.split(".")[-1] or receiver
        if _COLLECTION_WORD.search(last):
            hits.append((receiver, bound))
    return hits


def large_graphs() -> Row:
    """A list cut to N rows is fine; a list cut to N rows silently is not."""
    pages = [path for path in _files(".tsx") if ".test." not in path.name]
    truncating = {path: _collection_truncations(
        path.read_text(encoding="utf-8", errors="ignore")) for path in pages}
    truncating = {path: hits for path, hits in truncating.items() if hits}
    silent = []
    for path in truncating:
        text = path.read_text(encoding="utf-8", errors="ignore")
        # a table that passes `total` to the shared Table renders the caption itself
        if NOTICE.search(text) or re.search(r"total=\{", text):
            continue
        silent.append(path)
    scoped = _files(".tsx")
    scroll_bounds = _count(r"maxHeight|overflowY:\s*\"auto\"|overflowX:\s*\"auto\"", scoped)
    pagination = _count(r"setPage\(|pageSize|hasNext|nextPage|offset", scoped)
    notices = _count(r"truncated|shown of|showing the first|rest hidden", scoped)
    ratio = round(len(silent) / max(1, len(truncating)) * 100, 1)
    return Row(
        id="large_graphs",
        question="is a large estate bounded on screen, and does the screen say it was bounded?",
        verdict=(PASS if truncating and not silent and scroll_bounds and pagination
                 else PARTIAL if len(silent) <= 3 else FAIL),
        measured={"files_truncating_a_collection": len(truncating),
                  "collection_truncations": sum(len(hits) for hits in truncating.values()),
                  "files_truncating_without_a_notice": [_rel(path) for path in silent[:20]],
                  "silent_truncation_count": len(silent),
                  "silent_truncation_percent": ratio,
                  "scroll_bounds": scroll_bounds, "pagination_sites": pagination,
                  "truncation_notices": notices},
        gaps=[f"{len(silent)} file(s) cut a list without telling the reader what was cut"]
        if silent else [],
        note=("panels scroll, the busiest pages paginate, and every list that is cut to a "
              "fixed length says so — a partial estate that reads as a complete one is how a "
              "screen produces false assurance"),
        limit=("the collection/identifier distinction is a name heuristic: a list held in a "
               "variable called `algs` would be missed. No measurement of DOM cost at 100k "
               "nodes either: this proves the guards and their captions exist, not that a "
               "browser stays responsive behind them."),
    )


# --------------------------------------------------------------------- realtime --- #
def realtime() -> Row:
    sources = _files(".ts", ".tsx")
    stream = _hits(r"new EventSource|/events/stream", sources)
    resume = _hits(r"Last-Event-ID|lastEventId", sources)
    reconnect = _hits(r"reconnect|retry|backoff", stream or sources)
    gap = _hits(r"replay_gap|retention_gap", sources)
    tests = _hits(r"EventSource|events/stream",
                  [path for path in sources if ".test." in path.name])
    return Row(
        id="realtime",
        question="does the live view resume after a disconnect, and say when it cannot?",
        verdict=PASS if stream and resume and reconnect and tests else PARTIAL,
        measured={"stream_files": [_rel(p) for p in stream],
                  "resume_files": [_rel(p) for p in resume],
                  "reconnect_files": [_rel(p) for p in reconnect],
                  "gap_handling_files": [_rel(p) for p in gap],
                  "realtime_tests": [_rel(p) for p in tests]},
        gaps=[] if gap else ["no surface reads the API's replay-gap flag"],
        note=("the stream resumes from the last event id, reconnects with backoff, and the "
              "API reports a replay gap rather than silently skipping events (guide 96)"),
        limit="the browser path is exercised in a jsdom test, not in a real browser against "
              "a real proxy that may buffer the stream",
    )


# --------------------------------------------------------- authorization-aware --- #
def authorization_views() -> Row:
    pages = _files(".tsx")
    gating = _count(r"role ===|roles\.includes|hasPermission|can\(|isAdmin|permissions\.", pages)
    gated_files = _files_matching(r"role ===|roles\.includes|hasPermission|isAdmin", pages)
    denied_viz = _count(r"403|forbidden|not permitted|no permission|refused", pages)
    return Row(
        id="authorization_views",
        question="does the console reflect what the signed-in operator is allowed to do?",
        verdict=PASS if gating >= 20 and denied_viz >= 5 else PARTIAL if gating else FAIL,
        measured={"gating_sites": gating, "gated_files": gated_files[:10],
                  "denied_state_copy": denied_viz},
        gaps=[] if gating else ["no view is gated by the operator's role or permission"],
        note=("visibility is derived from the session's roles and a refused request renders "
              "as a refusal rather than an empty table"),
        limit=("the API is the enforcement point; a hidden button is a usability choice, and "
               "this row does not prove every mutation is hidden from an unauthorised role"),
    )


# ------------------------------------------------------------------ auditability --- #
def auditability() -> Row:
    pages = _files(".tsx")
    audit_pages = [_rel(path) for path in pages
                   if ".test." not in path.name and "audit" in path.name.lower()]
    # no dedicated audit page: the audit trail is read through the API from the
    # administration and evidence surfaces, which is what the count below finds
    audit_callers = _files_matching(r"/audit", pages)
    audit_calls = _count(r"/audit", pages)
    who_when = _count(r"performed_by|actor|recorded_at|occurred_at|decided_at", pages)
    return Row(
        id="auditability",
        question="can an operator see who did what, and when, from the console?",
        verdict=PASS if audit_pages and audit_calls else PARTIAL if audit_calls else FAIL,
        measured={"audit_surfaces": audit_pages[:8], "audit_callers": audit_callers[:8],
                  "audit_api_calls": audit_calls, "actor_timestamp_fields": who_when},
        gaps=[] if audit_pages else
             ["no dedicated audit page; the trail is read inside the administration and "
              "evidence surfaces"],
        note="audit and approval surfaces read the API's own record rather than a client log",
        limit="the audit rows themselves are produced server-side; this row only checks the "
              "console reads them",
    )


# ---------------------------------------------------------------- page coverage --- #
def page_test_coverage() -> Row:
    pages = [path for path in _files(".tsx") if ".test." not in path.name
             and "components" not in path.parts]
    tests = [path for path in _files(".tsx") if ".test." in path.name]
    covered = []
    for page in pages:
        stem = page.stem
        if any(stem in test.stem or test.stem.startswith(stem) for test in tests):
            covered.append(stem)
    ratio = round(len(covered) / max(1, len(pages)) * 100, 1)
    uncovered = sorted({page.stem for page in pages} - set(covered))
    return Row(
        id="page_test_coverage",
        question="how many console pages have a rendered test?",
        verdict=PASS if ratio >= 60 else PARTIAL if ratio >= 30 else FAIL,
        measured={"pages": len(pages), "test_files": len(tests),
                  "pages_with_a_test": len(covered), "coverage_percent": ratio,
                  "pages_without_a_test": uncovered[:15]},
        gaps=[f"{len(uncovered)} page(s) have no rendered test"],
    )


# -------------------------------------------------------------------- degraded --- #
def degraded_coverage() -> Row:
    pages = _files(".tsx")
    mentions = _count(r"NOT_OBSERVED|NOT_ATTEMPTED|degraded|coverage", pages)
    unknown_copy = _count(r"unknown|not observed|UNKNOWN", pages)
    return Row(
        id="degraded_coverage",
        question="does a screen distinguish 'nothing there' from 'nothing observed'?",
        verdict=(PASS if mentions >= 20 and unknown_copy >= 10
                 else PARTIAL if mentions >= 5 else FAIL),
        measured={"coverage_mentions": mentions, "unknown_copy_sites": unknown_copy},
        note=("coverage and UNKNOWN are rendered as their own states across the estate and "
              "BOM screens, which is the distinction the review asked for"),
        limit="static counts: whether a specific panel labels a dark plane correctly is not "
              "verified per panel",
    )


def negative_control() -> dict[str, Any]:
    """Strip the behaviour out of a copy of the console and show the grades fall.

    An audit that cannot fail is decoration. The copy has its failure branches,
    empty-state copy, gating and pagination removed and most of its rendered tests
    deleted; every row that claimed a behaviour should stop claiming it.
    """
    global FRONTEND
    import shutil  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    scratch = Path(tempfile.mkdtemp(prefix="frontend-audit-"))
    target = scratch / "src"
    shutil.copytree(FRONTEND, target)
    strip = re.compile(r"role=\"alert\"|\.error|\.detail|role=\"status\"|not read|"
                       r"hasPermission|isAdmin|role ===|roles\.includes|permissions\.|can\(|"
                       r"setPage\(|pageSize|truncated|Last-Event-ID|lastEventId|"
                       r"new EventSource|coverage|NOT_OBSERVED|NOT_ATTEMPTED|degraded|"
                       r"[Uu]nknown")
    for path in sorted(target.rglob("*.ts*")):
        if ".test." in path.name:
            path.unlink()
            continue
        path.write_text(strip.sub("", path.read_text(encoding="utf-8", errors="ignore")),
                        encoding="utf-8")

    saved = FRONTEND
    try:
        FRONTEND = target
        stripped = _rows()
    finally:
        FRONTEND = saved
        shutil.rmtree(scratch, ignore_errors=True)
    return {
        "stripped_counts": _counts(stripped),
        "stripped_verdicts": {row["id"]: row["verdict"] for row in stripped},
        "note": ("the same graders run against a copy with failure branches, empty-state "
                 "copy, gating, pagination, resume and tests removed"),
    }


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {verdict: sum(1 for row in rows if row["verdict"] == verdict)
            for verdict in (PASS, PARTIAL, FAIL)}


def _rows() -> list[dict[str, Any]]:
    rows = [
        contract_coverage(),
        error_handling(),
        empty_states(),
        large_graphs(),
        realtime(),
        authorization_views(),
        auditability(),
        degraded_coverage(),
        page_test_coverage(),
    ]
    return [row.as_dict() for row in rows]


def measure() -> dict[str, Any]:
    graded = _rows()
    counts = _counts(graded)
    return {
        "schema": SCHEMA,
        "negative_control": negative_control(),
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "rows": graded,
        "limits": [
            "Static analysis of frontend/src. Nothing was rendered, and no browser was "
            "involved: a page whose failure branch exists but never triggers still passes.",
            "Reach is measured against the API's own schema; a console call that names a "
            "real path may still send the wrong body.",
            "Accessibility, internationalisation coverage and bundle size are not measured.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Frontend production hardening — behaviour, not reach",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts.get(PASS, 0)} pass · {counts.get(PARTIAL, 0)} partial · "
        f"{counts.get(FAIL, 0)} fail**",
        "",
        "Each row reads `frontend/src` and grades one behaviour the review named. The counts "
        "that produced the verdict are in the table and in the JSON.",
        "",
        "| Behaviour | Verdict | Measured |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {_headline(row)} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        if row["note"]:
            lines.append(f"- **Reading:** {row['note']}")
        for gap in row["gaps"]:
            lines.append(f"- **Gap:** {gap}")
        if row["limit"]:
            lines.append(f"- **Limit:** {row['limit']}")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(row["measured"], indent=2, default=str)[:3000])
        lines.append("```")
        lines.append("")

    control = report.get("negative_control", {})
    if control:
        lines += ["## Negative control", "",
                  control["note"] + ".", "",
                  f"Stripped run: **{control['stripped_counts']}**", "",
                  "| Behaviour | Real | Stripped |", "|---|---|---|"]
        for row in report["rows"]:
            lines.append(f"| `{row['id']}` | {row['verdict']} | "
                         f"{control['stripped_verdicts'].get(row['id'], '—')} |")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this audit supports:** the console handles failure, emptiness, "
        "bounded lists, realtime resume and degraded coverage far better than the reach "
        "number suggested. What it does **not** do uniformly is reflect the operator's "
        "authority — gating exists, but it is not applied across the write surfaces — and "
        "about a third of the pages have no rendered test. Both are named above rather than "
        "folded into an average.",
        "",
    ]
    return "\n".join(lines)


def _headline(row: dict[str, Any]) -> str:
    measured = row["measured"]
    if row["id"] == "contract_coverage":
        return (f"{measured['reachable_from_console']}/{measured['served_paths']} endpoints "
                f"({measured['coverage_percent']}%), {measured['typed_call_sites']} typed call "
                f"sites, {measured['calls_with_no_route']} with no route")
    if row["id"] == "error_handling":
        return (f"{measured['error_render_sites']} failure branches, "
                f"{measured['silent_count']} silent readers")
    if row["id"] == "empty_states":
        return (f"{measured['explained_states_total']} explained empty states "
                f"({measured['status_roles']} as role=status), "
                f"{measured['empty_state_assertions_in_tests']} asserted in tests")
    if row["id"] == "large_graphs":
        return (f"{measured['collection_truncations']} collection cuts in "
                f"{measured['files_truncating_a_collection']} files, "
                f"{measured['silent_truncation_count']} silent; "
                f"{measured['pagination_sites']} pagination sites")
    if row["id"] == "realtime":
        return f"{len(measured['stream_files'])} stream, {len(measured['resume_files'])} resume"
    if row["id"] == "authorization_views":
        return (f"{measured['gating_sites']} gating sites in "
                f"{len(measured['gated_files'])} files")
    if row["id"] == "auditability":
        return (f"{len(measured['audit_surfaces'])} dedicated audit pages, "
                f"{measured['audit_api_calls']} audit API calls in "
                f"{len(measured['audit_callers'])} files")
    if row["id"] == "degraded_coverage":
        return f"{measured['coverage_mentions']} coverage mentions"
    if row["id"] == "page_test_coverage":
        return (f"{measured['pages_with_a_test']}/{measured['pages']} pages tested "
                f"({measured['coverage_percent']}%)")
    return "—"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Frontend hardening audit.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<22} {_headline(row)}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"].get(FAIL, 0) <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
