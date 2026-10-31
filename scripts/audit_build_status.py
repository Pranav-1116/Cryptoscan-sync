#!/usr/bin/env python3
"""Measure — rather than claim — how finished this product is.

The complaint this exists to answer is "90% of it is still partial". That is a
number, so it should be produced by a measurement someone else can re-run, not by
whoever is writing the summary.

Four measurements, each with a definition that says what it does *not* mean:

1. **Endpoint surface** — every route the API actually serves (read from the
   generated OpenAPI document, so a wrapper or a shadowed router cannot hide one).
2. **UI reachability** — routes for which the browser client (`frontend/src/lib`)
   or any component contains a matching URL. An unreachable endpoint is not
   necessarily broken; it is a capability no operator can use from the console.
3. **Test reachability** — routes whose path appears in a test file. Untested is
   not the same as untested-but-known-good: it is unmeasured.
4. **Stub and marker scan** — literal admissions in the source (`stub`,
   `NotImplementedError`, `TODO`, `demo`, `synthetic`, `placeholder`,
   `reference surface`), reported with file and line so each one can be judged
   rather than counted.

Usage::

    python scripts/audit_build_status.py            # human summary
    python scripts/audit_build_status.py --json     # machine-readable
    python scripts/audit_build_status.py --markdown docs/bank-environment/95-build-status-audit.md

Exit code is 0 — this is a status report, not a gate. A gate that fails on "some
route has no screen" would be gamed by deleting routes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

#: words that, inside a comment or docstring, are an admission rather than a
#: domain term. A migration task genuinely named ``TODO`` is not one of these —
#: which is why this scan reads *comments and docstrings*, not raw lines.
ADMISSION_WORDS: tuple[str, ...] = (
    "stub",
    "not implemented",
    "placeholder",
    "reference surface",
    "demo",
    "synthetic",
    "simplified",
    "approximation",
)

SCAN_DIRS = ("services", "shared")
SKIP_PARTS = {".venv", "node_modules", "__pycache__", "tests", "migrations"}

#: `_rsGet<Foo>(\`/api/v1/x/${y}\`)` → /api/v1/x/{}
_URL_LITERAL = re.compile(r"[\"'`](/api/v1[^\"'`]*)[\"'`]")
_TEMPLATE = re.compile(r"\$\{[^}]*\}")


def _normalise(path: str) -> str:
    path = path.split("?")[0].rstrip("/")
    path = _TEMPLATE.sub("{}", path)
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path or "/"


def api_surface() -> dict:
    from api.main import create_app
    from api.routers.enterprise import withdrawn_routes

    withdrawn = set(withdrawn_routes())

    app = create_app()
    document = app.openapi()
    endpoints: list[dict] = []
    for path, operations in (document.get("paths") or {}).items():
        for method, operation in operations.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "normalised": _normalise(path),
                    "summary": (operation.get("summary") or "")[:120],
                    "tags": operation.get("tags") or [],
                    # A withdrawn route is served but answers 410. Counting it as an
                    # unreachable capability would be wrong in both directions: it is
                    # not a screen nobody built, and it is not an integration point.
                    "withdrawn": path in withdrawn,
                }
            )
    return {"document_version": document.get("info", {}).get("version"), "endpoints": endpoints}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def frontend_urls() -> set[str]:
    urls: set[str] = set()
    for directory in (ROOT / "frontend" / "src",):
        for path in directory.rglob("*"):
            if path.suffix not in {".ts", ".tsx"} or not path.is_file():
                continue
            for match in _URL_LITERAL.finditer(_read(path)):
                urls.add(_normalise(match.group(1)))
    return urls


def test_paths() -> set[str]:
    found: set[str] = set()
    for path in (ROOT / "services").rglob("test_*.py"):
        if not path.is_file():
            continue
        for match in _URL_LITERAL.finditer(_read(path)):
            found.add(_normalise(match.group(1)))
        # tests sometimes build the path as a fragment; catch bare "/estate/evidence/x"
        for match in re.finditer(r"[\"'](/[a-z0-9][a-z0-9\-/_]{4,})[\"']", _read(path)):
            fragment = match.group(1)
            if fragment.count("/") >= 2:
                found.add(_normalise("/api/v1" + fragment) if not fragment.startswith("/api") else _normalise(fragment))
    return found


#: word-boundary match. ``demo`` must not fire on "demoted", and ``stub`` must not
#: fire on "stubborn" — a scan that counts substrings measures its own English.
_ADMISSION = re.compile(
    r"\b(stub|stubbed|not implemented|placeholder|reference surface|demo|synthetic|simplified|approximation)\b"
)

#: ``synthetic`` and ``placeholder`` are also the names of real fixtures in this
#: repository. When they describe a fixture rather than a shortfall, they are not
#: an admission and must not be counted as one.
_DOMAIN_PHRASES: tuple[str, ...] = (
    "synthetic bank",
    "synthetic estate",
    "synthetic data",
    "synthetic traffic",
    "synthetic corpus",
    "synthetic vault",
    "synthetic scenario",
    "synthetic tenant",
    "placeholder value",
)


def _is_domain_term(word: str, lowered: str) -> bool:
    if word not in {"synthetic", "placeholder"}:
        return False
    return any(phrase in lowered for phrase in _DOMAIN_PHRASES)


def _docstring_lines(tree) -> dict[int, str]:
    """Line number → docstring text for every module/class/function docstring."""
    import ast

    found: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                value = body[0].value.value
                if isinstance(value, str):
                    found[body[0].lineno] = value
    return found


def admissions() -> list[dict]:
    """Self-declared limits, read from comments and docstrings — not from raw text.

    Counting the literal string ``TODO`` anywhere in a Python file is how a status
    report becomes noise: this repository has a migration task state genuinely
    called ``TODO`` and 30-odd docstrings about the *synthetic bank estate*, which
    is a fixture, not a gap. So the scan reads comments and docstrings only, and
    separates three kinds of hit:

    * ``ABSTRACT_OR_GAP`` — a ``raise NotImplementedError``. An ABC contract is a
      design, a leaf implementation raising it is a hole; the line is listed so a
      human can tell which.
    * ``CODE_TODO`` — a ``TODO``/``FIXME`` comment: a known unfinished thing.
    * ``SELF_DECLARED`` — a comment or docstring that calls its own behaviour a
      stub / placeholder / demo / synthetic / approximation. These are the honest
      ones; they are listed because a reader deserves to see them, not because
      every one is a defect.
    """
    import ast
    import io
    import tokenize

    hits: list[dict] = []
    for base in SCAN_DIRS:
        for path in (ROOT / base).rglob("*.py"):
            if not path.is_file() or SKIP_PARTS & set(path.parts):
                continue
            text = _read(path)
            relative = str(path.relative_to(ROOT))

            # 1) raise NotImplementedError — AST, so a caught one is not counted
            try:
                tree = ast.parse(text)
            except SyntaxError:
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Raise) and isinstance(node.exc, (ast.Call, ast.Name)):
                        target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
                        name = getattr(target, "id", None) or getattr(target, "attr", None)
                        if name == "NotImplementedError":
                            hits.append(
                                {
                                    "kind": "ABSTRACT_OR_GAP",
                                    "file": relative,
                                    "line": node.lineno,
                                    "text": text.splitlines()[node.lineno - 1].strip()[:160],
                                }
                            )

            # 2) comments and 3) docstrings
            blocks: list[tuple[int, str, str]] = []
            try:
                for token in tokenize.generate_tokens(io.StringIO(text).readline):
                    if token.type == tokenize.COMMENT:
                        blocks.append((token.start[0], "comment", token.string))
            except (tokenize.TokenError, IndentationError):
                pass
            if tree is not None:
                for line, doc in _docstring_lines(tree).items():
                    blocks.append((line, "docstring", doc))

            for line, where, body in blocks:
                lowered = body.lower()
                if re.search(r"\b(todo|fixme|xxx)\b", lowered):
                    hits.append(
                        {
                            "kind": "CODE_TODO",
                            "file": relative,
                            "line": line,
                            "text": body.strip().splitlines()[0][:160],
                        }
                    )
                    continue
                match = _ADMISSION.search(lowered)
                if match is None or _is_domain_term(match.group(0), lowered):
                    continue
                hits.append(
                    {
                        "kind": "SELF_DECLARED",
                        "file": relative,
                        "line": line,
                        "marker": match.group(0),
                        "where": where,
                        "text": body.strip().splitlines()[0][:160],
                    }
                )
    return hits


def _match(endpoint: dict, urls: set[str]) -> bool:
    """Exact path match after normalising variable segments.

    Strict, with one allowance that matters: a client usually composes
    ``${BASE}/${id}``, so a *base path constant* legitimately covers routes whose
    remaining segments are all dynamic. Everything else must match exactly — a
    loose prefix match made every nested route look covered by one parent call and
    produced 99.5%, which is the flattery this report exists to replace.
    """
    target = endpoint["normalised"]
    if target in urls:
        return True
    for url in urls:
        if not url or not target.startswith(url + "/"):
            continue
        rest = [segment for segment in target[len(url) + 1:].split("/") if segment]
        if rest and all(segment == "{}" for segment in rest):
            return True
    return False


def build_report() -> dict:
    surface = api_surface()
    endpoints = surface["endpoints"]
    known_urls = frontend_urls()
    tested = test_paths()
    stubs = admissions()

    for endpoint in endpoints:
        endpoint["ui"] = _match(endpoint, known_urls)
        endpoint["tested"] = _match(endpoint, tested)

    by_prefix: dict[str, dict] = {}
    for endpoint in endpoints:
        parts = endpoint["path"].strip("/").split("/")
        group = parts[2] if len(parts) > 2 else "root"
        bucket = by_prefix.setdefault(group, {"endpoints": 0, "with_ui": 0, "tested": 0})
        bucket["endpoints"] += 1
        bucket["with_ui"] += int(endpoint["ui"])
        bucket["tested"] += int(endpoint["tested"])

    total = len(endpoints)
    with_ui = sum(1 for endpoint in endpoints if endpoint["ui"])
    tested_count = sum(1 for endpoint in endpoints if endpoint["tested"])

    return {
        "api_version": surface["document_version"],
        "endpoints": total,
        "endpoints_with_ui": with_ui,
        "endpoints_tested": tested_count,
        "ui_percent": round(100.0 * with_ui / total, 1) if total else None,
        "tested_percent": round(100.0 * tested_count / total, 1) if total else None,
        "by_prefix": dict(sorted(by_prefix.items(), key=lambda item: -item[1]["endpoints"])),
        "stub_hits": stubs,
        "stub_files": len({hit["file"] for hit in stubs}),
        "stub_kinds": dict(Counter(hit["kind"] for hit in stubs)),
        "routes": [
            {
                key: endpoint[key]
                for key in ("method", "path", "ui", "tested", "summary", "withdrawn")
            }
            for endpoint in sorted(endpoints, key=lambda item: item["path"])
        ],
    }


_DOCS = Path(__file__).resolve().parents[1] / "docs" / "bank-environment"


def _load_artifact(name: str) -> dict | None:
    """Read a measured artifact, or None when it has not been generated."""
    try:
        return json.loads((_DOCS / name).read_text())
    except (OSError, ValueError):
        return None


def _scale_curve_cell() -> str:
    """The measured scale curve, read from the harness's own artifact."""
    document = _load_artifact("107-scale-curve.json")
    rows = (document or {}).get("rows") or []
    if not rows:
        return "**not measured** — `scripts/scale_bank_curve.py` has not been run"
    accuracies = [
        row["accuracy"][family][key]
        for row in rows
        for family in ("crypto", "relationships")
        for key in ("precision", "recall", "f1")
    ]
    refusals = [row["accuracy"]["relationships"]["refusals"] for row in rows]
    correlation = [row["accuracy"]["correlation"] for row in rows]
    worst = min(accuracies) if accuracies else 0.0
    refused = sum(int(item.get("refused") or 0) for item in refusals)
    expected_refusals = sum(int(item.get("expected") or 0) for item in refusals)
    probes = sum(int(item.get("agreement", {}).get("expected") or 0) for item in correlation)
    detected = sum(int(item.get("agreement", {}).get("detected") or 0) for item in correlation)
    return (f"**measured** at {len(rows)} scales — every precision/recall/F1 >= {worst:.3f}, "
            f"{refused}/{expected_refusals} refusals refused, {detected}/{probes} correlation "
            "probes agreed")


def _evidence_integrity_cell() -> str:
    """The evidence tamper matrix, read from the drill's own artifact."""
    document = _load_artifact("112-evidence-integrity.json")
    if not document:
        return "**not measured** — `scripts/evidence_integrity_drill.py` has not been run"
    detected = int(document.get("attacks_detected") or 0)
    total = int(document.get("attacks_total") or 0)
    undetectable = int(document.get("attacks_undetectable_by_design") or 0)
    missed = int(document.get("attacks_undetected") or 0)
    enforcing = int(document.get("read_paths_enforcing") or 0)
    points = int(document.get("read_paths_total") or 0)
    cell = (f"**{detected} / {total}** tampering attacks detected, {enforcing}/{points} "
            "enforcement points reject")
    if undetectable:
        cell += f", {undetectable} undetectable by design"
    if missed:
        cell += f", **{missed} MISSED**"
    return cell


def _job_contract_cell() -> str:
    """The job/worker contract, read from the drills' own artifact."""
    document = _load_artifact("111-job-contract.json")
    if not document:
        return "**not measured** — `scripts/job_contract_matrix.py` has not been run"
    proven = int(document.get("proven") or 0)
    total = int(document.get("expected_properties") or 9)
    broken = int(document.get("broken") or 0)
    unproven = int(document.get("unproven") or 0)
    cell = f"**{proven} / {total} proven** by an executed drill"
    if broken:
        cell += f", **{broken} BROKEN**"
    if unproven:
        cell += f", {unproven} unproven (not passes)"
    return cell


def _failure_matrix_cell() -> str:
    """The nine failure modes, read from the drills' own artifact."""
    document = _load_artifact("109-failure-matrix.json")
    if not document:
        return "**not measured** — `scripts/failure_matrix.py` has not been run"
    proven = int(document.get("proven") or 0)
    total = int(document.get("expected_modes") or 9)
    broken = int(document.get("broken") or 0)
    unproven = int(document.get("unproven") or 0)
    cell = f"**{proven} / {total} proven** by an executed drill"
    if broken:
        cell += f", **{broken} BROKEN**"
    if unproven:
        cell += f", {unproven} unproven (not passes)"
    return cell


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    add = lines.append
    add("# 95 — Build status, measured")
    add("")
    add(
        "Generated by `python scripts/audit_build_status.py --markdown "
        "docs/bank-environment/95-build-status-audit.md`. Re-run it after any change; "
        "a status that is typed by hand rots within a week."
    )
    add("")
    add("## What this measures, and what it refuses to")
    add("")
    add(
        "A status report that says \"90% complete\" is a feeling. These are the only four things this "
        "script can actually see, and each is stated with its ceiling:"
    )
    add("")
    # computed, not typed: a hand-written "34 endpoints of 1,160" was stale within one
    # iteration, and a status document that quietly drifts is worse than none
    estate = (report.get("by_prefix") or {}).get("estate") or {}
    add(
        "* **Surface without a screen is the real gap.** The engines exist; the console over them "
        f"often does not. That is why the estate/twin work ({estate.get('endpoints', 0)} endpoints, "
        f"{estate.get('with_ui', 0)} with a screen) is a small share of {report['endpoints']:,} and "
        "why \"it is all still partial\" is a defensible reading of this table."
    )
    add(
        "* **Four things cannot be measured from source at all**, and are therefore absent from every "
        "number below: correctness against a real bank estate, vendor hardware behaviour (HSM firmware, "
        "ADC images), whether a screen is *usable*, and whether an approval workflow matches a "
        "regulator's expectation. Those need a deployment and an auditor, not a script."
    )
    add(
        "* **Test references are counted, not judged.** A route reached once by a smoke call counts the "
        "same as one with twenty behavioural tests."
    )
    add("")

    add("## The measured numbers")
    add("")
    add("| Measure | Value | What it means | What it does **not** mean |")
    add("|---|---|---|---|")
    add(
        f"| API endpoints served | **{report['endpoints']}** | routes in the generated OpenAPI document | — |"
    )
    add(
        f"| Endpoints reachable from the console | **{report['endpoints_with_ui']}** "
        f"({report['ui_percent']}%) | a URL for it exists in `frontend/src` | built. An endpoint with no "
        "screen is a capability an operator cannot use, not a broken one |"
    )
    add(
        f"| Synthetic-bank scale curve (10/50/100/150) | {_scale_curve_cell()} "
        "| `docs/bank-environment/108-scale-curve.md` | that a bank's real estate scores the "
        "same: the corpus is generated from this repository's own vocabulary, so it is a "
        "regression curve, not an accuracy estimate |"
    )
    add(
        f"| Evidence tampering detected | {_evidence_integrity_cell()} "
        "| `docs/bank-environment/112-evidence-integrity.md` | tamper *proof*: the scan manifest "
        "is unsigned, so a full rewrite verifies PASS |"
    )
    add(
        f"| Job/worker contract properties | {_job_contract_cell()} "
        "| `docs/bank-environment/111-job-contract.md` | that a retried job is retried after a "
        "*failure*: the contract retries worker loss, not handler errors |"
    )
    add(
        f"| Failure modes with an executed drill | {_failure_matrix_cell()} "
        "| `docs/bank-environment/109-failure-matrix.md` | that the deployment is configured, "
        "monitored or observed — these are in-process drills, not a chaos run |"
    )
    add(
        f"| Endpoints referenced by a test | **{report['endpoints_tested']}** "
        f"({report['tested_percent']}%) | the path appears in a test file | tested well, or tested at all "
        "beyond a smoke call |"
    )
    kinds = report.get("stub_kinds") or {}
    add(
        f"| Self-declared limits | **{len(report['stub_hits'])}** in {report['stub_files']} files "
        f"({kinds.get('ABSTRACT_OR_GAP', 0)} abstract/gap raises, {kinds.get('CODE_TODO', 0)} TODO comments, "
        f"{kinds.get('SELF_DECLARED', 0)} self-described stubs/approximations) | admissions found in "
        "comments and docstrings | that any of them is a defect. Most are honest labels; the list is "
        "here so they can be judged one by one |"
    )
    add("")
    add("## Where the surface is")
    add("")
    add("| Area | Endpoints | With a UI caller | Referenced by a test |")
    add("|---|---|---|---|")
    for name, bucket in report["by_prefix"].items():
        add(f"| `{name}` | {bucket['endpoints']} | {bucket['with_ui']} | {bucket['tested']} |")
    add("")
    add("## Endpoints with no console caller")
    add("")
    withdrawn = [route for route in report["routes"] if route.get("withdrawn")]
    if withdrawn:
        add(
            f"**{len(withdrawn)} of the endpoints below are withdrawn, not unbuilt.** They answer "
            f"`410 Gone` and are listed separately at the end of this section — an integrator must be "
            f"able to discover the refusal, but they are not a console gap."
        )
        add("")
    missing = [route for route in report["routes"] if not route["ui"] and not route.get("withdrawn")]
    if not missing:
        add("None.")
    else:
        add("| Method | Path | What it does |")
        add("|---|---|---|")
        for route in missing:
            add(f"| {route['method']} | `{route['path']}` | {route['summary'] or '—'} |")
    add("")
    if withdrawn:
        add("### Withdrawn (410) — discoverable, not callable")
        add("")
        add("| Method | Path | What it does |")
        add("|---|---|---|")
        for route in withdrawn:
            add(
                f"| {route['method']} | `{route['path']}` | "
                f"{route['summary'] or '—'} — **withdrawn: answers `410`**, see "
                f"[airgap-deployment.md](../airgap-deployment.md) |"
            )
        add("")
    add("## Self-declared limits")
    add("")
    if not report["stub_hits"]:
        add("None.")
    else:
        for kind, blurb in (
            ("ABSTRACT_OR_GAP", "`raise NotImplementedError` — an ABC contract if the class is abstract, a hole if it is not"),
            ("CODE_TODO", "a `TODO`/`FIXME` comment"),
            ("SELF_DECLARED", "a comment or docstring that calls its own behaviour a stub / placeholder / demo / approximation"),
        ):
            hits = [hit for hit in report["stub_hits"] if hit["kind"] == kind]
            add(f"### {kind} ({len(hits)}) — {blurb}")
            add("")
            if not hits:
                add("None.")
                add("")
                continue
            add("| File:line | Text |")
            add("|---|---|")
            for hit in hits[:80]:
                text = hit["text"].replace("|", "\\|")
                add(f"| `{hit['file']}:{hit['line']}` | {text} |")
            if len(hits) > 80:
                add("")
                add(f"_{len(hits) - 80} further hits omitted._")
            add("")
    add("")
    add("## How to read this honestly")
    add("")
    add(
        "* **No single percentage is \"finished\"** here. A route with a screen and a test can still be "
        "wrong for a bank; a route with neither can be a deliberate operator/CLI surface."
    )
    add(
        "* The estate engine (specs 93/94) is not the whole product. This table is the whole product, "
        "which is why the twin work is a small share of the endpoints."
    )
    add(
        "* Anything this report cannot measure is stated as such rather than estimated: correctness "
        "against a real bank environment, vendor coverage, and whether a given screen is *usable* are "
        "not derivable from the source."
    )
    add("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the machine-readable report")
    parser.add_argument("--markdown", metavar="PATH", help="write the markdown report to PATH")
    args = parser.parse_args()

    report = build_report()

    if args.markdown:
        target = Path(args.markdown)
        if not target.is_absolute():
            target = ROOT / target
        target.write_text(render_markdown(report), encoding="utf-8")
        print(f"wrote {target.relative_to(ROOT)}")

    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.markdown:
        print(f"endpoints            {report['endpoints']}")
        print(f"with a UI caller     {report['endpoints_with_ui']} ({report['ui_percent']}%)")
        print(f"referenced by test   {report['endpoints_tested']} ({report['tested_percent']}%)")
        print(f"stub/marker hits     {len(report['stub_hits'])} in {report['stub_files']} files")
        print()
        for name, bucket in list(report["by_prefix"].items())[:15]:
            print(f"  {name:<24} {bucket['endpoints']:>4} endpoints  ui {bucket['with_ui']:>3}  tested {bucket['tested']:>3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
