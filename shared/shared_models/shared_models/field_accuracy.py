"""Field accuracy: a bank's own review of CryptoScan's output, turned into the same number as the corpus benchmark.

The corpus benchmark (`scripts/accuracy_benchmark.py`) says how the scanner does on code *we* labelled. A pilot bank
reviews a triage workbook (`scripts/bank_triage.py workbook`) — marks each finding TP/FP and each candidate miss
FN/OK — and this module scores it in exactly the same unit (per file × algorithm family) so the two numbers can be
put side by side. Scored results are published to the API (`POST /api/v1/scans/{scan_id}/triage`) and pooled by
`GET /api/v1/accuracy/field`, which is what BANK-READINESS.md cites as "field-measured".

Pure functions + pydantic models; no I/O.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

_EXT_LANG = {
    ".java": "java", ".kt": "kotlin", ".scala": "scala", ".groovy": "groovy", ".cs": "csharp", ".py": "python", ".go": "go",
    ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".cc": "cpp", ".hpp": "cpp", ".rs": "rust", ".rb": "ruby", ".php": "php", ".swift": "swift", ".m": "objc", ".sql": "sql",
    ".pks": "sql", ".pkb": "sql", ".cbl": "cobol", ".cob": "cobol", ".cpy": "cobol", ".jcl": "jcl", ".asm": "hlasm", ".rpgle": "rpg",
    ".sqlrpgle": "rpg", ".nsp": "natural", ".nsn": "natural", ".4gl": "4gl", ".p": "progress", ".w": "progress", ".tal": "tal",
    ".sas": "sas", ".pl": "perl", ".sh": "shell", ".ps1": "powershell", ".yml": "config", ".yaml": "config", ".json": "config",
    ".xml": "config", ".conf": "config", ".cfg": "config", ".ini": "config", ".inf": "config", ".reg": "config", ".properties": "config",
    ".toml": "config", ".tf": "config", ".mqsc": "config", ".hsm": "config", ".policy": "config", ".plist": "config",
}


def language_of(path: str) -> str:
    p = path.lower()
    for ext, lang in _EXT_LANG.items():
        if p.endswith(ext):
            return lang
    return "other"


class LanguageScore(BaseModel):
    language: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None


class TriageResult(BaseModel):
    """One reviewed workbook, scored."""

    repo: str = Field(..., description="repository / estate label as the bank names it (may be redacted)")
    reviewer: Optional[str] = Field(None, description="who signed off the review (team or role, not necessarily a person)")
    reviewed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scanner_version: Optional[str] = None
    files_scanned: int = 0
    findings_reviewed: int = 0
    candidate_misses_reviewed: int = 0
    unreviewed: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    by_language: list[LanguageScore] = Field(default_factory=list)
    fp_examples: list[dict[str, Any]] = Field(default_factory=list, description="up to 20 {file, algorithm, note} — what the bank rejected")
    fn_examples: list[dict[str, Any]] = Field(default_factory=list, description="up to 20 {file, expected, note} — what the scanner missed")
    notes: Optional[str] = None


def _prf(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None]:
    # No denominator means NOT MEASURED, not perfect accuracy.
    p = round(tp / (tp + fp), 4) if tp + fp else None
    r = round(tp / (tp + fn), 4) if tp + fn else None
    f = round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None
    return p, r, f


def _validate_workbook(wb: Any) -> None:
    if not isinstance(wb, dict):
        raise ValueError("workbook must be an object")
    for field, verdicts in (("findings", {"", "TP", "FP"}), ("candidate_misses", {"", "FN", "OK"})):
        rows = wb.get(field, [])
        if not isinstance(rows, list):
            raise ValueError(f"{field} must be a list")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("file"), str) or not row["file"].strip():
                raise ValueError(f"{field} requires an object with a nonempty file")
            if str(row.get("verdict") or "").strip().upper() not in verdicts:
                raise ValueError(f"invalid verdict for {field}")
            if "expected" in row and (not isinstance(row["expected"], list) or not row["expected"]
                    or any(not isinstance(x, str) or not x.strip() for x in row["expected"])):
                raise ValueError("expected must be a nonempty list of algorithm families")


def score_workbook(wb: dict[str, Any], *, reviewer: str | None = None, notes: str | None = None) -> TriageResult:
    """Score a reviewed `bank_triage.py workbook` JSON. Unit = (file, algorithm family), same as the corpus benchmark.

    Workbook: {"repo", "files_scanned"?, "scanner_version"?, "findings": [{file, algorithm, verdict: TP|FP|""}],
    "candidate_misses": [{file, verdict: FN|OK|"", expected?: [families]}]}.
    """
    _validate_workbook(wb)
    tp_by_file: dict[str, set[str]] = defaultdict(set)
    fp_by_file: dict[str, set[str]] = defaultdict(set)
    fn_by_file: dict[str, set[str]] = {}
    unreviewed = 0
    fp_examples: list[dict[str, Any]] = []
    fn_examples: list[dict[str, Any]] = []
    findings = list(wb.get("findings") or [])
    misses = list(wb.get("candidate_misses") or [])
    for r in findings:
        v = str(r.get("verdict") or "").strip().upper()
        algo = str(r.get("algorithm") or "UNKNOWN").upper()
        if v == "TP":
            tp_by_file[r["file"]].add(algo)
        elif v == "FP":
            fp_by_file[r["file"]].add(algo)
            if len(fp_examples) < 20:
                fp_examples.append({"file": r["file"], "algorithm": algo, "note": (r.get("note") or "")[:200]})
        else:
            unreviewed += 1
    for m in misses:
        v = str(m.get("verdict") or "").strip().upper()
        if v == "FN":
            expected = {str(x).upper() for x in (m.get("expected") or ["UNKNOWN"])}
            fn_by_file[m["file"]] = fn_by_file.get(m["file"], set()) | expected
            if len(fn_examples) < 20:
                fn_examples.append({"file": m["file"], "expected": sorted(expected), "note": (m.get("note") or "")[:200]})
        elif v != "OK":
            unreviewed += 1
    # a family marked TP anywhere in the file cancels an FP mark on the same family (duplicate hits on one line pair)
    per_lang: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for f, fams in tp_by_file.items():
        per_lang[language_of(f)][0] += len(fams)
    for f, fams in fp_by_file.items():
        per_lang[language_of(f)][1] += len(fams - tp_by_file[f])
    for f, fams in fn_by_file.items():
        per_lang[language_of(f)][2] += len(fams - tp_by_file.get(f, set()))
    tp = sum(v[0] for v in per_lang.values())
    fp = sum(v[1] for v in per_lang.values())
    fn = sum(v[2] for v in per_lang.values())
    p, r, f1 = _prf(tp, fp, fn)
    langs = []
    for lang, (ltp, lfp, lfn) in sorted(per_lang.items()):
        lp, lr, lf = _prf(ltp, lfp, lfn)
        langs.append(LanguageScore(language=lang, tp=ltp, fp=lfp, fn=lfn, precision=lp, recall=lr, f1=lf))
    return TriageResult(
        repo=str(wb.get("repo") or "unnamed"), reviewer=reviewer, scanner_version=wb.get("scanner_version"),
        files_scanned=int(wb.get("files_scanned") or 0), findings_reviewed=len(findings) - sum(1 for r in findings if not str(r.get("verdict") or "").strip()),
        candidate_misses_reviewed=sum(1 for m in misses if str(m.get("verdict") or "").strip()), unreviewed=unreviewed,
        tp=tp, fp=fp, fn=fn, precision=p, recall=r, f1=f1, by_language=langs, fp_examples=fp_examples, fn_examples=fn_examples, notes=notes,
    )


class FieldAccuracy(BaseModel):
    """Pooled field number across every published triage (what BANK-READINESS cites)."""

    metric_scope: str = "REVIEWED_FILE_ALGORITHM_UNITS_NOT_ESTATE_COMPLETENESS"
    false_positive_rate: Optional[float] = None  # FP/(FP+TN): no TN denominator in legacy workbooks
    false_negative_rate: Optional[float] = None
    precision_denominator: int = 0
    recall_denominator: int = 0
    measurement_basis: str = "LEGACY_SUBMITTED_TRIAGE_NOT_APPROVED_FROZEN_SAMPLE"
    approved_customer_sample: bool = False
    global_accuracy_claim: bool = False
    triages: int = 0
    repos: int = 0
    reviewers: int = 0
    files_scanned: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    by_language: list[LanguageScore] = Field(default_factory=list)
    worst_languages: list[str] = Field(default_factory=list, description="languages with F1 < 0.95 and ≥ 10 reviewed families")
    corpus_f1: Optional[float] = Field(None, description="the corpus benchmark's F1 for comparison, when supplied")
    gap: Optional[float] = Field(None, description="corpus_f1 − field f1 (positive = the corpus is flattering)")
    status: str = Field("NO_FIELD_DATA", description="NO_FIELD_DATA | NO_REVIEWED_UNITS | MEASURED")


def aggregate(results: list[TriageResult], *, corpus_f1: float | None = None) -> FieldAccuracy:
    if not results:
        return FieldAccuracy(corpus_f1=corpus_f1)
    per_lang: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for t in results:
        for ls in t.by_language:
            per_lang[ls.language][0] += ls.tp
            per_lang[ls.language][1] += ls.fp
            per_lang[ls.language][2] += ls.fn
    tp = sum(t.tp for t in results)
    fp = sum(t.fp for t in results)
    fn = sum(t.fn for t in results)
    p, r, f1 = _prf(tp, fp, fn)
    langs, worst = [], []
    for lang, (ltp, lfp, lfn) in sorted(per_lang.items()):
        lp, lr, lf = _prf(ltp, lfp, lfn)
        langs.append(LanguageScore(language=lang, tp=ltp, fp=lfp, fn=lfn, precision=lp, recall=lr, f1=lf))
        if lf is not None and lf < 0.95 and ltp + lfp + lfn >= 10:
            worst.append(lang)
    return FieldAccuracy(
        triages=len(results), repos=len({t.repo for t in results}), reviewers=len({t.reviewer for t in results if t.reviewer}),
        files_scanned=sum(t.files_scanned for t in results), tp=tp, fp=fp, fn=fn, precision=p, recall=r, f1=f1,
        by_language=langs, worst_languages=worst, corpus_f1=corpus_f1,
        gap=round(corpus_f1 - f1, 4) if corpus_f1 is not None and f1 is not None else None,
        false_negative_rate=round(fn / (tp + fn), 4) if tp + fn else None,
        precision_denominator=tp + fp, recall_denominator=tp + fn,
        status="MEASURED" if tp + fp + fn else "NO_REVIEWED_UNITS",
    )
