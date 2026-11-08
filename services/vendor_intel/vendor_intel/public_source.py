"""Public-source disclosure baseline engine
(docs/bank-environment/emirates-nbd/GAP-ANALYSIS.md).

The OUTSIDE-IN stage of a CBOM engagement: what public sources
disclose about a subject organisation's technology and vendors, what
can only be INFERRED from the type of technology, what remains
UNVERIFIED, and what data only the bank can supply.

Discipline (standing acceptance rules):
- a disclosure is evidence of a PUBLICATION, never of current state:
  `current_state_confirmed` is ALWAYS False for public-source rows;
  dated disclosures are "was deployed", never "is deployed" (§ the
  baseline's currency rule);
- confidence follows the baseline's key: high = bank/vendor published,
  medium = trade press, low = aggregator / job advert / undated — a
  low-confidence row is a LEAD TO VERIFY, never a fact;
- crypto siting is INFERENCE (`evidence_class="inferred"`) — it tells
  a CBOM team where to look and what to ask, and is NEVER a claim
  about the subject;
- an unverified claim is recorded, never asserted;
- a disclosure gap is NEVER an absence claim ("Do not assume any") —
  missing disclosure ≠ the technology is absent;
- external acts (sending the request list, receiving data) are NEVER
  marked done from inside the repo: request statuses advance only
  against IMPORTED evidence of the act (actor, date, artifact).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

SCHEMA = "zelnx.public-source-baseline/1"
CONFIDENCE_LEVELS = ("high", "high_medium", "medium", "low_medium",
                     "low")
REQUEST_STATUSES = ("listed", "requested", "partially_received",
                    "received")

_LOW_CONFIDENCE_NOTE = ("low-confidence disclosure — a LEAD TO "
                        "VERIFY, never a fact")
_INFERENCE_NOTE = ("INFERENCE from the type of technology disclosed — "
                   "never a claim about the subject organisation; it "
                   "tells a CBOM team where to look and what to ask")
_GAP_NOTE = ("a disclosure gap is NEVER an absence claim — missing "
             "disclosure does not mean the technology is absent "
             "('Do not assume any')")


@dataclass
class DisclosureRecord:
    """One publicly disclosed technology/vendor row."""
    item_id: str
    name: str
    category: str
    role: str
    disclosed: str
    refs: List[str]
    confidence: str
    confidence_basis: str
    as_of: str = "undated"
    currency_note: str = ""
    # decisive honesty field — public sources NEVER confirm current
    # state, so this is structurally always False (test-enforced)
    current_state_confirmed: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "category": self.category,
            "role": self.role,
            "disclosed": self.disclosed,
            "refs": list(self.refs),
            "confidence": self.confidence,
            "confidence_basis": self.confidence_basis,
            "as_of": self.as_of,
            "currency_note": self.currency_note,
            "current_state_confirmed": self.current_state_confirmed,
            "note": ("a public disclosure is evidence of a "
                     "publication — 'was deployed', never 'is "
                     "deployed'; confirm current state with the "
                     "subject" + ("; " + _LOW_CONFIDENCE_NOTE
                                  if self.confidence in ("low",
                                                         "low_medium")
                                  else "")),
        }


@dataclass
class SitingHypothesis:
    """Where cryptographic assets TYPICALLY sit for a disclosed
    technology area — inference only."""
    area: str
    crypto_assets_typically_present: List[str]
    basis_for_inference: str
    question_to_confirm: str
    evidence_class: str = "inferred"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "area": self.area,
            "crypto_assets_typically_present":
                list(self.crypto_assets_typically_present),
            "basis_for_inference": self.basis_for_inference,
            "question_to_confirm": self.question_to_confirm,
            "evidence_class": self.evidence_class,
            "note": _INFERENCE_NOTE,
        }


@dataclass
class UnverifiedClaim:
    claim_id: str
    statement: str
    source: str
    source_quality: str
    status: str = "unverified"
    treatment: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "source": self.source,
            "source_quality": self.source_quality,
            "status": self.status,
            "treatment": self.treatment,
            "note": ("an unverified claim is RECORDED, never asserted "
                     "— it is a question to ask, not a fact"),
        }


@dataclass
class GapRecord:
    gap_id: str
    statement: str
    note: str = _GAP_NOTE

    def as_dict(self) -> Dict[str, Any]:
        return {"gap_id": self.gap_id, "statement": self.statement,
                "note": self.note}


@dataclass
class DataRequest:
    """An item only the subject organisation can supply for an
    AUTHORISED CBOM engagement."""
    request_id: str
    category: str
    item: str
    status: str = "listed"
    # external acts are recorded ONLY as imported evidence — the repo
    # never performs or claims the act itself
    status_evidence: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "category": self.category,
            "item": self.item,
            "status": self.status,
            "status_evidence": list(self.status_evidence),
            "note": ("statuses advance only against imported evidence "
                     "of the external act — the platform never marks "
                     "an external act done from inside the repo"),
        }


@dataclass
class PublicSourceBaseline:
    schema: str
    subject: str
    prepared_for: str
    prepared_on: str
    method: str
    status: str
    confidence_key: Dict[str, str]
    currency_rule: str
    organisation_profile: List[Dict[str, Any]]
    disclosures: List[DisclosureRecord]
    crypto_siting: List[SitingHypothesis]
    unverified_claims: List[UnverifiedClaim]
    gaps: List[GapRecord]
    data_requests: List[DataRequest]
    references: Dict[str, str]
    load_errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "subject": self.subject,
            "prepared_for": self.prepared_for,
            "prepared_on": self.prepared_on,
            "method": self.method,
            "status": self.status,
            "confidence_key": dict(self.confidence_key),
            "currency_rule": self.currency_rule,
            "organisation_profile": list(self.organisation_profile),
            "disclosures": [d.as_dict() for d in self.disclosures],
            "crypto_siting": [s.as_dict() for s in self.crypto_siting],
            "unverified_claims": [c.as_dict()
                                  for c in self.unverified_claims],
            "gaps": [g.as_dict() for g in self.gaps],
            "data_requests": [r.as_dict() for r in self.data_requests],
            "references": dict(self.references),
            "load_errors": list(self.load_errors),
            "note": ("outside-in public-source baseline — it is NOT a "
                     "CBOM: public sources do not disclose "
                     "algorithms, keys, certificates or HSMs"),
        }

    # ── derived views ─────────────────────────────────────────────

    def vendor_register(self) -> List[Dict[str, Any]]:
        """Consolidated one-line-per-third-party register (the
        baseline's §8), derived from disclosures + organisation rows.
        'first_seen' is the earliest public date found — never a
        contract date."""
        rows: List[Dict[str, Any]] = []
        for d in self.disclosures:
            rows.append({
                "name": d.name,
                "category": d.category,
                "relationship": d.role,
                "first_seen": d.as_of,
                "confidence": d.confidence,
                "refs": list(d.refs),
                "note": "'first seen' is the earliest public date "
                        "found — never a contract date",
            })
        return rows

    def cbom_request_list(self) -> List[Dict[str, Any]]:
        """The §11 data-request list — the input checklist for an
        AUTHORISED engagement. Discovery tooling runs only inside an
        agreed scope."""
        return [r.as_dict() for r in self.data_requests]

    def claims(self) -> List[Dict[str, Any]]:
        """Claims this baseline asserts about the subject's crypto.
        Always EMPTY: public sources never establish cryptographic
        facts. The method exists so callers can CHECK the emptiness."""
        return []


def load_baseline(data: Mapping[str, Any]) -> PublicSourceBaseline:
    """Validate and assemble a baseline. Malformed rows are recorded
    in load_errors and skipped — never fabricated, never guessed."""
    errors: List[str] = []
    if data.get("schema") != SCHEMA:
        raise ValueError(f"baseline schema must be {SCHEMA!r}")

    disclosures: List[DisclosureRecord] = []
    seen_ids = set()
    for i, row in enumerate(data.get("disclosures") or []):
        where = f"disclosures[{i}]"
        item_id = str(row.get("item_id") or "").strip()
        name = str(row.get("name") or "").strip()
        if not item_id or not name:
            errors.append(f"{where}: missing item_id or name — row "
                          "skipped, never fabricated")
            continue
        if item_id in seen_ids:
            errors.append(f"{where}: duplicate item_id {item_id!r} — "
                          "row skipped, never merged silently")
            continue
        confidence = str(row.get("confidence") or "").strip()
        if confidence not in CONFIDENCE_LEVELS:
            errors.append(f"{where}: unknown confidence "
                          f"{confidence!r} — row skipped, never "
                          "guessed")
            continue
        refs = [str(r) for r in (row.get("refs") or []) if str(r)]
        if not refs:
            errors.append(f"{where}: no source reference — row "
                          "skipped; an unsourced row is not evidence")
            continue
        as_of = str(row.get("as_of") or "undated")
        currency_note = str(row.get("currency_note") or "")
        if as_of not in ("undated", "") and "date not shown" not in \
                as_of and "undated" not in as_of:
            currency_note = currency_note or ("treat as 'was "
                                              "deployed'; confirm "
                                              "current state with the "
                                              "bank")
        seen_ids.add(item_id)
        disclosures.append(DisclosureRecord(
            item_id=item_id, name=name,
            category=str(row.get("category") or "unknown"),
            role=str(row.get("role") or ""),
            disclosed=str(row.get("disclosed") or ""),
            refs=refs, confidence=confidence,
            confidence_basis=str(row.get("confidence_basis")
                                 or "unknown"),
            as_of=as_of, currency_note=currency_note,
            current_state_confirmed=False,
        ))

    siting: List[SitingHypothesis] = []
    for i, row in enumerate(data.get("crypto_siting") or []):
        where = f"crypto_siting[{i}]"
        area = str(row.get("area") or "").strip()
        assets = [str(a) for a in
                  (row.get("crypto_assets_typically_present") or [])
                  if str(a).strip()]
        if not area or not assets:
            errors.append(f"{where}: missing area or assets — row "
                          "skipped, never fabricated")
            continue
        siting.append(SitingHypothesis(
            area=area,
            crypto_assets_typically_present=assets,
            basis_for_inference=str(row.get("basis_for_inference")
                                    or ""),
            question_to_confirm=str(row.get("question_to_confirm")
                                    or ""),
            evidence_class="inferred",
        ))

    claims_list: List[UnverifiedClaim] = []
    for i, row in enumerate(data.get("unverified_claims") or []):
        claim_id = str(row.get("claim_id") or f"claim-{i}").strip()
        claims_list.append(UnverifiedClaim(
            claim_id=claim_id,
            statement=str(row.get("statement") or ""),
            source=str(row.get("source") or ""),
            source_quality=str(row.get("source_quality") or "unknown"),
            status="unverified",
            treatment=str(row.get("treatment") or
                          "a question to ask, not a fact"),
        ))

    gaps = [GapRecord(gap_id=str(row.get("gap_id") or f"gap-{i}"),
                      statement=str(row.get("statement") or ""))
            for i, row in enumerate(data.get("gaps") or [])
            if str(row.get("statement") or "").strip()]

    requests: List[DataRequest] = []
    for i, row in enumerate(data.get("data_requests") or []):
        request_id = str(row.get("request_id") or "").strip()
        category = str(row.get("category") or "").strip()
        if not request_id or not category:
            errors.append(f"data_requests[{i}]: missing id or "
                          "category — row skipped, never fabricated")
            continue
        requests.append(DataRequest(request_id=request_id,
                                    category=category,
                                    item=str(row.get("item") or "")))

    return PublicSourceBaseline(
        schema=SCHEMA,
        subject=str(data.get("subject") or "unknown"),
        prepared_for=str(data.get("prepared_for") or ""),
        prepared_on=str(data.get("prepared_on") or ""),
        method=str(data.get("method") or ""),
        status=str(data.get("status") or ""),
        confidence_key=dict(data.get("confidence_key") or {}),
        currency_rule=str(data.get("currency_rule") or ""),
        organisation_profile=list(data.get("organisation_profile")
                                  or []),
        disclosures=disclosures,
        crypto_siting=siting,
        unverified_claims=claims_list,
        gaps=gaps,
        data_requests=requests,
        references={str(k): str(v) for k, v in
                    (data.get("references") or {}).items()},
        load_errors=errors,
    )


def load_baseline_file(path: str | Path) -> PublicSourceBaseline:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_baseline(raw)


def advance_request(baseline: PublicSourceBaseline, request_id: str,
                    status: str, evidence: Mapping[str, Any]) -> Dict[
                        str, Any]:
    """Advance a data-request status ONLY against imported evidence of
    the external act.

    `evidence` must record {actor, date, artifact_ref} — who performed
    the external act, when, and a reference to the receipt. The
    platform NEVER marks an external act done from inside the repo:
    without imported evidence the advance is REFUSED with a reason.
    """
    if status not in REQUEST_STATUSES:
        raise ValueError(f"status must be one of {REQUEST_STATUSES}")
    for row in baseline.data_requests:
        if row.request_id != request_id:
            continue
        actor = str(evidence.get("actor") or "").strip()
        date = str(evidence.get("date") or "").strip()
        artifact = str(evidence.get("artifact_ref") or "").strip()
        if not (actor and date and artifact):
            return {
                "request_id": request_id,
                "advanced": False,
                "reason": ("refused — an external act is never marked "
                           "done from inside the repo; imported "
                           "evidence must record actor, date and "
                           "artifact_ref"),
            }
        row.status = status
        row.status_evidence.append({
            "actor": actor, "date": date,
            "artifact_ref": artifact, "status": status,
        })
        return {"request_id": request_id, "advanced": True,
                "status": status}
    return {"request_id": request_id, "advanced": False,
            "reason": "request_id not found — nothing was changed"}


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def match_observation(baseline: PublicSourceBaseline,
                      observations: Iterable[Mapping[str, Any]]
                      ) -> List[Dict[str, Any]]:
    """DISCOVERY: match observed estate technology against the
    disclosed product register.

    A match is a CANDIDATE — never confirmation. Matching is
    content-based on name/alias tokens; co-location and naming
    similarity are never proof that the product is in use (§ the
    provides/uses discipline)."""
    results: List[Dict[str, Any]] = []
    for obs in observations:
        text = " ".join(str(obs.get(k) or "") for k in
                        ("name", "product", "vendor", "banner",
                         "description")).lower()
        tokens = set(_TOKEN_RE.findall(text))
        candidates = []
        for d in baseline.disclosures:
            content = " ".join((d.name, d.category, d.role,
                                d.disclosed)).lower()
            content_tokens = set(_TOKEN_RE.findall(content))
            shared = tokens & content_tokens
            # meaningful overlap: at least one distinctive token
            # (length > 2) shared
            distinctive = {t for t in shared if len(t) > 2}
            if distinctive:
                candidates.append({
                    "item_id": d.item_id,
                    "name": d.name,
                    "match_basis": f"content tokens shared: "
                                   f"{sorted(distinctive)}",
                    "confidence": d.confidence,
                    "status": "candidate_match",
                    "note": ("a candidate match from observed "
                             "content — never confirmation; the "
                             "product being present is not proof of "
                             "how its cryptography is used"),
                })
        results.append({
            "observation": dict(obs),
            "candidates": candidates,
            "note": ("no candidate is not 'product absent' — "
                     "matching is name-token based and incomplete"
                     if not candidates else
                     "candidate matches only — require correlation "
                     "before any claim"),
        })
    return results
