"""The VBOM dependency surface over HTTP: ask a question, export a document.

Every answer the vendor graph can give is available here, and nothing else is: the routes
are generated from :mod:`cbom.vbom_surface`'s catalogue rather than hand-written per
question, so a question that is not in the catalogue is a 404 and a parameter that is not in
a reader's signature is a 422.

The payload is supplied by the caller. That is deliberate for this increment: the graph is a
statement about *vendor documents and the estate*, and reading the estate out of the database
is the cross-links route's job (``GET /cbom/cross-links``), which keeps this surface a pure
function of what it was given. Nothing here writes, caches or stores a payload.

A refusal is a 200 with ``ok: false`` and a code, not a 500. The graph answered; the answer
was "no, and here is which of five checks failed".
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path

from cbom import vbom_dependency as vd
from cbom import vbom_surface as surface

from api.dependencies import get_current_user

router = APIRouter(prefix="/cbom/vbom", tags=["cbom-vbom"])

#: the largest payload this surface will parse. A vendor estate is documents and rows, not
#: binaries; anything past this is a mistake or an attack, and both deserve one answer.
MAX_ROWS = 5000


def _payload(body: dict[str, Any]) -> dict[str, Any]:
    payload = body.get("payload") if isinstance(body, dict) else None
    if not isinstance(payload, dict) or not payload:
        raise HTTPException(status_code=422,
                            detail={"code": "PAYLOAD_REQUIRED",
                                    "reason": "a vendor payload is required; this surface "
                                              "does not read the estate for you"})
    declared = payload.get("schema")
    if declared not in (None, vd.INPUT_SCHEMA):
        raise HTTPException(status_code=422,
                            detail={"code": "UNKNOWN_PAYLOAD_SCHEMA",
                                    "reason": f"payload declares {declared}; this build reads "
                                              f"{vd.INPUT_SCHEMA}"})
    for section, rows in payload.items():
        if isinstance(rows, list) and len(rows) > MAX_ROWS:
            raise HTTPException(status_code=413,
                                detail={"code": "PAYLOAD_TOO_LARGE",
                                        "reason": f"{section} carries {len(rows)} row(s); "
                                                  f"the limit is {MAX_ROWS}"})
    return payload


def _questions(names: Any) -> list[str] | None:
    if names is None:
        return None
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise HTTPException(status_code=422,
                            detail={"code": "BAD_QUESTION_LIST",
                                    "reason": "questions must be a list of catalogue names"})
    unknown = [name for name in names if name not in surface.QUESTIONS]
    if unknown:
        raise HTTPException(status_code=404,
                            detail={"code": "UNKNOWN_QUESTION",
                                    "reason": f"not in the catalogue: {', '.join(unknown)}"})
    return names


@router.get("/questions")
def list_questions(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """The catalogue: every question this surface answers, and what it needs."""
    return surface.catalogue()


@router.post("/assess")
def assess(
    body: dict[str, Any] = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """A vendor payload (and optional live collector payloads) → graph, document, answers."""
    payload = _payload(body)
    result = surface.assess(
        payload,
        live=body.get("live") or None,
        as_of=body.get("as_of") or payload.get("as_of"),
        questions=_questions(body.get("questions")),
        given=body.get("given") or None,
        estate_id=body.get("estate_id") or "vbom:assessment",
    )
    return {key: value for key, value in result.items() if key != "graph"} | {
        "graph": {key: value for key, value in result["graph"].items() if key != "bom"},
    }


@router.post("/answer/{question}")
def answer(
    question: str = Path(...),
    body: dict[str, Any] = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """One question, one envelope. ``ok: false`` is an answer, not an error."""
    if question not in surface.QUESTIONS:
        raise HTTPException(status_code=404,
                            detail={"code": "UNKNOWN_QUESTION",
                                    "reason": f"{question} is not in the catalogue; "
                                              f"GET /cbom/vbom/questions lists the "
                                              f"{len(surface.QUESTIONS)} it serves"})
    payload = _payload(body)
    built = surface.assess(payload, live=body.get("live") or None,
                           as_of=body.get("as_of") or payload.get("as_of"),
                           questions=[], estate_id=body.get("estate_id") or "vbom:assessment")
    params = dict(body.get("params") or {})
    result = surface.ask(built["document"], question, payload=payload, **params)
    if not result["ok"] and result["code"] in ("MISSING_PARAMETER", "UNKNOWN_PARAMETER"):
        raise HTTPException(status_code=422,
                            detail={"code": result["code"], "reason": result["reason"],
                                    "required": list(surface._required(question))})
    return result


@router.post("/summary")
def summary(
    body: dict[str, Any] = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Levels, applicability states and refusals — the first three numbers a reviewer wants."""
    payload = _payload(body)
    built = surface.assess(payload, live=body.get("live") or None,
                           as_of=body.get("as_of") or payload.get("as_of"), questions=[])
    return surface.summary(built["document"], vendor=body.get("vendor"))


@router.post("/export/cyclonedx")
def export_cyclonedx(
    body: dict[str, Any] = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """The vendor graph as a CycloneDX 1.6 document, validated before it is returned."""
    payload = _payload(body)
    built = surface.assess(payload, live=body.get("live") or None,
                           as_of=body.get("as_of") or payload.get("as_of"), questions=[])
    result = surface.to_cyclonedx(
        built["document"], as_of=body.get("as_of") or payload.get("as_of"),
        applicability=vd.declaration_applicability(
            built["document"], as_of=body.get("as_of") or payload.get("as_of")))
    if not result["validation"]["ok"]:
        # A document that fails its own schema is not returned as if it were an export.
        raise HTTPException(status_code=500,
                            detail={"code": "EXPORT_INVALID",
                                    "reason": result["statement"],
                                    "errors": result["validation"]["errors"][:10]})
    return result
