"""Named CycloneDX CBOM validator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cbom.validator import validate_cbom

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "cyclonedx-1.5.schema.json"


def _schema_errors(bom: dict[str, Any]) -> list[str]:
    if not SCHEMA_PATH.is_file():
        return []
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    errors: list[str] = []
    for field in schema.get("required") or []:
        if field not in bom:
            errors.append(f"missing {field}")
    fmt = ((schema.get("properties") or {}).get("bomFormat") or {}).get("const")
    if fmt and bom.get("bomFormat") != fmt:
        errors.append("bomFormat must be CycloneDX")
    allowed = ((schema.get("properties") or {}).get("specVersion") or {}).get("enum")
    if allowed and bom.get("specVersion") not in allowed:
        errors.append("specVersion must be a CycloneDX 1.4+ release")
    if "components" in (schema.get("required") or []) and not isinstance(bom.get("components"), list):
        errors.append("components must be a list")
    return errors


class CbomValidator:
    def validate(self, bom: dict[str, Any]) -> dict[str, Any]:
        result = validate_cbom(bom)
        extra = _schema_errors(bom)
        errors = list(result.get("errors") or []) + [item for item in extra if item not in (result.get("errors") or [])]
        return {"ok": not errors, "errors": errors}


def validate(bom: dict[str, Any]) -> dict[str, Any]:
    return CbomValidator().validate(bom)
