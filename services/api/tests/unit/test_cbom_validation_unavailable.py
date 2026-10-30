"""A missing validation dependency must say so — not 500, not "invalid".

The banking-sandbox run on a fresh venv surfaced this the hard way: every CBOM
import returned 500 with a bare `ModuleNotFoundError`, the CBOM layer came out
empty, and an operator could easily have read that as "the estate has no
cryptography". These tests pin the three answers apart:

* dependencies present  -> the document is judged;
* dependencies missing  -> ``ValidationUnavailable`` (503 upstairs), nothing stored;
* a genuinely bad doc   -> 422, as before.
"""
from __future__ import annotations

import builtins
import importlib

import pytest

from cbom import cyclonedx16


VALID = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "bank-app", "bom-ref": "app-1"}},
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "alg-1",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "ae"}},
        }
    ],
}


def test_a_valid_document_is_judged_valid():
    if cyclonedx16.unavailable_reason():
        pytest.skip("this environment lacks the pinned validation dependencies")
    result = cyclonedx16.validate_cyclonedx16(VALID)
    assert result["ok"] is True, result["errors"]
    assert result["validation_basis"] == "CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES"


def test_a_missing_checker_raises_instead_of_calling_the_document_invalid(monkeypatch):
    monkeypatch.setattr(cyclonedx16, "validate_rfc3986", None)
    reason = cyclonedx16.unavailable_reason()
    assert reason and "rfc3986-validator" in reason
    assert "NOT_EVALUATED" in reason

    with pytest.raises(cyclonedx16.ValidationUnavailable) as raised:
        cyclonedx16.validate_cyclonedx16(VALID)
    assert "rfc3986-validator" in str(raised.value)
    # the exception is not the "invalid document" path
    assert not isinstance(raised.value, ValueError)


def test_the_module_still_imports_without_the_checker(monkeypatch):
    """An absent optional checker must not take the whole importer down with it."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "rfc3986_validator":
            raise ModuleNotFoundError("No module named 'rfc3986_validator'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    reloaded = importlib.reload(cyclonedx16)
    try:
        assert reloaded.validate_rfc3986 is None
        assert "rfc3986-validator" in (reloaded.unavailable_reason() or "")
    finally:
        monkeypatch.undo()
        importlib.reload(cyclonedx16)


def test_ingest_returns_503_with_a_fix_when_validation_cannot_run(monkeypatch):
    """The API answers with a state and a fix, not a 500 traceback."""
    from fastapi import HTTPException

    from api.routers import cbom

    monkeypatch.setattr(cyclonedx16, "validate_rfc3986", None)
    monkeypatch.setattr("cbom.inventory.validate_document",
                        lambda bom: cyclonedx16.validate_cyclonedx16(bom))

    with pytest.raises(HTTPException) as raised:
        cbom.ingest_document(bom=VALID, db=None, actor="tester")
    assert raised.value.status_code == 503
    detail = raised.value.detail
    assert detail["error"] == "validator_unavailable"
    assert detail["documents_judged"] is False
    assert detail["documents_stored"] is False
    assert "requirements.txt" in detail["fix"]
