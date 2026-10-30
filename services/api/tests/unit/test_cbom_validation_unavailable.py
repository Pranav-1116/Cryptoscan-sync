"""A missing URI checker must neither block the import nor pass silently.

The banking-sandbox run on a fresh venv surfaced this the hard way: every CBOM
import returned 500 with a bare `ModuleNotFoundError`, the CBOM layer came out
empty, and an operator could easily have read that as "the estate has no
cryptography".

Then the first fix — refuse the import with a clear 503 — was still wrong in the
other direction: one absent *format* checker blocked 21 sound documents from
being stored, and the estate looked crypto-free until the operator ran a pip
install. A document that cannot be judged *fully* is still worth judging as far
as the checks present allow, provided the substitution is stated in the answer.

These tests pin the three answers apart:

* pinned package present -> the upstream RFC 3986 rule judges URI fields;
* package absent         -> the local shape rule judges them, and the response
                            names the substitution in ``validation.warnings``;
* a genuinely bad doc    -> 422, as before.
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
    "metadata": {
        "component": {"type": "application", "name": "bank-app", "bom-ref": "app-1"},
        "tools": [{"name": "bank-sandbox", "version": "1.0"}],
    },
    "components": [
        {
            "type": "cryptographic-asset",
            "bom-ref": "alg-1",
            "name": "AES-256-GCM",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "ae"}},
        }
    ],
}

# The only URI-typed field a CycloneDX 1.6 CBOM actually exercises is a
# proprietary signature algorithm (JSF: enum of JWA names, else a URI). The rest
# of the document uses `iri-reference`, which jsonschema does not format-check.
BAD_URI = {**VALID, "signature": {"algorithm": "our-own-alg", "value": "not-base64url"}}


def _without_upstream(monkeypatch):
    """Behave as a venv that lacks rfc3986-validator."""
    monkeypatch.setattr(cyclonedx16, "_upstream_uri_rule", None)


def test_a_valid_document_is_judged_valid():
    result = cyclonedx16.validate_cyclonedx16(VALID)
    assert result["ok"] is True, result["errors"]
    assert result["validation_basis"] == "CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES"
    assert result["format_checks"]["uri"] in {
        "RFC3986_VALIDATOR_PACKAGE",
        "LOCAL_RFC3986_SHAPE_CHECK",
    }


def test_the_uri_rule_names_itself():
    rule, name = cyclonedx16.uri_rule()
    assert callable(rule)
    assert name == (
        "RFC3986_VALIDATOR_PACKAGE" if cyclonedx16._upstream_uri_rule else "LOCAL_RFC3986_SHAPE_CHECK"
    )


def test_a_missing_package_is_a_stated_substitution_not_a_refusal(monkeypatch):
    _without_upstream(monkeypatch)

    warning = cyclonedx16.uri_check_warning()
    assert warning and "rfc3986-validator" in warning
    assert "not installed" in warning

    result = cyclonedx16.validate_cyclonedx16(VALID)
    assert result["ok"] is True, result["errors"]
    assert result["format_checks"]["uri"] == "LOCAL_RFC3986_SHAPE_CHECK"
    assert any("rfc3986-validator" in item for item in result["warnings"])


def test_the_pinned_package_silences_the_warning(monkeypatch):
    """With the pinned dependency installed, nothing is substituted."""
    pytest.importorskip("rfc3986_validator")
    upstream = cyclonedx16._upstream_uri_rule
    if upstream is None:  # pragma: no cover - environment without the package
        pytest.skip("rfc3986-validator is not importable in this environment")
    assert cyclonedx16.uri_check_warning() is None
    result = cyclonedx16.validate_cyclonedx16(VALID)
    assert result["warnings"] == []
    assert result["format_checks"]["uri"] == "RFC3986_VALIDATOR_PACKAGE"


def test_the_local_rule_still_rejects_a_field_that_is_not_a_uri(monkeypatch):
    """The fallback is weaker, not absent: a bare string is still an error."""
    _without_upstream(monkeypatch)
    result = cyclonedx16.validate_cyclonedx16(BAD_URI)
    assert result["ok"] is False
    assert any("oneOf" in error for error in result["errors"]), result["errors"]


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
        assert reloaded._upstream_uri_rule is None
        assert reloaded.uri_rule()[1] == "LOCAL_RFC3986_SHAPE_CHECK"
        assert reloaded.validate_cyclonedx16(VALID)["ok"] is True
    finally:
        monkeypatch.undo()
        importlib.reload(cyclonedx16)


def test_a_bad_document_is_still_rejected_with_422(monkeypatch):
    """The weaker URI rule did not turn the import into an accept-anything path."""
    from fastapi import HTTPException

    from api.routers import cbom as cbom_router

    _without_upstream(monkeypatch)
    with pytest.raises(HTTPException) as raised:
        cbom_router.ingest_document(bom=BAD_URI, db=None, actor="tester")
    assert raised.value.status_code == 422
    assert "signature" in str(raised.value.detail).lower()
