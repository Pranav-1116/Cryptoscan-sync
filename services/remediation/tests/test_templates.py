"""W51-52: remediation template library — language-specific fixes, guides, fix-branch payloads."""

from remediation import templates
from remediation.engine import HARDCODED_KEY_RULE, suggest_remediations


def test_catalog_covers_every_engine_rule():
    """Every rule the engine can emit must have a template (guidance never 404s)."""
    report = suggest_remediations([
        {"algorithm": "MD5"}, {"algorithm": "SHA-1", "purpose": "signing"},
        {"algorithm": "RC4"}, {"algorithm": "DES"},
        {"algorithm": "3DES"}, {"algorithm": "RSA", "key_size": 1024},
        {"algorithm": "ECB"}, {"algorithm": "AES", "mode": "ECB"},
        {"algorithm": "AES", "key_size": 128}, {"algorithm": "SHA-1"},
        {"algorithm": "RSA", "purpose": "signing", "key_size": 2048},
        {"algorithm": "Blowfish"}, {"algorithm": "some-unknown-alg"},
        {"algorithm": "AES", "mode": "GCM", "key_size": 256, "purpose": "encryption"},
    ])
    covered = {s["rule"] for s in report["suggestions"]}
    covered.discard("manual-review")  # no template by design
    catalog = {t["rule"] for t in templates.template_catalog()}
    missing = covered - catalog
    assert not missing, f"engine rules without templates: {missing}"


def test_hardcoded_key_gets_p0_rule_and_template():
    report = suggest_remediations([
        {"algorithm": "AES", "mode": "GCM", "key_size": 256, "purpose": "encryption",
         "is_hardcoded_key": True},
    ])
    assert report["suggestions"][0]["rule"] == HARDCODED_KEY_RULE["rule"]
    assert report["suggestions"][0]["priority"] == "P0"
    rendered = templates.render(HARDCODED_KEY_RULE["rule"], "java")
    assert rendered and "kmsClient" in rendered["after"]


def test_render_all_languages_and_fallback():
    for tid in templates.template_ids():
        for lang in templates.languages():
            rendered = templates.render(tid, lang)
            assert rendered is not None
            assert rendered["language"] == lang
            assert rendered["before"] and rendered["after"]
            assert rendered["testing"] and rendered["references"]
    # unavailable language falls back to the python snippet, flagged honestly
    rendered = templates.render("replace-md5", "rust")
    assert rendered["requested_language_unavailable"] is True
    assert rendered["before"] == templates.render("replace-md5", "python")["before"]
    assert templates.render("no-such-rule", "python") is None


def test_references_are_real_standards_not_placeholders():
    allowed_sources = {"nist.gov", "rfc-editor.org", "owasp.org", "cisa.gov", "iarc.net"}
    seen = 0
    for tid in templates.template_ids():
        for ref in templates.render(tid, "python")["references"]:
            assert ref["url"].startswith("https://"), ref
            assert ref["label"], ref  # human-readable citation, not a bare URL
            domain = ref["url"].split("/")[2]
            assert any(domain.endswith(src) for src in allowed_sources), ref
            seen += 1
    assert seen >= 15  # every template carries at least one real reference


def test_guides_are_multi_step():
    for name in templates._GUIDES:
        guide = templates.guide(name)
        steps = guide["steps"]
        assert len(steps) >= 4, name  # "multi-step" means at least 4 steps
        for i, step in enumerate(steps, start=1):
            assert step["order"] == i
            assert step["title"] and step["detail"]
            assert step["verification"]  # every step says how to verify it
        assert len(guide["references"]) >= 2, name
    assert templates.guide("no-such-guide") is None


def test_fix_branch_payload_is_advisory():
    suggestion = {
        "rule": "replace-md5", "algorithm": "MD5", "file_path": "src/hash.py",
        "line_number": 42, "replace_with": "SHA-256",
        "category": "CLASSICALLY_BROKEN", "priority": "P0",
    }
    payload = templates.fix_branch_payload(suggestion, language="go")
    assert payload["branch"].startswith("fix/cryptoscan-replace-md5-")
    assert payload["commands"][0].startswith("git checkout -b")
    assert "never pushes" in payload["pr_body"].lower() or "advisory" in payload["pr_body"].lower()
    assert payload["changes"][0]["after"]  # go snippet rendered (before/after pair)
    assert payload["pr_title"] and payload["commit_message"]
    assert any("md5" not in c or "sha256" in c for c in [payload["changes"][0]["after"]])
    # unknown rule still yields a reviewable payload, no crash
    manual = templates.fix_branch_payload({**suggestion, "rule": "manual-review"}, "python")
    assert manual["branch"]
