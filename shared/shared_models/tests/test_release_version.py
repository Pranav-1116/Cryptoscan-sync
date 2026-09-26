"""Release version-consistency gate — the release rules are tested, not prose.

Guarantees:
1. A release version is exact semver and agrees with the API's API_VERSION.
2. A release exists in CHANGELOG with a real date before it may be tagged.
3. The v<version> tag exists and sits on HEAD (warn) — untaggable trees are
   caught by the gate, not by an operator mid-deploy.
4. Ordered migrations (NNNN_*) run 0001..max with no gaps.
"""
from __future__ import annotations

from shared_models.release_version import (
    ERROR,
    WARN,
    Finding,
    changelog_release_date,
    is_semver,
    migration_gaps,
    validate_release,
)

CHANGELOG = """# Changelog

## [Unreleased]
- work in progress

## [1.0.0] — 2026-09-10

### Production release
- everything

## [0cb159e] — 2026-09-07

### Baseline
- initial
"""


def _validate(**overrides):
    kwargs = {
        "version_text": "1.0.0",
        "api_version": "1.0.0",
        "changelog_text": CHANGELOG,
        "tags": ["v1.0.0"],
        "head_tagged": True,
    }
    kwargs.update(overrides)
    return validate_release(**kwargs)


def test_semver_shape():
    assert is_semver("1.0.0")
    assert is_semver(" 10.20.30 \n")
    assert not is_semver("89497be")  # interim hash-style version
    assert not is_semver("1.0")
    assert not is_semver("v1.0.0")  # the v lives on the tag, not in VERSION
    assert not is_semver("")


def test_happy_release_has_no_findings():
    assert _validate() == []


def test_version_must_agree_with_api():
    findings = _validate(api_version="0.9.0")
    assert [f.check for f in findings] == ["version-consistency"]
    assert findings[0].blocking
    assert "0.9.0" in findings[0].message


def test_non_semver_version_short_circuits_with_single_error():
    findings = _validate(version_text="89497be")
    assert [f.check for f in findings] == ["version-format"]
    # the other checks would be noise against a malformed version
    assert all(f.check == "version-format" for f in findings)


def test_changelog_section_required_with_date():
    findings = _validate(changelog_text="# Changelog\n\n## [Unreleased]\n- nothing\n")
    assert [f.check for f in findings] == ["changelog-section"]

    # a section without a date does not count
    findings = _validate(changelog_text="## [1.0.0]\n- undated\n")
    assert [f.check for f in findings] == ["changelog-section"]

    # plain hyphen separator is accepted alongside the em dash
    dated = CHANGELOG.replace("## [1.0.0] — 2026-09-10", "## [1.0.0] - 2026-09-10")
    assert changelog_release_date(dated, "1.0.0") == "2026-09-10"


def test_changelog_date_of_the_requested_version_only():
    assert changelog_release_date(CHANGELOG, "1.0.0") == "2026-09-10"
    assert changelog_release_date(CHANGELOG, "0cb159e") == "2026-09-07"
    assert changelog_release_date(CHANGELOG, "9.9.9") is None


def test_missing_tag_blocks_unless_dry_run():
    findings = _validate(tags=[])
    assert [f.check for f in findings] == ["git-tag"]
    assert findings[0].blocking

    findings = _validate(tags=[], allow_untagged=True)
    assert [f.severity for f in findings] == [WARN]


def test_tag_off_head_is_a_warning_not_a_blocker():
    findings = _validate(head_tagged=False)
    assert [f.check for f in findings] == ["git-tag-head"]
    assert not findings[0].blocking


def test_multiple_errors_accumulate():
    findings = _validate(api_version="0.1.0", changelog_text="", tags=[])
    assert sorted(f.check for f in findings) == ["changelog-section", "git-tag", "version-consistency"]


def test_finding_blocking_property():
    assert Finding("a", ERROR, "x").blocking
    assert not Finding("a", WARN, "x").blocking


def test_migration_gaps():
    assert migration_gaps(["0001_a.py", "0002_b.py", "0003_c.py"]) == []
    assert migration_gaps(["0001_a.py", "0004_d.py"]) == [2, 3]
    assert migration_gaps(["0001_a.py"]) == []
    # unnumbered helpers are ignored, not treated as gaps
    assert migration_gaps(["0001_a.py", "__init__.py", "helpers.py"]) == []
    assert migration_gaps([]) == []
