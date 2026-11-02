"""Version ordering and constraint syntax, per ecosystem.

The cases here are the ones a naive comparator gets wrong: a release candidate
ordered after its release, a dev release ordered after a prerelease, an epoch
ignored, and a caret read as an exact pin. Each test names the ecosystem because
the same string can order differently in two of them.
"""

from __future__ import annotations

import pytest

from devsecops import version_ranges as vr


@pytest.mark.parametrize(("left", "right", "ecosystem", "expected"), [
    ("1.0.0-rc1", "1.0.0", "semver", -1),
    ("1.0.0", "1.0.0-rc1", "semver", 1),
    ("1.0.0-rc1", "1.0.0-beta.2", "semver", 1),
    ("1.0.0+build", "1.0.0", "semver", 0),
    ("1.10.0", "1.9.0", "semver", 1),
    ("1.0.0a1", "1.0.0", "pep440", -1),
    ("1.0.0.dev1", "1.0.0a1", "pep440", -1),
    ("1.0.0a1.dev1", "1.0.0a1", "pep440", -1),
    ("1.0.0.post1", "1.0.0", "pep440", 1),
    ("1!1.0", "2.0", "pep440", 1),
    ("1.0", "1.0.0", "pep440", 0),
    ("1.0.0", "1.0", "generic", 0),
    ("2.0.0", "10.0.0", "generic", -1),
])
def test_ordering(left: str, right: str, ecosystem: str, expected: int) -> None:
    assert vr.compare(left, right, ecosystem=ecosystem) == expected
    assert vr.compare(right, left, ecosystem=ecosystem) == -expected


@pytest.mark.parametrize(("manager", "family"), [
    ("npm", "semver"), ("cargo", "semver"), ("pip", "pep440"), ("poetry", "pep440"),
    ("maven", "maven"), ("gradle", "maven"), ("nuget", "generic"), ("gem", "generic"),
    ("debian", "generic"), ("unknown-manager", "generic"),
])
def test_ecosystem_families(manager: str, family: str) -> None:
    assert vr.family_for(manager) == family


def test_a_version_with_no_numbers_is_refused() -> None:
    with pytest.raises(vr.ConstraintError, match="no version numbers"):
        vr.compare("three", "1.0.0", ecosystem="generic")


def test_a_prerelease_is_refused_by_the_semver_comparator_as_a_number() -> None:
    with pytest.raises(vr.ConstraintError, match="not a semantic version"):
        vr.compare("not-a-version", "1.0.0", ecosystem="semver")


@pytest.mark.parametrize(("version", "constraint", "ecosystem", "expected"), [
    ("5.2.3", "^5.0.0", "semver", True),
    ("6.0.0", "^5.0.0", "semver", False),
    ("0.2.5", "^0.2.3", "semver", True),
    ("0.3.0", "^0.2.3", "semver", False),
    ("1.2.9", "~1.2.3", "semver", True),
    ("1.3.0", "~1.2.3", "semver", False),
    ("1.2.7", "1.2.x", "semver", True),
    ("1.3.0", "1.2.x", "semver", False),
    ("1.5.0", ">=1.0.0 <2.0.0", "semver", True),
    ("2.0.0", ">=1.0.0 <2.0.0", "semver", False),
    ("3.0.11", ">=3.0.0, <3.0.13", "semver", True),
    ("3.0.13", ">=3.0.0, <3.0.13", "semver", False),
    ("1.4.9", "~=1.4.5", "pep440", True),
    ("1.5.0", "~=1.4.5", "pep440", False),
    ("1.5.0", "[1.0,2.0)", "maven", True),
    ("2.0.0", "[1.0,2.0)", "maven", False),
    ("1.9.0", "1.0.0 || 1.9.0", "semver", True),
    ("1.8.0", "1.0.0 || 1.9.0", "semver", False),
    ("2.32.0", "*", "generic", True),
    ("2.32.0", "", "generic", True),
    ("1.2.3", "!=1.2.3", "semver", False),
    ("3.0.13", "3.0.13", "semver", True),
    ("3.0.12", "3.0.13", "semver", False),
    ("2.0.0-rc1", ">=2.0.0", "semver", False),
])
def test_constraints(version: str, constraint: str, ecosystem: str,
                     expected: bool) -> None:
    assert vr.satisfies(version, constraint, ecosystem=ecosystem) is expected


def test_constraint_kinds_are_named() -> None:
    assert vr.parse_constraint("3.0.11")["kind"] == "EXACT"
    assert vr.parse_constraint("^1.2.3")["kind"] == "RANGE"
    assert vr.parse_constraint("*")["kind"] == "ANY"
    assert vr.parse_constraint("")["kind"] == "ANY"


def test_an_unreadable_constraint_is_invalid_with_a_reason() -> None:
    parsed = vr.parse_constraint(">=bogus.1", ecosystem="semver")
    assert parsed["kind"] == "INVALID"
    assert "not a semantic version" in parsed["reason"]


def test_satisfies_raises_rather_than_returning_false_for_garbage() -> None:
    with pytest.raises(vr.ConstraintError):
        vr.satisfies("1.0.0", ">=three", ecosystem="semver")


def test_a_caret_can_be_explained() -> None:
    explanation = vr.explain("^1.2.3", ecosystem="npm")
    assert explanation["predicates"] == [(">=", "1.2.3"), ("<", "2")]
    assert explanation["kind"] == "RANGE"


def test_any_affected_reports_what_it_could_not_read() -> None:
    affected, unevaluable = vr.any_affected(
        "3.0.11", [">=bogus", ">=3.0.0 <3.0.13"], ecosystem="semver")
    assert affected is True
    assert unevaluable == [">=bogus"]


def test_the_advisory_window_shape() -> None:
    assert vr.affected("3.0.11", introduced="3.0.0", fixed="3.0.13") is True
    assert vr.affected("3.0.13", introduced="3.0.0", fixed="3.0.13") is False
    assert vr.affected("3.0.11", introduced="3.0.0", last_affected="3.0.11") is True
    assert vr.affected("3.0.12", introduced="3.0.0", last_affected="3.0.11") is False
    assert vr.affected("3.0.11", introduced="three") is None  # unreadable, not "clean"


def test_the_container_comparator_uses_the_same_engine() -> None:
    """One comparator, with the ecosystem deciding the ordering.

    Container packages are Debian/RPM versions, whose ``-rc1`` is a package
    *revision* (so it sorts after the bare version) rather than a semver
    prerelease. The point of the delegation is that this is a deliberate family
    choice in one place, not two different comparators disagreeing.
    """
    from devsecops.container_scan import version_compare

    assert version_compare("3.0.10", "3.0.11") < 0
    assert version_compare("1.0.0", "1.0.0") == 0
    assert version_compare("1.0.0-rc1", "1.0.0") == vr.compare(
        "1.0.0-rc1", "1.0.0", ecosystem="generic")
    assert vr.compare("1.0.0-rc1", "1.0.0", ecosystem="npm") < 0  # a real prerelease
