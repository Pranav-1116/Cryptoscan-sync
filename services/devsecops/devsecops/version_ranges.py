"""Version ordering and constraint satisfaction, per ecosystem, without guessing.

The review's item 10 is blunt about this: *range parsing per ecosystem is the
next step, and until then ``INSUFFICIENT_IDENTIFIER`` is the honest answer more
often than a bank will like.* This module is that step.

Three things it deliberately does **not** do:

* it does not pretend every ecosystem orders versions the same way. ``1.0.0-rc1``
  is *older* than ``1.0.0`` in semver and in PEP 440, but the naive
  "split on dots and compare" that shipped before this module compared the
  prerelease as a trailing tag and got it backwards;
* it does not treat an unparseable constraint as "no match". A constraint the
  platform cannot read raises :class:`ConstraintError`, and the caller records
  ``UNKNOWN`` with the reason — a silent non-match is the failure mode that makes
  "0 vulnerabilities" untrustworthy;
* it does not compare across ecosystems. ``1.0.0.0`` (Maven) and ``1.0.0+build``
  (semver) are read by the comparator for their own ecosystem.

Supported constraint syntax, which is what the advisory feeds in the estate
actually carry:

===============  ==========================================================
``1.2.3``        an exact version (a bare version is a pin)
``==1.2.3``      an exact version
``>=1.2, <2.0``  comparator sets, joined by spaces or commas (AND)
``^1.2.3``       ``>=1.2.3 <2.0.0`` (``^0.2.3`` → ``<0.3.0``)
``~1.2.3``       ``>=1.2.3 <1.3.0`` (``~1.2`` → ``<1.3.0``)
``1.2.x``        any ``1.2.*``
``*`` / empty    anything
``a || b``       either side (OR)
``[1.0,2.0)``    Maven/ivy interval notation, ``(`` ``)`` exclusive
``!=1.2.3``      everything but that version
``~=1.4.5``      PEP 440 compatible release: ``>=1.4.5, ==1.4.*``
===============  ==========================================================
"""

from __future__ import annotations

import re
from typing import Any, Iterable

SCHEMA = "cryptoscan.version-ranges/1"

SEMVER, PEP440, MAVEN, GENERIC = "semver", "pep440", "maven", "generic"
ECOSYSTEMS: tuple[str, ...] = (SEMVER, PEP440, MAVEN, GENERIC)

#: package manager → comparator family
_MANAGER_FAMILY: dict[str, str] = {
    "npm": SEMVER, "yarn": SEMVER, "pnpm": SEMVER, "cargo": SEMVER, "rust": SEMVER,
    "go": SEMVER, "gomod": SEMVER, "composer": SEMVER, "php": SEMVER,
    "pip": PEP440, "pypi": PEP440, "python": PEP440, "poetry": PEP440,
    "pipenv": PEP440, "setuptools": PEP440,
    "maven": MAVEN, "gradle": MAVEN, "java": MAVEN,
    "nuget": GENERIC, "dotnet": GENERIC, "gem": GENERIC, "bundler": GENERIC,
    "rubygems": GENERIC, "debian": GENERIC, "rpm": GENERIC, "apk": GENERIC,
    "alpine": GENERIC, "generic": GENERIC,
}


class ConstraintError(ValueError):
    """The constraint is not something this module can evaluate honestly."""


def family_for(ecosystem: str | None) -> str:
    """The comparator family for an ecosystem, package manager, or family name."""
    name = str(ecosystem or "").strip().lower()
    if name in ECOSYSTEMS:
        return name
    return _MANAGER_FAMILY.get(name, GENERIC)


# --------------------------------------------------------------------------- #
# ordering
# --------------------------------------------------------------------------- #

_PEP440 = re.compile(
    r"^(?:v?(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d*))?"
    r"(?:[-_.]?(?:post|rev|r)[-_.]?(?P<post>\d*))?"
    r"(?:[-_.]?dev[-_.]?(?P<dev>\d*))?",
    re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _release_parts(text: str) -> list[int]:
    return [int(part) for part in re.findall(r"\d+", text or "")]


def _pep440_key(version: str) -> tuple:
    """A comparable key per PEP 440: epoch, release, then pre/post/dev ordering.

    The ordering the standard defines, and the one a bank's feed depends on::

        1.0.dev1  <  1.0a1  <  1.0a1.post1  <  1.0b1  <  1.0rc1  <  1.0  <  1.0.post1

    A dev release with no pre/post marker sorts *before* the prereleases of the
    same release, which is the case a naive "compare the numbers" gets backwards.
    Trailing zeros are ignored, so ``1.0`` and ``1.0.0`` are the same version.
    """
    text = str(version or "").strip()
    match = _PEP440.match(text)
    if not match:
        raise ConstraintError(f"{version!r} is not a PEP 440 version")
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    epoch = int(match.group("epoch") or 0)
    pre_l = (match.group("pre_l") or "").lower()
    post = match.group("post")
    dev = match.group("dev")
    if pre_l:
        pre_key: tuple = (1, _PRE_RANK[pre_l], int(match.group("pre_n") or 0))
    elif post is None and dev is not None:
        pre_key = (-1,)  # a bare dev release precedes every prerelease
    else:
        pre_key = (2,)
    post_key = (0,) if post is None else (1, int(post or 0))
    dev_key = (0, int(dev or 0)) if dev is not None else (1,)
    return (epoch, tuple(release), pre_key, post_key, dev_key)


_SEMVER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")


def _semver_key(version: str) -> tuple:
    text = str(version or "").strip()
    match = _SEMVER.match(text)
    if not match:
        raise ConstraintError(f"{version!r} is not a semantic version")
    release = [int(part) for part in match.group(1).split(".")]
    while len(release) < 3:
        release.append(0)
    prerelease = match.group(2)
    if prerelease is None:
        pre_key: tuple = (1,)
    else:
        identifiers = []
        for part in prerelease.split("."):
            identifiers.append((0, int(part)) if part.isdigit() else (1, part))
        # a shorter prerelease sorts first when the shared parts are equal
        pre_key = (0, tuple(identifiers))
    return (tuple(release), pre_key)


def _generic_key(version: str) -> tuple:
    """Dot/dash separated segments, numbers before text, missing segments as 0."""
    text = str(version or "").strip().lstrip("v")
    if not text:
        raise ConstraintError("an empty string is not a version")
    segments: list[tuple] = []
    for part in re.split(r"[.\-_+~]", text):
        if part == "":
            continue
        for piece in re.findall(r"\d+|[A-Za-z]+", part):
            segments.append((0, int(piece)) if piece.isdigit() else (1, piece.lower()))
    if not segments:
        raise ConstraintError(f"{version!r} has no comparable segments")
    if not any(kind == 0 for kind, _ in segments):
        # a string with no digits anywhere is a label, not a version: treating
        # "three" as a comparable release would let an unreadable advisory look
        # like a real answer
        raise ConstraintError(f"{version!r} contains no version numbers")
    while segments and segments[-1] == (0, 0):
        segments.pop()
    return tuple(segments)


def compare(left: str, right: str, *, ecosystem: str | None = None) -> int:
    """``-1`` / ``0`` / ``1`` — the ordering of two versions in one ecosystem.

    Raises :class:`ConstraintError` for a value the comparator for that ecosystem
    cannot read, so a caller can record an unassessed component instead of
    treating a parse failure as "not affected".
    """
    family = family_for(ecosystem)
    if family == PEP440:
        a, b = _pep440_key(left), _pep440_key(right)
    elif family == SEMVER:
        a, b = _semver_key(left), _semver_key(right)
    else:
        a, b = _generic_key(left), _generic_key(right)
    return (a > b) - (a < b)


def sort_key(version: str, *, ecosystem: str | None = None) -> Any:
    family = family_for(ecosystem)
    if family == PEP440:
        return _pep440_key(version)
    if family == SEMVER:
        return _semver_key(version)
    return _generic_key(version)


# --------------------------------------------------------------------------- #
# constraints
# --------------------------------------------------------------------------- #

Comparator = tuple[str, str]


def _bump(parts: list[int], index: int) -> str:
    bumped = list(parts[: index + 1])
    bumped[index] += 1
    while len(bumped) <= index:
        bumped.append(0)
    return ".".join(str(part) for part in bumped)


def _caret(version: str) -> list[Comparator]:
    """``^1.2.3`` → ``>=1.2.3 <2.0.0``; ``^0.2.3`` → ``>=0.2.3 <0.3.0``."""
    parts = _release_parts(version)
    if not parts:
        raise ConstraintError(f"caret needs a version, got {version!r}")
    first = next((index for index, part in enumerate(parts) if part != 0), 0)
    return [(">=", version), ("<", _bump(parts, first))]


def _tilde(version: str) -> list[Comparator]:
    """``~1.2.3`` → ``>=1.2.3 <1.3.0``; ``~1`` → ``>=1 <2``."""
    parts = _release_parts(version)
    if not parts:
        raise ConstraintError(f"tilde needs a version, got {version!r}")
    index = 0 if len(parts) == 1 else 1
    return [(">=", version), ("<", _bump(parts, index))]


def _compatible(version: str) -> list[Comparator]:
    """PEP 440 ``~=1.4.5`` → ``>=1.4.5, ==1.4.*``."""
    parts = _release_parts(version)
    if len(parts) < 2:
        raise ConstraintError("~= needs at least two release segments")
    prefix = ".".join(str(part) for part in parts[:-1])
    return [(">=", version), ("~prefix", prefix)]


_WILDCARD = re.compile(r"^(?P<prefix>\d+(?:\.\d+)*)\.[xX*]$")
_BARE = re.compile(r"^\d+(?:\.\d+)*([.\-+~][0-9A-Za-z.\-+~]*)?$")
_MAVEN_RANGE = re.compile(r"^(?P<open>[\[(])\s*(?P<low>[^,\]]*)\s*,\s*(?P<high>[^)\]]*)\s*(?P<close>[\])])$")


def _single(token: str) -> list[Comparator]:
    token = token.strip()
    if token in {"", "*", "x", "X", "latest", "any"}:
        return []
    if token.startswith("^"):
        return _caret(token[1:])
    if token.startswith("~="):
        return _compatible(token[2:])
    if token.startswith("~"):
        return _tilde(token[1:])
    wildcard = _WILDCARD.match(token)
    if wildcard:
        return [("~prefix", wildcard.group("prefix"))]
    for operator in (">=", "<=", "==", "!=", ">", "<", "="):
        if token.startswith(operator):
            value = token[len(operator):].strip()
            if not value:
                raise ConstraintError(f"{token!r} has no version after {operator!r}")
            return [("==" if operator == "=" else operator, value)]
    maven = _MAVEN_RANGE.match(token)
    if maven:
        clauses: list[Comparator] = []
        if maven.group("low"):
            clauses.append((">" if maven.group("open") == "(" else ">=", maven.group("low")))
        if maven.group("high"):
            clauses.append(("<" if maven.group("close") == ")" else "<=", maven.group("high")))
        return clauses
    if _BARE.match(token):
        return [("==", token)]
    raise ConstraintError(f"cannot read constraint {token!r}")


def parse_constraint(constraint: str | None, *,
                     ecosystem: str | None = None) -> dict[str, Any]:
    """Parse a constraint into alternatives (OR) of comparator sets (AND).

    Returns ``{"kind": "ANY"|"EXACT"|"RANGE"|"INVALID", "alternatives": [[...]],
    "reason": ...}`` — never raises, so a caller can report why a constraint was
    not usable.
    """
    text = "" if constraint is None else str(constraint).strip()
    if text in {"", "*", "x", "X"}:
        return {"kind": "ANY", "alternatives": [[]], "text": text}
    alternatives: list[list[Comparator]] = []
    try:
        for alternative in re.split(r"\s*\|\|\s*", text):
            clauses: list[Comparator] = []
            # commas separate comparators, except inside a Maven interval
            for chunk in re.split(r",(?![^\[]*[\])])", alternative):
                for token in re.split(r"\s+", chunk.strip()):
                    clauses.extend(_single(token))
            alternatives.append(clauses)
        # every version a constraint names must be readable in this ecosystem,
        # otherwise the constraint is unusable and saying so beats a silent miss
        for clauses in alternatives:
            for operator, target in clauses:
                if operator != "~prefix":
                    sort_key(target, ecosystem=ecosystem)
    except ConstraintError as exc:
        return {"kind": "INVALID", "alternatives": [], "text": text, "reason": str(exc)}
    flat = [clause for clauses in alternatives for clause in clauses]
    if not any(flat):
        kind = "ANY"
    elif all(clause[0] == "==" for clause in flat) and len(flat) == 1:
        kind = "EXACT"
    else:
        kind = "RANGE"
    return {"kind": kind, "alternatives": alternatives, "text": text}


def _clause_ok(version: str, clause: Comparator, family: str) -> bool:
    operator, target = clause
    if operator == "~prefix":
        # 1.4.* / 1.x: a prefix match on the release segments
        wanted = [int(part) for part in re.findall(r"\d+", target)]
        if family == SEMVER:
            have = list(_semver_key(version)[0][: len(wanted)])
        elif family == PEP440:
            have = list(_pep440_key(version)[1][: len(wanted)])
            while len(have) < len(wanted):
                have.append(0)
        else:
            have = [part[1] for part in _generic_key(version) if part[0] == 0][: len(wanted)]
        return have == wanted
    order = compare(version, target, ecosystem=family)
    return {
        "==": order == 0, "!=": order != 0,
        ">": order > 0, ">=": order >= 0,
        "<": order < 0, "<=": order <= 0,
    }[operator]


def satisfies(version: str, constraint: str | None, *, ecosystem: str | None = None) -> bool:
    """Is ``version`` inside ``constraint`` for this ecosystem?

    Raises :class:`ConstraintError` when either side cannot be read — an
    unparseable advisory range must not become "not affected".
    """
    parsed = parse_constraint(constraint, ecosystem=ecosystem)
    if parsed["kind"] == "INVALID":
        raise ConstraintError(parsed.get("reason") or f"cannot read {constraint!r}")
    family = family_for(ecosystem)
    try:
        return any(all(_clause_ok(version, clause, family) for clause in clauses)
                   for clauses in parsed["alternatives"])
    except ConstraintError:
        raise
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise ConstraintError(f"cannot compare {version!r} with {constraint!r}: {exc}") from exc


def affected(version: str, *, introduced: str | None = None, fixed: str | None = None,
             last_affected: str | None = None, ecosystem: str | None = None) -> bool | None:
    """The advisory-range shape (introduced/fixed/last_affected), or ``None``.

    ``None`` means the range could not be evaluated, which the caller must report
    as ``UNKNOWN`` rather than as a clean result.
    """
    try:
        if introduced and compare(version, introduced, ecosystem=ecosystem) < 0:
            return False
        if fixed is not None:
            return compare(version, fixed, ecosystem=ecosystem) < 0
        if last_affected is not None:
            return compare(version, last_affected, ecosystem=ecosystem) <= 0
        return True
    except ConstraintError:
        return None


def explain(constraint: str | None, *, ecosystem: str | None = None) -> dict[str, Any]:
    """What a constraint means, for a report that has to defend a match."""
    parsed = parse_constraint(constraint, ecosystem=ecosystem)
    return {
        "schema": SCHEMA,
        "text": parsed.get("text"),
        "kind": parsed["kind"],
        "ecosystem": family_for(ecosystem),
        "predicates": [clause for clauses in parsed["alternatives"] for clause in clauses],
        "reason": parsed.get("reason"),
    }


def any_affected(version: str, constraints: Iterable[str], *,
                 ecosystem: str | None = None) -> tuple[bool, list[str]]:
    """``(affected, unevaluable)`` — every constraint that could not be read.

    The ``unevaluable`` list is the point: a caller can say "2 of the advisory's
    3 ranges could not be interpreted" instead of quietly reporting a non-match.
    """
    unevaluable: list[str] = []
    for constraint in constraints:
        try:
            if satisfies(version, constraint, ecosystem=ecosystem):
                return True, unevaluable
        except ConstraintError:
            unevaluable.append(str(constraint))
    return False, unevaluable
