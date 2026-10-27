"""Release version-consistency core (pure).

The production release gate (``scripts/release_check.py``) wires real
repository state (VERSION file, CHANGELOG, git tags, migration filenames)
into these functions and turns the returned findings into an operator-facing
report and exit code. Keeping every rule pure keeps the gate itself testable:
a release may only be cut when the VERSION file, the API's declared version,
the CHANGELOG, the git tag and the ordered migrations all agree.

Conventions pinned here:

* ``VERSION`` holds a plain semver string (``MAJOR.MINOR.PATCH``).
* The API declares the same version as ``APISettings.API_VERSION``.
* CHANGELOG carries a ``## [<version>] — <YYYY-MM-DD>`` section per release
  (dash, en dash or em dash accepted as the separator).
* The release is git-tagged ``v<version>`` (annotated).
* Ordered database migrations are numbered ``NNNN_*`` with no gaps.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# "## [1.0.0] — 2026-09-10" (separator may be -, –, —)
_CHANGELOG_SECTION_RE = re.compile(
    r"^##\s*\[(?P<version>[^\]\s]+)\]\s*[-–—]+\s*(?P<date>\d{4}-\d{2}-\d{2})\s*$",
    re.MULTILINE,
)

# "0001_create_scans_table.py" -> 1
_MIGRATION_NUMBER_RE = re.compile(r"^(\d{4})_")

ERROR = "error"
WARN = "warn"


@dataclass(frozen=True)
class Finding:
    """One gate result. ``severity`` is ERROR (blocks the release) or WARN."""

    check: str
    severity: str
    message: str

    @property
    def blocking(self) -> bool:
        return self.severity == ERROR


def is_semver(text: str) -> bool:
    """True when ``text`` is an exact MAJOR.MINOR.PATCH version string."""
    return bool(SEMVER_RE.match(text.strip()))


def changelog_release_date(changelog_text: str, version: str) -> str | None:
    """Release date for ``version`` from its CHANGELOG section, else None."""
    for match in _CHANGELOG_SECTION_RE.finditer(changelog_text):
        if match.group("version") == version:
            return match.group("date")
    return None


def migration_gaps(names: list[str]) -> list[int]:
    """Missing sequence numbers in an ``NNNN_*``-named migration list.

    Files whose names carry no leading number are ignored (e.g. helper
    modules). The sequence is expected to run 0001..max with no holes.
    """
    numbers = sorted(
        int(match.group(1))
        for name in names
        if (match := _MIGRATION_NUMBER_RE.match(name)) is not None
    )
    if not numbers:
        return []
    present = set(numbers)
    return [n for n in range(1, max(numbers) + 1) if n not in present]


def validate_release(
    version_text: str,
    api_version: str,
    changelog_text: str,
    tags: list[str],
    head_tagged: bool,
    allow_untagged: bool = False,
) -> list[Finding]:
    """Cross-check VERSION file, API version, CHANGELOG and git tags.

    ``tags`` holds existing tag names; ``head_tagged`` is True when the
    current HEAD commit carries the release tag. ``allow_untagged`` downgrades
    the missing-tag error to a warning (pre-tag dry runs).
    """
    findings: list[Finding] = []
    version = version_text.strip()

    if not is_semver(version):
        findings.append(
            Finding(
                "version-format",
                ERROR,
                f"VERSION must be MAJOR.MINOR.PATCH (got {version!r}); "
                "hash-style versions are interim history, releases are semver",
            )
        )
        return findings

    if version != api_version.strip():
        findings.append(
            Finding(
                "version-consistency",
                ERROR,
                f"VERSION ({version}) != API API_VERSION ({api_version.strip()}) — "
                "the dashboard, OpenAPI doc and release name must agree",
            )
        )

    date = changelog_release_date(changelog_text, version)
    if date is None:
        findings.append(
            Finding(
                "changelog-section",
                ERROR,
                f"CHANGELOG.md has no '## [{version}] — YYYY-MM-DD' section",
            )
        )

    expected_tag = f"v{version}"
    if expected_tag not in tags:
        severity = WARN if allow_untagged else ERROR
        findings.append(
            Finding(
                "git-tag",
                severity,
                f"tag {expected_tag} does not exist "
                + ("(allowed by --allow-untagged dry run)" if allow_untagged else "— create it annotated: git tag -a"),
            )
        )
    elif not head_tagged:
        findings.append(
            Finding(
                "git-tag-head",
                WARN,
                f"tag {expected_tag} exists but is not on the current HEAD commit",
            )
        )

    return findings
