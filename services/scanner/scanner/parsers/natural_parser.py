"""Software AG Natural (Adabas shops): ICSF callable services from Natural programs.

Natural calls the same z/OS crypto services as COBOL (``CALL 'CSNBSYE' ...``) and declares
the 8-byte rule-array keywords in ``DEFINE DATA`` (``INIT <'SHA-256 '>``), so the COBOL/ICSF
rule table applies unchanged.  Only the comment syntax differs:

* ``*`` in column 1 (reporting mode) / ``**`` — whole-line comment
* ``/*`` — comment to end of line (also inside structured-mode statements)

Object types: NSP program, NSN subprogram, NSS subroutine, NSH helproutine, NSC copycode,
NSL/NSA/NSG data areas, NSM map (Natural ONE / NaturalONE export naming).
"""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.cobol_parser import _RULES
from scanner.parsers.rule_engine import run_rules

SCANNER_ID = "static-natural-scanner-v1.0"
NATURAL_EXT = {".nsp", ".nsn", ".nss", ".nsh", ".nsc", ".nsl", ".nsa", ".nsg", ".nsm", ".nat"}


def strip_natural_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("*") and not stripped.startswith("*LENGTH") and not stripped.startswith("*DAT") and not stripped.startswith("*TIM") and not stripped.startswith("*PROGRAM") and not stripped.startswith("*USER"):
            # `*` comment line; system variables (*LENGTH, *DATX ...) never start a line as a statement anyway
            out.append(" " * len(line))
            continue
        idx = line.find("/*")
        if idx >= 0:
            line = line[:idx] + " " * (len(line) - idx)
        out.append(line)
    return "\n".join(out)


def parse_natural_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=strip_natural_comments(text),
        rules=_RULES,
        language="NATURAL",
        scanner_id=SCANNER_ID,
        confidence_reason="icsf-callable-service",
        strip_comments=False,
    )
