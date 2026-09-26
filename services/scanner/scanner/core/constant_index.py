"""Repo-level constant index: resolve algorithm names declared in *another* file.

Bank code bases keep algorithm strings in constants classes::

    public final class Algorithms { public static final String DIGEST = "SHA-1"; }
    ...
    MessageDigest.getInstance(Algorithms.DIGEST)      // different file

The per-file parsers cannot see the literal and report ``UNKNOWN`` with
``variable_name="Algorithms.DIGEST"``.  This module builds a light index of
string constants across the tree (Java/Kotlin/Scala/C#) and rewrites those
UNKNOWN findings once, after all files were scanned.

Precision rules:
* only compile-time constants (``static final``, ``const val``, ``const string``,
  ``static readonly string``) with a literal ≤ 80 chars are indexed;
* a simple name that is bound to *different* literals in different classes is
  ambiguous and is never used unless the finding names the class;
* the resolved algorithm must be in the scanner vocabulary (otherwise it stays
  UNKNOWN);
* resolved findings are MEDIUM confidence with a ``confidence_reason`` naming
  the source constant, so a reviewer can verify the hop.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown, parse_transformation

_JAVA_CONST = re.compile(
    r"\b(?:public|private|protected|internal)?\s*(?:static\s+final|final\s+static|const\s+val|const|static\s+readonly|readonly\s+static)\s+"
    r"(?:String|string|val)?\s*(\w+)\s*(?::\s*String)?\s*=\s*\"([^\"\\\n]{1,80})\"\s*;?",
)
_CLASS = re.compile(r"\b(?:class|object|interface|enum|struct)\s+(\w+)")
_INDEXED_SUFFIXES = {".java", ".kt", ".kts", ".scala", ".cs"}
_RESOLVABLE_API_TYPES = {
    "CIPHER_INSTANCE", "MESSAGE_DIGEST", "MAC", "SIGNATURE", "KEY_GENERATOR", "KEY_PAIR_GENERATOR",
    "SECRET_KEY_SPEC", "SECRET_KEY_FACTORY", "KEY_FACTORY", "KEY_AGREEMENT", "HARDCODED_KEY",
}
_MAX_FILE_BYTES = 2_000_000


class ConstantIndex:
    def __init__(self) -> None:
        # simple name -> {literal: {ClassName, ...}}
        self._by_name: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.files_indexed = 0
        self.constants_indexed = 0

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, files: Iterable[Path]) -> "ConstantIndex":
        index = cls()
        for path in files:
            if path.suffix.lower() not in _INDEXED_SUFFIXES:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            index.add_source(text)
        return index

    def add_source(self, text: str) -> None:
        if "=" not in text or '"' not in text:
            return
        self.files_indexed += 1
        # class name in scope for each constant = nearest preceding class/object declaration
        class_positions = [(m.start(), m.group(1)) for m in _CLASS.finditer(text)]
        for m in _JAVA_CONST.finditer(text):
            name, value = m.group(1), m.group(2)
            owner = ""
            for pos, cname in class_positions:
                if pos < m.start():
                    owner = cname
                else:
                    break
            self._by_name[name][value].add(owner)
            self.constants_indexed += 1

    # ---------------------------------------------------------------- lookup
    def lookup(self, reference: str) -> tuple[str | None, str | None]:
        """``"Algorithms.DIGEST"`` / ``"DIGEST"`` → (literal, "Algorithms.DIGEST") or (None, None)."""
        if not reference or not re.fullmatch(r"[\w.]+", reference):
            return None, None
        parts = reference.split(".")
        name = parts[-1]
        owner = parts[-2] if len(parts) >= 2 else None
        values = self._by_name.get(name)
        if not values:
            return None, None
        if owner:
            hits = {v for v, owners in values.items() if owner in owners}
            if len(hits) == 1:
                return next(iter(hits)), f"{owner}.{name}"
            if hits:
                return None, None  # same class name, different literals → ambiguous
        if len(values) == 1:
            value = next(iter(values))
            owners = sorted(o for o in values[value] if o)
            return value, f"{owners[0]}.{name}" if owners else name
        return None, None

    # --------------------------------------------------------------- resolve
    def resolve(self, findings: list) -> int:
        """Fill algorithm/mode/padding on UNKNOWN findings whose variable_name is an indexed constant.
        Returns the number of findings resolved."""
        if not self.constants_indexed:
            return 0
        resolved = 0
        for f in findings:
            try:
                if f.crypto.algorithm not in (None, "UNKNOWN"):
                    continue
                if f.crypto.api_type not in _RESOLVABLE_API_TYPES:
                    continue
                if f.source.language not in {"JAVA", "KOTLIN", "SCALA", "CSHARP"}:
                    continue
                ref = f.source.variable_name
            except AttributeError:
                continue
            value, origin = self.lookup(ref or "")
            if not value:
                continue
            parsed = parse_transformation(value)
            algorithm = known_algorithm_or_unknown(parsed.algorithm)
            if algorithm == "UNKNOWN":
                continue
            f.crypto.algorithm = algorithm
            f.crypto.mode = f.crypto.mode or parsed.mode
            f.crypto.padding = f.crypto.padding or parsed.padding
            f.crypto.raw_transformation = f.crypto.raw_transformation or value
            f.metadata.confidence = "MEDIUM"
            f.metadata.confidence_reason = f"algorithm resolved from cross-file constant {origin} = \"{value}\""
            resolved += 1
        return resolved
