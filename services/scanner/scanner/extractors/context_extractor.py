"""Extract file / method / class context around a source line."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from scanner.extractors.snippet_extractor import extract_snippet

METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|def|function|void|async)?\s*(\w+)\s*\([^;]*\)\s*\{?"
)
CLASS_RE = re.compile(r"(?:class|interface|enum)\s+(\w+)")


def extract_context(file_path: Path, line_number: int) -> dict:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"file_path": str(file_path), "line_number": line_number}
    lines = source.splitlines()
    prefix = "\n".join(lines[: max(line_number, 0)])
    methods = list(METHOD_RE.finditer(prefix))
    classes = list(CLASS_RE.finditer(prefix))
    return {
        "file_path": str(file_path),
        "line_number": line_number,
        "method_name": methods[-1].group(1) if methods else None,
        "class_name": classes[-1].group(1) if classes else None,
        "code_snippet": extract_snippet(file_path, line_number),
    }


def containing_method(source: str, line_number: int) -> Optional[str]:
    prefix = "\n".join(source.splitlines()[: max(line_number, 0)])
    matches = list(METHOD_RE.finditer(prefix))
    return matches[-1].group(1) if matches else None
