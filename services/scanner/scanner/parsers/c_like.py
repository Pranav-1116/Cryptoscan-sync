"""Comment-aware helpers for C-like languages (JS/TS/C#). Preserves newlines."""

from __future__ import annotations


def strip_c_like_comments(source: str) -> str:
    """Remove // and /* */ comments without touching string or template literals."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            i += 2
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            i = min(n, i + 2)
            out.append("  ")
            continue
        if ch in {'"', "'"}:
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                out.append(source[i])
                if source[i] == "\\" and i + 1 < n:
                    out.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "`":
            out.append(ch)
            i += 1
            while i < n:
                out.append(source[i])
                if source[i] == "\\" and i + 1 < n:
                    out.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == "`":
                    i += 1
                    break
                i += 1
            continue
        if ch == "@" and nxt == '"':
            out.append(ch)
            out.append(nxt)
            i += 2
            while i < n:
                out.append(source[i])
                if source[i] == '"' and i + 1 < n and source[i + 1] == '"':
                    out.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _copy_quoted(source: str, i: int, out: list[str]) -> int:
    n = len(source)
    quote = source[i]
    out.append(quote)
    i += 1
    while i < n:
        out.append(source[i])
        if source[i] == "\\" and i + 1 < n:
            out.append(source[i + 1])
            i += 2
            continue
        if source[i] == quote:
            return i + 1
        i += 1
    return i


def strip_hash_line_comments(source: str) -> str:
    """Remove # line comments outside strings. Preserves newlines (PHP/Ruby/shell)."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in {'"', "'", "`"}:
            i = _copy_quoted(source, i, out)
            continue
        if ch == "#":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def strip_php_comments(source: str) -> str:
    return strip_hash_line_comments(strip_c_like_comments(source))


def strip_ruby_comments(source: str) -> str:
    """Remove =begin/=end blocks and # line comments. Preserves newlines."""
    pieces: list[str] = []
    in_block = False
    for line in source.splitlines(keepends=True):
        start = line.lstrip(" \t")
        if not in_block and start.startswith("=begin"):
            in_block = True
            pieces.append("\n" if line.endswith("\n") else "")
            continue
        if in_block:
            if start.startswith("=end"):
                in_block = False
            pieces.append("\n" if line.endswith("\n") else "")
            continue
        pieces.append(line)
    return strip_hash_line_comments("".join(pieces))
