"""
Code snippet extractor - extracts context lines around a finding.

Returns ±5 lines around the line of interest, with line numbers.
The finding line is marked with '>>>' prefix.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


CONTEXT_LINES = 5


def extract_snippet(
    file_path: Path,
    target_line: int,
    context_lines: int = CONTEXT_LINES,
) -> Optional[str]:
    """
    Extract a code snippet around the target line.
    
    Args:
        file_path: Path to the source file
        target_line: 1-indexed line number of the finding
        context_lines: Number of context lines before and after
        
    Returns:
        Formatted string with line numbers, or None if file unreadable
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None

    lines = content.splitlines()
    total_lines = len(lines)

    # Convert to 0-indexed
    target_idx = target_line - 1
    start_idx = max(0, target_idx - context_lines)
    end_idx = min(total_lines - 1, target_idx + context_lines)

    snippet_lines = []
    for idx in range(start_idx, end_idx + 1):
        line_num = idx + 1  # Back to 1-indexed for display
        line_content = lines[idx] if idx < total_lines else ""
        prefix = ">>>" if idx == target_idx else "   "
        snippet_lines.append(f"{line_num:4d}: {prefix} {line_content}")

    return "\n".join(snippet_lines)


def extract_snippet_from_source(
    source_lines: list[str],
    target_line: int,
    context_lines: int = CONTEXT_LINES,
) -> str:
    """
    Extract snippet from already-loaded source lines.
    
    Args:
        source_lines: List of source code lines (0-indexed)
        target_line: 1-indexed line number
        context_lines: Context window size
        
    Returns:
        Formatted snippet string
    """
    total_lines = len(source_lines)
    target_idx = target_line - 1
    start_idx = max(0, target_idx - context_lines)
    end_idx = min(total_lines - 1, target_idx + context_lines)

    snippet_lines = []
    for idx in range(start_idx, end_idx + 1):
        line_num = idx + 1
        line_content = source_lines[idx] if idx < total_lines else ""
        prefix = ">>>" if idx == target_idx else "   "
        snippet_lines.append(f"{line_num:4d}: {prefix} {line_content}")

    return "\n".join(snippet_lines)