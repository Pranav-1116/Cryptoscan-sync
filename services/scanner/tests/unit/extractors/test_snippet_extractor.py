"""Scanner extractor tests — snippet extractor (previously untested)."""

from __future__ import annotations

from pathlib import Path

from scanner.extractors.snippet_extractor import (
    CONTEXT_LINES,
    extract_snippet,
    extract_snippet_from_source,
)


def _source(n: int) -> list[str]:
    return [f"line {i + 1}" for i in range(n)]


class TestExtractSnippetFromSource:
    def test_marks_finding_line(self):
        snippet = extract_snippet_from_source(_source(10), target_line=4)
        assert ">>>" in snippet
        assert "line 4" in snippet
        # only the target line is marked
        assert snippet.count(">>>") == 1

    def test_default_context_window_is_five(self):
        snippet = extract_snippet_from_source(_source(20), target_line=10)
        assert "line 5" in snippet
        assert "line 15" in snippet
        assert "line 4" not in snippet  # outside the ±5 window
        assert "line 16" not in snippet

    def test_custom_context_window(self):
        snippet = extract_snippet_from_source(
            _source(20), target_line=10, context_lines=1)
        assert "line 9" in snippet
        assert "line 11" in snippet
        assert "line 8" not in snippet

    def test_clamps_at_file_start(self):
        snippet = extract_snippet_from_source(_source(10), target_line=1)
        assert snippet.startswith("   1: >>> line 1")
        assert "line 6" in snippet

    def test_clamps_at_file_end(self):
        snippet = extract_snippet_from_source(_source(10), target_line=10)
        assert "line 10" in snippet
        assert ">>>" in snippet
        assert "line 5" in snippet  # window clamps to last line

    def test_line_numbers_present(self):
        snippet = extract_snippet_from_source(_source(5), target_line=3)
        for expected in ("   1:", "   2:", "   3:", "   4:", "   5:"):
            assert expected in snippet

    def test_empty_source(self):
        assert extract_snippet_from_source([], target_line=1) == ""


class TestExtractSnippetFile:
    def test_reads_file_and_marks_line(self, tmp_path: Path):
        path = tmp_path / "Pay.java"
        path.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
        snippet = extract_snippet(path, target_line=3)
        assert snippet is not None
        assert ">>>" in snippet
        assert "c" in snippet

    def test_missing_file_returns_none(self, tmp_path: Path):
        assert extract_snippet(tmp_path / "missing.py", target_line=1) is None

    def test_directory_returns_none(self, tmp_path: Path):
        assert extract_snippet(tmp_path, target_line=1) is None

    def test_binary_file_never_raises(self, tmp_path: Path):
        # errors="replace" means odd bytes are substituted, never an exception
        path = tmp_path / "blob.bin"
        path.write_bytes(b"\x00\x01\x02\xff\xfe")
        snippet = extract_snippet(path, target_line=1)
        assert snippet is not None
        assert ">>>" in snippet

    def test_line_beyond_file_yields_empty(self, tmp_path: Path):
        path = tmp_path / "short.txt"
        path.write_text("one\ntwo\n", encoding="utf-8")
        snippet = extract_snippet(path, target_line=999)
        # the window is entirely past the last line, so no lines to render
        assert snippet == ""

    def test_constant_is_five(self):
        assert CONTEXT_LINES == 5
