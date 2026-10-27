"""Shared RawFinding constructor for language parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from scanner.extractors.snippet_extractor import extract_snippet
from scanner.models.raw_finding import CryptoInfo, FindingMetadata, RawFinding, SourceLocation


def make_finding(
    *,
    file_path: Path,
    repo_root: Path | None,
    line_number: int,
    language: str,
    api_type: str,
    algorithm: Optional[str],
    purpose: str,
    library: str,
    scanner_id: str,
    mode: Optional[str] = None,
    padding: Optional[str] = None,
    key_size: Optional[int] = None,
    confidence: str = "HIGH",
    confidence_reason: str = "literal-api",
    is_hardcoded_key: bool = False,
    hardcoded_key_length: Optional[int] = None,
    method_name: Optional[str] = None,
    class_name: Optional[str] = None,
    raw_transformation: Optional[str] = None,
) -> RawFinding:
    # Algorithm registry enrichment: every finding leaves with its key size
    # (AES-256 -> 256, DES -> 56, RSA -> min 2048 guidance) even when the
    # parser could not extract one from the call site.
    try:
        from shared_models.algorithm_registry import parse_algorithm

        info = parse_algorithm(str(raw_transformation or algorithm or ""))
        if info.recognized:
            if key_size is None:
                key_size = info.key_size
            if mode is None and info.mode:
                mode = info.mode
    except Exception:
        pass

    relative = str(file_path)
    if repo_root:
        try:
            relative = str(file_path.relative_to(repo_root))
        except ValueError:
            relative = str(file_path)
    return RawFinding(
        scanner_id=scanner_id,
        scanner_version="1.0.0",
        source=SourceLocation(
            type="SOURCE_CODE",
            language=language,
            file_path=relative,
            line_number=line_number,
            method_name=method_name,
            class_name=class_name,
            code_snippet=extract_snippet(file_path, line_number),
        ),
        crypto=CryptoInfo(
            api_type=api_type,
            algorithm=algorithm,
            mode=mode,
            padding=padding,
            key_size=key_size,
            purpose=purpose,
            raw_transformation=raw_transformation,
        ),
        metadata=FindingMetadata(
            confidence=confidence,
            confidence_reason=confidence_reason,
            library=library,
            is_hardcoded_key=is_hardcoded_key,
            hardcoded_key_length=hardcoded_key_length,
        ),
    )
