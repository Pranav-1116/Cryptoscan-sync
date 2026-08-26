"""Scanner package. Heavy imports stay lazy so plugin catalog works without structlog."""

from __future__ import annotations

__all__ = ["Scanner", "CryptoScanner"]


def __getattr__(name: str):
    if name in {"Scanner", "CryptoScanner", "MultiLanguageScanner"}:
        from scanner.core.scanner import Scanner

        return Scanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
