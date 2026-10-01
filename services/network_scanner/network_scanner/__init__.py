"""Network TLS scanner — active probe + certificate inventory.

The realtime CLI keeps optional configuration dependencies lazy so an
uninstalled deployment returns a structured PREFLIGHT/UNAVAILABLE result
instead of crashing before it can report scanner availability.
"""

try:
    from network_scanner.core.scanner import NetworkTlsScanner
except (ImportError, ModuleNotFoundError):  # optional yaml/settings dependency
    NetworkTlsScanner = None  # type: ignore[assignment]

__all__ = ["NetworkTlsScanner"]
