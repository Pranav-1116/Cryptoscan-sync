"""Import-compatible package wrapper for the nested telecom scanner source.

The service keeps its implementation under ``telecom_scanner/telecom_scanner``
for consistency with the other service packages. Test runners and local
workers put the service root on ``PYTHONPATH``; expose the inner directory as
this package's module path so ``telecom_scanner.automation``,
``telecom_scanner.classify`` and the rest resolve identically in source and
installed-style execution.
"""

from pathlib import Path

__path__ = [str(Path(__file__).with_name("telecom_scanner"))]
__all__: list[str] = []
