"""JSON output writer - serializes scan results to files."""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from scanner.models.scan_result import ScanResult

logger = structlog.get_logger(__name__)


class JsonWriter:
    """Writes scan results to JSON files."""

    def __init__(self, output_path: Path | None = None):
        self.output_path = Path(output_path) if output_path else None

    def write(self, result: ScanResult, output_dir: Path | None = None) -> Path:
        """
        Write scan result to a JSON file.
        
        Output filename: scan-results-{scan_id}.json
        
        Args:
            result: Complete scan result
            output_dir: Directory to write the file
            
        Returns:
            Path to the written file
        """
        if output_dir is None and self.output_path is not None:
            output_path = self.output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            dest = Path(output_dir or "./scan-output")
            dest.mkdir(parents=True, exist_ok=True)
            output_path = dest / f"scan-results-{result.scan_id}.json"

        data = result.model_dump(mode="json")

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(
            "scan_result_written",
            path=str(output_path),
            findings=result.statistics.total_findings,
        )

        return output_path

    def write_to_stdout(self, result: ScanResult) -> None:
        """Write scan result as JSON to stdout."""
        import sys
        data = result.model_dump(mode="json")
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


JSONWriter = JsonWriter