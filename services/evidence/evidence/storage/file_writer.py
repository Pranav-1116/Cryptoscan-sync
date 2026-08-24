"""Write evidence records to disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FileWriter:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_records(self, records: list[Any], filename: str = "evidence.json") -> Path:
        path = self.output_dir / filename
        payload = []
        for record in records:
            if hasattr(record, "model_dump"):
                payload.append(record.model_dump(mode="json"))
            elif hasattr(record, "to_dict"):
                payload.append(record.to_dict())
            else:
                payload.append(record)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
