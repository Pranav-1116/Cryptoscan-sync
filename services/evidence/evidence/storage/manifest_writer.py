"""Write scan manifests to disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ManifestWriter:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, manifest: Any, filename: str = "manifest.json") -> Path:
        path = self.output_dir / filename
        if hasattr(manifest, "model_dump"):
            payload = manifest.model_dump(mode="json")
        elif hasattr(manifest, "to_dict"):
            payload = manifest.to_dict()
        else:
            payload = manifest
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
