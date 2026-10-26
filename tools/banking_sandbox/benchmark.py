"""Measure generator + real static collector only. Unexercised service capacity is NULL."""

from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import resource
import time
from tools.banking_sandbox.generator import generate
from tools.banking_sandbox.harness import run_static
from tools.banking_sandbox.common import dump


def run(output, counts=(10, 50, 100, 150), scale="small"):
    output = Path(output)
    if output.exists():
        raise ValueError("fresh benchmark output required")
    output.mkdir(parents=True, mode=0o700)
    rows = []
    for banks in counts:
        estate = output / f"estate-{banks}"
        start = time.monotonic()
        cpu = resource.getrusage(resource.RUSAGE_SELF)
        generate(estate, banks=banks, scale=scale)
        after = resource.getrusage(resource.RUSAGE_SELF)
        generated = {
            "wall_seconds": time.monotonic() - start,
            "cpu_seconds": after.ru_utime + after.ru_stime - cpu.ru_utime - cpu.ru_stime,
            "process_peak_rss_kib_cumulative": after.ru_maxrss,
            **json.loads((estate / "generation-metrics.json").read_text()),
        }
        result = run_static(estate, output / f"collection-{banks}")
        summaries = []
        for line in (output / f"collection-{banks}/collector.log").read_text().splitlines():
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                    if "summary" in d:
                        summaries.append(d["summary"])
                except ValueError:
                    pass
        accuracy = (
            json.loads((output / f"collection-{banks}/accuracy.json").read_text())
            if result["failure"] is None
            else None
        )
        row = {
            "banks": banks,
            "scale": scale,
            "generated": generated,
            "collection": result,
            "collector_summary": summaries[-1] if summaries else None,
            "accuracy": {
                k: accuracy[k]
                for k in [
                    "precision",
                    "recall",
                    "false_positive_rate_negative_files",
                    "failure_rate",
                    "files",
                    "tp",
                    "fp",
                    "fn",
                ]
            }
            if accuracy
            else None,
        }
        rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)
        dump(output / f"measurement-{banks}.json", row)
    report = {
        "version": "SYNTHETIC_STATIC_SCALE_MEASUREMENTS_V1",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "clock_kind": "ACTUAL_WALL_CLOCK",
        "samples": rows,
        "production_capacity_claim": False,
        "limits": "Sequential library-call scanner benchmark, not queues/API/database/end-to-end workers",
    }
    dump(output / "report.json", report)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--banks", type=int, nargs="+", default=[10, 50, 100, 150])
    p.add_argument("--scale", choices=["small", "medium", "large", "mixed", "mega"], default="small")
    a = p.parse_args()
    run(a.output, a.banks, a.scale)
