"""CLI entry for the cloud / IaC scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cloud_scanner.config.settings import load_settings
from cloud_scanner.core.result_submitter import ResultSubmitter
from cloud_scanner.core.scanner import CloudScanner


def main(argv: list[str] | None = None) -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Scan Terraform / Kubernetes / CloudFormation for crypto config")
    parser.add_argument("path", nargs="?", default=".", help="Filesystem root to scan")
    parser.add_argument("-o", "--output", help="Write JSON result to this path")
    parser.add_argument("--live", action="store_true", default=settings.live)
    parser.add_argument("--submit", action="store_true", default=settings.submit_results)
    args = parser.parse_args(argv)

    result = CloudScanner(live=args.live).scan_filesystem(args.path)
    if args.submit:
        result["submit"] = ResultSubmitter(api_url=settings.api_url).submit(result)
    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
