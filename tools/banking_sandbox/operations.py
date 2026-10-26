"""Local read-only UI, drift/failure exercises and honest capability matrix."""

from functools import partial
import http.server
import json
from pathlib import Path
import shutil
import tempfile
from urllib.parse import unquote, urlsplit

from tools.banking_sandbox.common import open_estate, dump, stream, records, file_hash
from tools.banking_sandbox.catalog import TEST_MODES
from tools.banking_sandbox.validator import integrity
from tools.banking_sandbox.documents import validators


def modes():
    return {
        "synthetic": True,
        "modes": {
            m: {
                "implementation": "NORMAL_COLLECTOR_AVAILABLE"
                if m == "static"
                else "ISOLATED_VM_SAMPLE_AVAILABLE"
                if m in ("network", "runtime")
                else "ACTUAL_INPUT_VALIDATION_AVAILABLE"
                if m in ("sbom", "cbom", "evidence-integrity")
                else "CONTROLLED_FIXTURE_MUTATION_AVAILABLE"
                if m in ("drift", "failure-recovery")
                else "BENCHMARK_AVAILABLE"
                if m in ("performance", "scale")
                else "FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY",
                "product_acceptance": "NOT_IMPLIED_BY_FIXTURE_COVERAGE",
            }
            for m in TEST_MODES
        },
    }


def apply_drift(root, destination):
    root, meta = open_estate(root)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink() or destination.resolve().is_relative_to(root):
        raise ValueError("fresh independent drift destination required")
    shutil.copytree(root, destination, ignore=shutil.ignore_patterns("scanner-inputs"))
    changes = []
    for p in sorted((destination / "public/drift").glob("*.json")):
        d = json.loads(p.read_text())
        if not d["enabled"]:
            continue
        network = destination / "public/network" / f"{d['bank_id']}.jsonl"
        rows = list(records(network))
        for row in rows:
            if row["app_id"] != d["target"]:
                continue
            old = dict(row)
            row["configured_protocol"] = "TLS1.2"
            row["simulated_negotiated_protocol"] = "TLS1.2"
            row["drift_time"] = d["changed_at"]
            row["clock_kind"] = "SIMULATED"
            row["configured_cipher"] = "AES-128-GCM"
            row["declared_certificate_algorithm"] = "RSA-2048"
            changes.append(
                {
                    "bank_id": d["bank_id"],
                    "endpoint_id": row["endpoint_id"],
                    "target": d["target"],
                    "when": d["changed_at"],
                    "clock_kind": "SIMULATED",
                    "previous": old,
                    "new": row,
                    "source_evidence": "CONFIGURED_FIXTURE_MUTATION_NOT_LIVE_NEGOTIATION",
                    "applications": d["affected_apps"],
                    "dependencies": d["affected_dependencies"],
                    "cbom": d["affected_cbom"],
                    "pqc_delta": d["pqc_delta"],
                }
            )
        network.unlink()
        stream(network, rows)
    from tools.banking_sandbox.load_balancers.drift import apply as apply_lb_drift

    lb_changes = apply_lb_drift(destination)
    manifest = destination / "manifest.json"
    previous = file_hash(manifest)
    manifest.unlink()
    files = [
        {"path": str(p.relative_to(destination / "public")), "bytes": p.stat().st_size, "sha256": file_hash(p)}
        for p in sorted((destination / "public").rglob("*"))
        if p.is_file()
    ]
    dump(
        manifest,
        {
            "version": "SYNTHETIC_PUBLIC_MANIFEST_V1",
            "files": files,
            "synthetic": True,
            "previous_manifest_sha256": previous,
        },
    )
    dump(destination / "control/expected_results/drift.json", {"expected_changes": changes, "synthetic": True})
    return {
        "status": "CONFIG_FIXTURE_DRIFT_APPLIED",
        "changes": len(changes),
        "load_balancer_changes": len(lb_changes),
        "clock_kind": "SIMULATED",
        "live_protocol_change": False,
    }


def failures(output):
    """Actual malformed-input/hash failures; infrastructure outages remain declared fixtures."""
    from tools.banking_sandbox.generator import generate

    output = Path(output)
    if output.exists():
        raise ValueError("fresh result path required")
    output.mkdir(parents=True, mode=0o700)
    cdx, spdx = validators()
    checks = []
    for kind, doc in [("malformed-sbom", {"bomFormat": "wrong"}), ("malformed-cbom", {"components": "invalid"})]:
        checks.append(
            {
                "case": kind,
                "actual_executed": True,
                "rejected": not cdx.is_valid(doc),
                "disposition": "FAILED_NOT_NO_CRYPTO",
            }
        )
    with tempfile.TemporaryDirectory(prefix="SYNTHETIC-hash-failure-") as tmp:
        root = Path(tmp) / "estate"
        generate(root, banks=1, profile="minimal")
        original = next((root / "public/source").rglob("*.py"))
        original.write_text("tampered SYNTHETIC evidence\n")
        try:
            integrity(root)
        except ValueError:
            rejected = True
        else:
            rejected = False
        checks.append(
            {
                "case": "corrupted-evidence",
                "actual_executed": True,
                "rejected": rejected,
                "disposition": "FAILED_NOT_NO_CRYPTO",
            }
        )
    result = {
        "executed_checks": checks,
        "all_rejected": all(c["rejected"] for c in checks),
        "database_redis_hsm_kms_cluster_outage_execution": "NOT_EXECUTED_DECLARED_FIXTURES_ONLY",
        "synthetic": True,
    }
    dump(output / "failure-report.json", result)
    return result


class PublicOnly(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def translate_path(self, path):
        rel = unquote(urlsplit(path).path).lstrip("/") or "index.html"
        root = Path(self.directory).resolve()
        candidate = root / rel
        if ".." in Path(rel).parts or candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return str(root / "FORBIDDEN-NONEXISTENT")
        return str(candidate)

    def list_directory(self, path):
        self.send_error(403, "Directory listing disabled")
        return None

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'",
        )
        super().end_headers()


def serve(root, host="127.0.0.1", port=8080):
    root, _ = open_estate(root)
    if host not in ("127.0.0.1", "0.0.0.0"):
        raise ValueError("only explicit local/preview dashboard binds allowed")
    # ONLY public fixtures. Never serve the estate root, oracle, results or private keys.
    server = http.server.ThreadingHTTPServer((host, port), partial(PublicOnly, directory=str(root / "public")))
    print(f"SYNTHETIC read-only dashboard on {host}:{port}", flush=True)
    server.serve_forever()
