"""Fresh script processes must have the same import surface as run_worker.sh."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]


def test_canonical_bootstrap_discovers_every_service_and_shared_package():
    script = """
import sys
sys.path.insert(0, 'scripts')
from _bootstrap import ROOT, bootstrap, path_entries
expected = {str(p) for group in ('services', 'shared') for p in (ROOT / group).iterdir() if p.is_dir()}
assert set(path_entries()) == expected | {str(ROOT)}
bootstrap()
bootstrap()
assert all(sys.path.count(p) == 1 for p in path_entries())
from devsecops.software_identity import sbom_components
from api.main import create_app
from worker.main import Worker
"""
    environment = {**os.environ, "PYTHONPATH": "", "ENVIRONMENT": "test", "REDIS_URL": ""}
    result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
