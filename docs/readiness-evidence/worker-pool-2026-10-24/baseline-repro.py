"""Run six expected-failing regressions against the prior published pool only.

Does not checkout/reset/edit production source or contact a deployment. Exit 1
is EXPECTED for this historical reproduction, not the final implementation gate.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()

import worker.core.pool as pool_module
import pytest

BASELINE = "2f9551b02a2601affd100e558c7a4b1afbdba184"
source = subprocess.check_output(["git", "show", BASELINE + ":services/worker/worker/core/pool.py"],
                                 cwd=ROOT, text=True)
exec(compile(source, "<published-baseline-pool-2f9551b0>", "exec"), pool_module.__dict__)
TEST = "services/worker/tests/unit/test_worker_pool_retention.py::"
raise SystemExit(pytest.main(["-q", *[TEST + name for name in (
    "test_completed_futures_are_not_retained_across_batches",
    "test_cancelled_queued_future_returns_its_capacity_without_running",
    "test_snapshot_cannot_mutate_pool_tracking",
    "test_negative_queue_limits_are_rejected_instead_of_stalling",
    "test_raising_done_callback_does_not_leak_pool_capacity",
)]]))
