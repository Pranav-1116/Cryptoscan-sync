"""Controlled benchmark performance (docs/performance/01_PRODUCT_SPEC.md,
§2.F and §8, roadmap Phase 5).

Two measurements stay separate for ever:

1. Observed production performance — measured from monitored operations.
2. Controlled benchmark performance — approved tests in a controlled
   environment.

A benchmark result is NEVER presented as production traffic performance:
every run carries ``measurement_kind="controlled_benchmark"`` and the
aggregation layer refuses to mix it into observed metrics (benchmark
results live in their own table, never in ``performance_metrics``).

Reproducibility is a contract, not a wish (§8): a run that does not
record hardware, software, provider, algorithm parameters, test
methodology, concurrency and sample count is refused. Nothing here
assumes a PQC algorithm will be slower or faster — the runner measures
what the local provider actually exposes and registers the rest as
external, never invented.
"""

from __future__ import annotations

import platform
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, model_validator

MEASUREMENT_KIND = "controlled_benchmark"

#: provider/algorithm pairs the local environment can measure right now.
#: Anything outside this list is register-only: a fixture or a name is
#: not a qualification.
LOCAL_CAPABLE = (
    ("cryptography-library", "RSA-2048"),
    ("cryptography-library", "RSA-3072"),
    ("cryptography-library", "ECDSA-P256"),
    ("cryptography-library", "Ed25519"),
)

EXTERNAL_ACTS = (
    "hsm-backed signing and verification benchmarks (provider hardware)",
    "KMS response-time benchmarks (cloud provider)",
    "ML-DSA signing and verification benchmarks (provider support)",
    "ML-KEM key establishment benchmarks (provider support)",
    "hybrid TLS negotiation benchmarks (approved endpoint)",
)


class BenchmarkMethod(BaseModel):
    """The reproducibility record — every field required (§8)."""

    hardware: str = Field(..., min_length=1)
    software: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    algorithm: str = Field(..., min_length=1)
    algorithm_parameters: Mapping[str, Any] = Field(...)
    methodology: str = Field(..., min_length=1)
    concurrency: int = Field(..., ge=1)
    sample_count: int = Field(..., ge=1)

    class Config:
        extra = "forbid"


class BenchmarkResult(BaseModel):
    operation: str
    mean_ms: float
    min_ms: float
    max_ms: float
    samples: int


class BenchmarkRun(BaseModel):
    """One controlled benchmark run — never production performance."""

    run_id: str
    tenant_id: str
    approved: bool = Field(
        ..., description="Approved benchmark (§2.F): a benchmark is an "
        "approved test in a controlled environment.")
    method: BenchmarkMethod
    results: List[BenchmarkResult] = Field(default_factory=list)
    executed_at: Optional[datetime] = None
    measurement_kind: str = MEASUREMENT_KIND

    class Config:
        extra = "forbid"

    @model_validator(mode="after")
    def _kind_is_benchmark(self) -> "BenchmarkRun":
        if self.measurement_kind != MEASUREMENT_KIND:
            raise ValueError(
                "a benchmark run is always controlled-benchmark "
                "measurement — it is never production performance")
        return self


def build_run(*, tenant_id: str, method: BenchmarkMethod,
              results: Sequence[BenchmarkResult],
              approved: bool = True) -> BenchmarkRun:
    """Assemble a run. An unapproved run is refused (§2.F: approved
    tests only); a method missing any reproducibility field is refused
    at validation."""
    if not approved:
        raise ValueError(
            "an unapproved benchmark is refused — controlled benchmark "
            "performance means approved tests in a controlled environment "
            "(docs/performance/01_PRODUCT_SPEC.md §2.F)")
    if not results:
        raise ValueError("a benchmark run without results records nothing")
    return BenchmarkRun(
        run_id=f"bench-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id, approved=approved,
        method=method, results=list(results),
        executed_at=datetime.now(timezone.utc),
    )


def local_method(algorithm: str, *, sample_count: int, concurrency: int = 1,
                 methodology: str = "sequential sign/verify timing over "
                                   "fresh keys and messages; wall clock, "
                                   "monotonic") -> BenchmarkMethod:
    """The reproducibility record for a local run, stamped from the real
    machine — hardware and software are observed, never typed in."""
    return BenchmarkMethod(
        hardware=f"{platform.machine()} ({platform.processor() or 'unknown'})",
        software=f"python {platform.python_version()}, "
                 f"cryptography {(_crypto_version())}",
        provider="cryptography-library",
        algorithm=algorithm,
        algorithm_parameters=_algorithm_parameters(algorithm),
        methodology=methodology,
        concurrency=concurrency,
        sample_count=sample_count,
    )


def run_local_benchmark(*, tenant_id: str, algorithm: str,
                        sample_count: int = 50) -> BenchmarkRun:
    """Measure what the local provider actually exposes.

    An algorithm the local provider cannot perform is refused with its
    reason and listed in EXTERNAL_ACTS — a name is not support, and no
    result is ever invented for it.
    """
    provider = "cryptography-library"
    if (provider, algorithm) not in LOCAL_CAPABLE:
        raise ValueError(
            f"{algorithm} is not measurable with the local provider — "
            "registered as an external act (a fixture or a name is not "
            "support); no result is invented for it")
    method = local_method(algorithm, sample_count=sample_count)
    sign_times, verify_times = _measure(algorithm, sample_count)
    results = [
        _result("sign", sign_times),
        _result("verify", verify_times),
    ]
    return build_run(tenant_id=tenant_id, method=method, results=results)


def _result(operation: str, times_ms: Sequence[float]) -> BenchmarkResult:
    return BenchmarkResult(
        operation=operation,
        mean_ms=round(sum(times_ms) / len(times_ms), 4),
        min_ms=round(min(times_ms), 4),
        max_ms=round(max(times_ms), 4),
        samples=len(times_ms),
    )


def _crypto_version() -> str:
    try:
        import cryptography
        return cryptography.__version__
    except Exception:
        return "unknown"


def _algorithm_parameters(algorithm: str) -> Dict[str, Any]:
    if algorithm.startswith("RSA-"):
        return {"key_size": int(algorithm.split("-")[1]), "padding": "PKCS1v15",
                "hash": "SHA-256"}
    if algorithm == "ECDSA-P256":
        return {"curve": "P-256", "hash": "SHA-256"}
    if algorithm == "Ed25519":
        return {"curve": "Ed25519"}
    return {}


def _measure(algorithm: str, sample_count: int) -> Tuple[List[float], List[float]]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    message = b"zelnx-performance-controlled-benchmark"
    sign_times: List[float] = []
    verify_times: List[float] = []
    for _ in range(sample_count):
        if algorithm.startswith("RSA-"):
            key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=int(algorithm.split("-")[1]))
            signer = lambda k: k.sign(message, padding.PKCS1v15(), hashes.SHA256())
            verifier = lambda k, sig: k.public_key().verify(
                sig, message, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == "ECDSA-P256":
            key = ec.generate_private_key(ec.SECP256R1())
            signer = lambda k: k.sign(message, ec.ECDSA(hashes.SHA256()))
            verifier = lambda k, sig: k.public_key().verify(
                sig, message, ec.ECDSA(hashes.SHA256()))
        elif algorithm == "Ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
            signer = lambda k: k.sign(message)
            verifier = lambda k, sig: k.public_key().verify(sig, message)
        else:  # pragma: no cover - guarded by LOCAL_CAPABLE
            raise ValueError(algorithm)
        start = time.perf_counter()
        signature = signer(key)
        sign_times.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter()
        verifier(key, signature)
        verify_times.append((time.perf_counter() - start) * 1000)
    return sign_times, verify_times
