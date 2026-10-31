"""Retry policy for a failed job: what may be retried, and what must not.

Before this module, a handler that raised was logged, reported ``False`` and
**acknowledged**. The queue retried work lost with a worker, never work that
*failed* — so a transient collector error (a connection reset, a DNS hiccup, a
pool timeout) was indistinguishable from a permanent refusal, and both were a
lost observation. That is the wrong failure mode for a bank's evidence pipeline:
the honest answer to "the collector timed out" is "try again in a minute", not
"mark it failed and move on".

Two rules make the retry safe rather than merely present:

**Only failures we can name as transient are retried.** ``classify`` reads the
exception type, so a ``ValueError`` from a malformed payload is terminal — a
retry would just fail identically three times and delay the operator finding
out. Unknown exceptions are terminal by default: retrying something we do not
understand multiplies an incident instead of reporting it.

**A job under controlled execution is never retried automatically.** Those jobs
carry an approval, a lease and a fence; an attempt that failed may already have
spent a request against the approval and left a row an operator must reconcile.
Re-running it from the queue would bypass the reconciliation path that exists
for exactly this case. ``decide(controlled=True)`` refuses — and says so.

The delay is exponential with jitter, capped, so N failing jobs do not return
to the queue in lockstep and turn a blip into a thundering herd.
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass
from typing import Any, Callable

#: exception types whose cause is a transient transport/runtime condition
RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ConnectionError,          # includes ConnectionResetError, ConnectionAbortedError, BrokenPipeError
    TimeoutError,             # includes socket.timeout on 3.10+
    BlockingIOError,
)

#: named permanent refusals — retrying these is a policy error, not a delay
TERMINAL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    PermissionError,
    FileNotFoundError,
    NotImplementedError,
)

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_SECONDS = 30.0
DEFAULT_MAX_SECONDS = 600.0
DEFAULT_JITTER = 0.25

logger = logging.getLogger(__name__)

RETRY = "RETRY"
DEAD_LETTER = "DEAD_LETTER"
NEVER = "NEVER"


@dataclass(frozen=True)
class RetryDecision:
    action: str            # RETRY | DEAD_LETTER | NEVER
    reason: str
    attempt: int           # the attempt that just failed (1-based)
    max_attempts: int
    delay_seconds: float   # 0 when there is no retry

    @property
    def retry(self) -> bool:
        return self.action == RETRY

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "delay_seconds": round(self.delay_seconds, 3),
        }


def _sqlalchemy_retryable(exc: BaseException) -> bool | None:
    """A DB error is retryable only when the connection itself is in trouble."""
    module = type(exc).__module__ or ""
    if not module.startswith("sqlalchemy"):
        return None
    name = type(exc).__name__
    if name in {"OperationalError", "InterfaceError", "DisconnectionError"}:
        # A syntax error is an OperationalError too, but the message says so;
        # a retry would repeat it exactly.
        text = str(exc).lower()
        if "syntax error" in text or "does not exist" in text or "undefined column" in text:
            return False
        return True
    return False


def classify(exc: BaseException) -> tuple[bool, str]:
    """``(retryable, why)`` for one failure. Unknown means terminal, deliberately."""
    sqlalchemy = _sqlalchemy_retryable(exc)
    if sqlalchemy is not None:
        if sqlalchemy:
            return True, f"transient database error ({type(exc).__name__})"
        return False, f"database error that a retry would repeat ({type(exc).__name__})"
    if isinstance(exc, TERMINAL_EXCEPTIONS):
        return False, f"permanent failure ({type(exc).__name__})"
    if isinstance(exc, RETRYABLE_EXCEPTIONS):
        return True, f"transient failure ({type(exc).__name__})"
    return False, f"unrecognised failure ({type(exc).__name__}) is terminal, not retried blindly"


def backoff_seconds(
    attempt: int,
    *,
    base: float = DEFAULT_BASE_SECONDS,
    cap: float = DEFAULT_MAX_SECONDS,
    jitter: float = DEFAULT_JITTER,
    rng: random.Random | None = None,
) -> float:
    """Exponential backoff with bounded jitter: ``base * 2**(attempt-1)``, capped.

    Jitter is a *decrease* of up to ``jitter`` fraction, so the delay never
    exceeds the cap and a retry never fires earlier than half the nominal wait.
    """
    attempt = max(1, int(attempt))
    nominal = min(float(cap), float(base) * (2 ** (attempt - 1)))
    spread = max(0.0, min(0.9, float(jitter)))
    source = rng or random
    return max(0.0, nominal * (1.0 - spread * source.random()))


def decide(
    *,
    exc: BaseException | None = None,
    attempt: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    controlled: bool = False,
    failure_reason: str | None = None,
) -> RetryDecision:
    """Decide what to do with a failed job.

    ``attempt`` is the number of attempts already made (0 for the first run).
    ``controlled`` marks a job under controlled execution (approval + lease +
    fence): those are never retried here.
    """
    used = max(0, int(attempt)) + 1
    if controlled:
        return RetryDecision(
            NEVER,
            "controlled execution: the attempt already holds an approval/lease and an operator "
            "must reconcile it; re-queuing would bypass that path",
            used, int(max_attempts), 0.0,
        )
    if exc is not None:
        retryable, why = classify(exc)
    else:
        retryable, why = True, failure_reason or "handler reported failure without an exception"
    if not retryable:
        return RetryDecision(DEAD_LETTER, why, used, int(max_attempts), 0.0)
    if used >= int(max_attempts):
        return RetryDecision(
            DEAD_LETTER,
            f"{why}; giving up after {used} attempts",
            used, int(max_attempts), 0.0,
        )
    return RetryDecision(
        RETRY,
        f"{why}; retrying (attempt {used + 1} of {max_attempts})",
        used, int(max_attempts), backoff_seconds(used),
    )


def retry_payload(job: Any) -> dict[str, Any]:
    """The job as it should go back on the queue: original payload, attempts kept.

    ``job.raw`` is the exact string Redis holds, so the retry carries every
    field the first delivery had — including fields this worker does not read —
    instead of a reconstruction that silently drops one.
    """
    raw = getattr(job, "raw", None)
    if raw:
        try:
            return dict(json.loads(raw))
        except (TypeError, ValueError):  # pragma: no cover — a corrupt payload is rebuilt below
            pass
    return {
        "job_id": job.job_id,
        "scan_id": getattr(job, "scan_id", None),
        "target_repo": job.target_repo,
        "target_branch": job.target_branch,
        "target_commit": getattr(job, "target_commit", None),
        "triggered_by": job.triggered_by,
        "job_type": getattr(job, "job_type", "MANUAL"),
        "system_id": getattr(job, "system_id", None),
        "tenant_id": getattr(job, "tenant_id", None),
        "progress": dict(getattr(job, "progress", None) or {}),
    }


def handle_failure(
    *,
    consumer: Any,
    job: Any,
    exc: BaseException | None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    fail_row: Callable[[str, str], None] | None = None,
) -> RetryDecision:
    """Apply the policy to one failed job: retry it, or dead-letter it once.

    Returns the decision so the caller (or a test) can see why. Nothing here
    raises on a scheduling failure: the job has already failed, and turning a
    failed job into a crashed worker would be a second, worse failure.
    """
    controlled = bool((getattr(job, "progress", None) or {}).get("execution_control"))
    decision = decide(exc=exc, attempt=int(getattr(job, "attempts", 0) or 0),
                      max_attempts=max_attempts, controlled=controlled)
    body = retry_payload(job)
    body["_attempts"] = decision.attempt

    if decision.action == NEVER:
        logger.warning("job_retry_refused", extra={"job_id": job.job_id, "reason": decision.reason})
        return decision

    if decision.retry:
        try:
            consumer.enqueue_delayed(body, decision.delay_seconds)
        except Exception as schedule_exc:  # noqa: BLE001
            logger.error("job_retry_enqueue_failed",
                         extra={"job_id": job.job_id, "error": str(schedule_exc)})
            return RetryDecision(DEAD_LETTER,
                                 f"{decision.reason}; the retry could not be scheduled: {schedule_exc}",
                                 decision.attempt, decision.max_attempts, 0.0)
        logger.warning("job_retry_scheduled", extra={"job_id": job.job_id, **decision.as_dict()})
        return decision

    # Terminal, or out of attempts.
    try:
        if getattr(consumer, "redis_client", None) is not None:
            consumer.redis_client.rpush(consumer.dead_letter_key, json.dumps(body, default=str))
    except Exception:  # noqa: BLE001
        logger.exception("job_dead_letter_push_failed", extra={"job_id": job.job_id})
    if fail_row is not None:
        try:
            fail_row(str(job.job_id), decision.reason)
        except Exception:  # noqa: BLE001
            logger.exception("job_fail_row_failed", extra={"job_id": job.job_id})
    if getattr(consumer, "on_dead_letter", None):
        try:
            consumer.on_dead_letter(body, decision.reason)
        except Exception:  # noqa: BLE001
            logger.exception("dead_letter_callback_failed")
    logger.error("job_dead_lettered_after_failure", extra={"job_id": job.job_id, **decision.as_dict()})
    return decision
