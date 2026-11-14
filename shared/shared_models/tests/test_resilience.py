"""Fault-tolerance primitives: breaker probe discipline, bounded retries,
counted bulkheads, and honest deadlines."""

from __future__ import annotations

import threading

import pytest

from shared_models.resilience import (
    Bulkhead, CircuitBreaker, CircuitOpenError,
    call_with_deadline, retry_with_backoff,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestCircuitBreaker:

    def test_it_opens_after_the_threshold_and_refuses(self):
        clock = FakeClock()
        breaker = CircuitBreaker("webhook", failure_threshold=3,
                                 recovery_timeout=60, clock=clock)
        for _ in range(2):
            breaker.record_failure()
            assert breaker.state == "closed"
        breaker.record_failure()
        assert breaker.state == "open"
        # Both refusal paths count: the dispatcher-style is_open check (the
        # drop-in contract) and a call() turned away — every refused piece of
        # traffic is counted, never silently dropped.
        assert breaker.is_open is True
        with pytest.raises(CircuitOpenError):
            breaker.call(lambda: "never runs")
        assert breaker.as_dict()["refused_total"] == 2

    def test_half_open_after_the_recovery_timeout_and_reopens_on_a_failed_probe(self):
        clock = FakeClock()
        breaker = CircuitBreaker("webhook", failure_threshold=1,
                                 recovery_timeout=60, success_threshold=2,
                                 clock=clock)
        breaker.record_failure()
        assert breaker.is_open is True
        clock.advance(61)
        assert breaker.state == "half-open"
        # One failed probe reopens immediately — the dependency is still down.
        breaker.record_failure()
        assert breaker.state == "open"

    def test_half_open_needs_success_threshold_consecutive_successes(self):
        clock = FakeClock()
        breaker = CircuitBreaker("webhook", failure_threshold=1,
                                 recovery_timeout=60, success_threshold=2,
                                 clock=clock)
        breaker.record_failure()
        clock.advance(61)
        assert breaker.state == "half-open"
        breaker.record_success()
        assert breaker.state == "half-open"  # one probe is not proof
        breaker.record_success()
        assert breaker.state == "closed"

    def test_call_records_outcomes_both_ways(self):
        clock = FakeClock()
        breaker = CircuitBreaker("webhook", failure_threshold=2, clock=clock)
        assert breaker.call(lambda: "ok") == "ok"
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("boom")))
        assert breaker.as_dict()["failure_count"] == 1
        breaker.call(lambda: "ok")
        assert breaker.as_dict()["failure_count"] == 0

    def test_thresholds_must_be_real(self):
        with pytest.raises(ValueError):
            CircuitBreaker("bad", failure_threshold=0)
        with pytest.raises(ValueError):
            CircuitBreaker("bad", recovery_timeout=0)

    def test_as_dict_names_the_next_probe(self):
        clock = FakeClock()
        breaker = CircuitBreaker("webhook", failure_threshold=1,
                                 recovery_timeout=30, clock=clock)
        breaker.record_failure()
        body = breaker.as_dict()
        assert body["state"] == "open"
        assert 0 < body["next_probe_in_seconds"] <= 30
        assert body["recovery_timeout_seconds"] == 30

    def test_concurrent_failures_open_exactly_once(self):
        breaker = CircuitBreaker("webhook", failure_threshold=50)
        threads = [threading.Thread(target=breaker.record_failure)
                   for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert breaker.state == "open"
        assert breaker.as_dict()["failure_count"] == 50


class TestRetryWithBackoff:

    def test_transient_failures_are_retried_then_succeed(self):
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) < 3:
                raise ConnectionError("blip")
            return "ok"

        slept = []
        ok, value, error = retry_with_backoff(
            flaky, retries=3, base_delay=0.1, jitter=0.0,
            sleep=slept.append)
        assert (ok, value, error) == (True, "ok", None)
        assert len(attempts) == 3
        assert slept == [0.1, 0.2]  # exponential, deterministic without jitter

    def test_retries_are_bounded_and_the_last_error_survives(self):
        attempts = []

        def always_down():
            attempts.append(1)
            raise ConnectionError("still down")

        ok, value, error = retry_with_backoff(
            always_down, retries=2, jitter=0.0, sleep=lambda _s: None)
        assert ok is False and value is None
        assert isinstance(error, ConnectionError)
        assert len(attempts) == 3  # the first try + two retries

    def test_a_permanent_error_is_never_retried(self):
        attempts = []

        def broken():
            attempts.append(1)
            raise ValueError("permanent")

        ok, _value, error = retry_with_backoff(
            broken, retries=5, jitter=0.0, sleep=lambda _s: None,
            is_retryable=lambda exc: isinstance(exc, ConnectionError))
        assert ok is False and isinstance(error, ValueError)
        assert len(attempts) == 1

    def test_backoff_respects_max_delay(self):
        slept = []

        def down():
            raise ConnectionError("x")

        retry_with_backoff(down, retries=8, base_delay=1.0, max_delay=2.0,
                           jitter=0.0, sleep=slept.append)
        assert all(delay <= 2.0 for delay in slept)


class TestBulkhead:

    def test_overload_refuses_and_counts(self):
        bulkhead = Bulkhead("notifier", max_concurrent=1, max_wait=0.0)
        assert bulkhead.acquire() is True
        assert bulkhead.acquire() is False  # full — refuse, never queue unbounded
        body = bulkhead.as_dict()
        assert body["refused_total"] == 1 and body["in_flight"] == 1
        bulkhead.release()
        assert bulkhead.acquire() is True  # release frees capacity
        assert bulkhead.as_dict()["completed_total"] == 1

    def test_limits_must_be_real(self):
        with pytest.raises(ValueError):
            Bulkhead("bad", max_concurrent=0)

    def test_concurrent_users_never_exceed_the_limit(self):
        bulkhead = Bulkhead("notifier", max_concurrent=2, max_wait=0.0)
        acquired = []

        def worker():
            if bulkhead.acquire():
                acquired.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(acquired) == 2
        assert bulkhead.as_dict()["refused_total"] == 6


class TestDeadline:

    def test_a_fast_call_returns_its_value(self):
        ok, value, error = call_with_deadline(lambda: 42, seconds=5)
        assert (ok, value, error) == (True, 42, None)

    def test_a_slow_call_is_abandoned_with_an_honest_timeout(self):
        ok, value, error = call_with_deadline(
            lambda: threading.Event().wait(30), seconds=0.05, name="slow-scan")
        assert ok is False and value is None
        assert isinstance(error, TimeoutError)
        # The honesty the contract names: we stopped waiting, we did not kill.
        assert "cannot be killed" in str(error)

    def test_a_failing_call_forwards_the_error(self):
        def boom():
            raise ValueError("inside")

        ok, value, error = call_with_deadline(boom, seconds=5)
        assert ok is False and value is None
        assert isinstance(error, ValueError)

    def test_the_deadline_must_be_positive(self):
        with pytest.raises(ValueError):
            call_with_deadline(lambda: None, seconds=0)
