"""Bounded per-operation measurements, not capacity predictions or container accounting.

SQL listeners record no SQL text/parameters. ContextVar isolation prevents an
engine shared by estates from cross-attributing query samples. Child/container
CPU, heap and network-provider metrics are deliberately NOT inferred here.
"""
from contextvars import ContextVar
from contextlib import contextmanager
import math
import sys
import threading
import time
import weakref

_active = ContextVar("workload_meter", default=None)
_installed = weakref.WeakSet()
_lock = threading.Lock()


def snapshot():
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF)
        return {"wall": time.perf_counter(), "cpu": r.ru_utime + r.ru_stime,
                "process_peak_rss_bytes": r.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                "read_blocks": r.ru_inblock, "write_blocks": r.ru_oublock}
    except (ImportError, OSError):
        return {"wall": time.perf_counter(), "cpu": None, "process_peak_rss_bytes": None,
                "read_blocks": None, "write_blocks": None}


class WorkloadMeter:
    def __init__(self):
        self.stage = None
        self.started = snapshot()
        self.stages = []
        self.query_ms = []
        self.query_count = 0
        self.query_total_ms = 0.0
        self.query_max_ms = None
        self.stage_query_count = 0
        self.stage_query_ms = 0.0

    def query(self, elapsed_ms):
        self.query_count += 1
        self.query_total_ms += elapsed_ms
        self.query_max_ms = max(self.query_max_ms or 0, elapsed_ms)
        if len(self.query_ms) < 512:
            self.query_ms.append(elapsed_ms)
        self.stage_query_count += 1
        self.stage_query_ms += elapsed_ms

    def transition(self, stage, final=False):
        end = snapshot()
        if self.stage is not None and len(self.stages) < 32:
            self.stages.append({"stage": self.stage, "wall_seconds": max(0, end["wall"] - self.started["wall"]),
                "process_cpu_seconds": max(0, end["cpu"] - self.started["cpu"]) if end["cpu"] is not None and self.started["cpu"] is not None else None,
                "process_peak_rss_bytes": end["process_peak_rss_bytes"],
                "read_blocks": end["read_blocks"] - self.started["read_blocks"] if end["read_blocks"] is not None else None,
                "write_blocks": end["write_blocks"] - self.started["write_blocks"] if end["write_blocks"] is not None else None,
                "db_query_count": self.stage_query_count, "db_cursor_ms": self.stage_query_ms})
        self.stage = None if final else stage
        self.started = end
        self.stage_query_count = 0
        self.stage_query_ms = 0.0

    def report(self):
        samples = sorted(self.query_ms)
        return {"schema": "cryptoscan.workload-measurement/1", "stages": list(self.stages),
                "db_query_count": self.query_count, "db_cursor_total_ms": self.query_total_ms,
                "db_cursor_max_ms": self.query_max_ms,
                "db_sample_p95_ms": samples[max(0, math.ceil(len(samples) * .95) - 1)] if samples else None,
                "db_samples": len(samples), "db_samples_truncated": self.query_count > len(samples),
                "limits": ["Process-wide CPU and high-water RSS, not isolated stage/container memory",
                    "Block I/O counters are not bytes, filesystem growth or retained evidence allocation",
                    "DB cursor timings exclude pool wait, ORM materialization and remote server attribution",
                    "Provider throttling, replay recovery and browser endurance require separate measured workloads"],
                "capacity_qualified": False}


def install(engine):
    from sqlalchemy import event
    with _lock:
        if engine in _installed:
            return
        def before(conn, cursor, statement, parameters, context, executemany):
            meter = _active.get()
            if meter is not None:
                context._cryptoscan_measurement = (meter, time.perf_counter())
        def after(conn, cursor, statement, parameters, context, executemany):
            sample = getattr(context, "_cryptoscan_measurement", None)
            if sample:
                sample[0].query((time.perf_counter() - sample[1]) * 1000)
        def failed(context):
            execution = context.execution_context
            sample = getattr(execution, "_cryptoscan_measurement", None)
            if sample:
                sample[0].query((time.perf_counter() - sample[1]) * 1000)
        event.listen(engine, "before_cursor_execute", before)
        event.listen(engine, "after_cursor_execute", after)
        event.listen(engine, "handle_error", failed)
        _installed.add(engine)


@contextmanager
def measure(engine):
    install(engine)
    meter = WorkloadMeter()
    token = _active.set(meter)
    try:
        yield meter
    finally:
        _active.reset(token)
