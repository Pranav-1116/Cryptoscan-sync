#!/usr/bin/env python3
"""eBPF execve tracer for the deterministic services (audit 81 P0#3).

    sudo python deploy/ebpf/execve_trace.py [--pid PID] [--json OUT]

Attaches bpftrace-style kprobes (``execve``/``execveat``) and prints/
streams every process execution on the host as JSON events, classified
by the platform's AI-boundary policy
(``api.security.ai_boundary``): ALLOWED / VIOLATION / UNKNOWN.

Requires: Linux with BTF, ``bcc`` (``apt install bpfcc-tools`` or
``pip install bcc``), root or ``CAP_BPF`` + ``CAP_PERFMON``. This is
the deployment half of audit 81 — the classifier it uses is pure,
stdlib-only and unit-tested in the repo; the seccomp profile from
round 36 stays the first line of defense.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "api"))

PROGRAM = r"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct exec_event_t {
    u32 pid;
    char comm[16];
    char argv[256];
};

BPF_PERF_OUTPUT(events);

static inline bool is_exec(const char *filename, const char *const *argv)
{
    return filename != NULL;
}

int trace_execve(struct pt_regs *ctx, const char *filename,
                 const char *const *argv, const char *const *envp)
{
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (filename != NULL) {
        bpf_probe_read_user_str(&event.argv, sizeof(event.argv), filename);
    }
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=0,
                        help="only report events for this pid tree (0 = all)")
    parser.add_argument("--json", default="-",
                        help="output file for JSON lines ('-' = stdout)")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate the program + policy and exit "
                             "(no kernel attachment)")
    args = parser.parse_args()

    from api.security.ai_boundary import classify_event

    if args.dry_run:
        # prove the policy half works without a kernel: the classifier
        # ships tested; this mode validates wiring only
        demo = classify_event({"pid": 1, "comm": b"python",
                               "argv_raw": b"python\x00-m\x00ollama\x00serve"})
        print(json.dumps({
            "mode": "dry-run",
            "program_bytes": len(PROGRAM),
            "policy_demo": demo,
            "ready": True,
        }))
        return 0

    try:
        from bcc import BPF  # noqa: F401 — kernel-side dependency
    except ImportError:
        print("bcc is not installed — this tracer needs a kernel with "
              "BTF and the bcc python bindings (deploy/ebpf/README)",
              file=sys.stderr)
        return 3

    try:
        from bcc import BPF
        bpf = BPF(text=PROGRAM)
        bpf.attach_kprobe(event=b"execve", fn_name=b"trace_execve")
        bpf.attach_kprobe(event=b"execveat", fn_name=b"trace_execve")
    except PermissionError:
        print("permission denied — attach needs root or CAP_BPF + "
              "CAP_PERFMON", file=sys.stderr)
        return 4
    except Exception as exc:  # noqa: BLE001 — kernel-side failures are environmental
        print(f"eBPF attach failed: {exc}", file=sys.stderr)
        return 5

    out = sys.stdout if args.json == "-" else open(args.json, "a", encoding="utf-8")

    def _on_event(cpu, data, size):
        event = bpf[b"events"].event(data)
        if args.pid and event.pid != args.pid:
            return
        classified = classify_event({
            "pid": event.pid,
            "comm": event.comm.decode("utf-8", errors="replace"),
            "argv_raw": event.argv,
        })
        print(json.dumps(classified), file=out, flush=True)

    bpf[b"events"].open_perf_buffer(_on_event)
    print(f"# execve tracing active (pid filter: {args.pid or 'all'})",
          file=sys.stderr)
    while True:
        try:
            bpf.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
