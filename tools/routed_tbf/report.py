"""Fail-closed deterministic qualification. Not production device authentication."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from tools.routed_tbf.guest import clean, owned, fingerprint

HERE = Path(__file__).resolve().parent
GATES = json.loads((HERE / "acceptance.json").read_text())
MATRIX = [
    ("udp_baseline", "udp", 1200, 1, 5, None),
    ("tcp_baseline", "tcp", 1200, 4, 5, None),
    ("udp_10", "udp", 1200, 1, 1, 10),
    ("udp_5", "udp", 1200, 1, 1, 5),
    ("udp_small_burst", "udp", 256, 1, 16, 10),
    ("udp_large_burst", "udp", 1400, 1, 16, 10),
    ("tcp_one_10", "tcp", 1200, 1, 1, 10),
    ("tcp_four_10", "tcp", 1200, 4, 1, 10),
    ("tcp_four_5", "tcp", 1200, 4, 1, 5),
    ("udp_recovered", "udp", 1200, 1, 5, None),
    ("tcp_recovered", "tcp", 1200, 4, 5, None),
]
FAULTS = {
    "controller_crash": "RECOVERED",
    "lost_connection": "RECOVERED",
    "expired_authorization": "RECOVERED",
    "interface_recreation": "REFUSED_IDENTITY_CHANGED",
    "policy_conflict": "REFUSED_POLICY_CONFLICT",
}
NEGATIVES = [
    "existing_class_filter_tree",
    "existing_clsact_filter",
    "management_interface_target",
    "unapproved_management_set",
    "policy_routing_ambiguity",
    "multipath_management_route",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Latency(Strict):
    planned: int = Field(ge=1, le=4800)
    sent: int = Field(ge=0)
    received: int = Field(ge=0)
    missed_schedule: int = Field(ge=0)
    errors: int = Field(ge=0)
    p95_ms: float = Field(ge=0)
    p99_ms: float = Field(ge=0)


class Sender(Strict):
    flow_bytes: list[int]
    successful_sends: int = Field(ge=0)
    sent_bytes_window: int = Field(ge=0)
    attempts: int = Field(ge=0)
    backpressure: int = Field(ge=0)
    errors: int = Field(ge=0)
    tcp_total_retransmissions: int = Field(ge=0)


class Receiver(Strict):
    bytes: int = Field(ge=0)
    packets: int = Field(ge=0)
    total_received: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    invalid: int = Field(ge=0)
    errors: int = Field(ge=0)
    elapsed_ns: int = Field(ge=10_000_000_000, le=10_000_000_000)


class Phase(Strict):
    label: str
    protocol: Literal["udp", "tcp"]
    payload: int
    flows: int
    burst_packets: int
    rate_mbps: int | None
    preflight: dict
    applied: list[dict]
    after: list[dict]
    restored: list[dict]
    sender: Sender
    receiver: Receiver
    data_latency: Latency
    management: Latency
    started_ns: int = Field(gt=0)
    finished_ns: int = Field(gt=0)
    ifindex: int = Field(gt=0)


class Capture(Strict):
    schema_version: Literal["cryptoscan.routed-tbf-guest/v1"]
    nonce: str = Field(pattern="^[a-f0-9]{64}$")
    kernel: Literal["6.12.58-cryptoscan-routed-tbf"]
    topology: dict
    phases: list[Phase] = Field(min_length=11, max_length=11)
    faults: list[dict] = Field(min_length=5, max_length=5)
    negative_cases: list[dict] = Field(min_length=6, max_length=6)
    unrelated_before: list[dict]
    unrelated_after: list[dict]
    management_policy_before: list[dict]
    management_policy_after: list[dict]
    final_policy: list[dict]
    finished_ns: int = Field(gt=0)


def preflight_blockers(c):
    out = []
    if c["target"] != "ge" or c["destinations"] != ["10.78.1.2"]:
        out.append("UNAPPROVED_TARGET_OR_MANAGEMENT_SET")
    if not clean(c["qdisc"]) or any(c[k] for k in ("class", "filter", "ingress_filters", "egress_filters")):
        out.append("EXISTING_POLICY_OR_FILTER")
    if [(r.get("priority"), r.get("table")) for r in c["rules"]] != [(0, "local"), (32766, "main"), (32767, "default")]:
        out.append("UNSUPPORTED_POLICY_ROUTING")
    if any("nexthops" in r or r.get("type") in ("blackhole", "unreachable", "prohibit") for r in c["routes"]):
        out.append("AMBIGUOUS_OR_UNSUPPORTED_ROUTE")
    if any(
        len(r) != 1 or r[0].get("dev") != "gm" or r[0].get("gateway") or r[0].get("nexthops")
        for r in c["management_routes"]
    ):
        out.append("MANAGEMENT_PATH_NOT_EXCLUDED")
    if len(c["management_routes"]) != len(c["destinations"]):
        out.append("MANAGEMENT_ROUTE_COUNT")
    return out


def latency_valid(row, management=False):
    if not (
        0 <= row.received <= row.sent <= row.planned
        and row.sent + row.missed_schedule <= row.planned
        and row.p95_ms <= row.p99_ms
        and (row.received > 0 or row.p99_ms == 0)
    ):
        return False
    if management:
        return (
            row.received / row.planned >= GATES["management_delivery_min"]
            and row.errors == 0
            and row.p95_ms <= GATES["management_p95_max_ms"]
            and row.p99_ms <= GATES["management_p99_max_ms"]
        )
    return row.received > 0 and row.errors == 0


def report(raw):
    cap = Capture.model_validate(raw)
    blockers, summaries = [], []

    def gate(ok, reason):
        if not ok:
            blockers.append(reason)

    expected_addresses = {
        "tx": ("s0", "10.77.1.2"),
        "gw": ("ge", "10.77.2.1"),
        "rx": ("r0", "10.77.2.2"),
        "mgmt": ("m0", "10.78.1.2"),
    }
    gate(set(cap.topology) == set(expected_addresses), "TOPOLOGY_NAMESPACES")
    for namespace, (dev, address) in expected_addresses.items():
        rows = cap.topology.get(namespace, [])
        expected_names = {"lo", "gi", "ge", "gm"} if namespace == "gw" else {"lo", dev}
        gate(
            {r["ifname"] for r in rows} == expected_names
            and any(
                r["ifname"] == dev and any(a.get("local") == address for a in r.get("addr_info", [])) for r in rows
            ),
            "TOPOLOGY_" + namespace,
        )
    for i, p in enumerate(cap.phases):
        prefix = p.label + ":"
        gate((p.label, p.protocol, p.payload, p.flows, p.burst_packets, p.rate_mbps) == MATRIX[i], prefix + "MATRIX")
        gate(
            not preflight_blockers(p.preflight)
            and p.preflight["allowed"] is True
            and not p.preflight["blockers"]
            and p.ifindex == p.preflight["ifindex"],
            prefix + "PREFLIGHT",
        )
        gate(p.finished_ns - p.started_ns >= 11_500_000_000, prefix + "TIMING")
        if i:
            gate(p.started_ns > cap.phases[i - 1].finished_ns, prefix + "PHASE_ORDER")
        s, r = p.sender, p.receiver
        gate(
            s.attempts == s.successful_sends + s.backpressure + s.errors
            and s.errors == 0
            and r.errors == r.invalid == r.duplicates == 0
            and len(s.flow_bytes) == p.flows
            and all(v > 0 for v in s.flow_bytes)
            and s.sent_bytes_window <= sum(s.flow_bytes),
            prefix + "DENOMINATORS",
        )
        if p.protocol == "udp":
            gate(
                sum(s.flow_bytes) == s.successful_sends * p.payload
                and r.bytes == r.packets * p.payload
                and r.packets <= r.total_received <= s.successful_sends
                and s.tcp_total_retransmissions == 0,
                prefix + "UDP_DENOMINATORS",
            )
            loss = (s.successful_sends - r.total_received) / s.successful_sends if s.successful_sends else None
        else:
            gate(r.packets == 0 and r.bytes <= r.total_received <= sum(s.flow_bytes), prefix + "TCP_DENOMINATORS")
            loss = None
        mbps = r.bytes * 8000 / r.elapsed_ns
        gate(latency_valid(p.management, True) and p.management.planned == 240, prefix + "MANAGEMENT")
        gate(latency_valid(p.data_latency) and p.data_latency.planned == 240, prefix + "DATA_LATENCY")
        gate(clean(p.restored), prefix + "ROLLBACK")
        if p.rate_mbps:
            band = GATES["udp_fraction" if p.protocol == "udp" else "tcp_fraction"]
            gate(band[0] * p.rate_mbps <= mbps <= band[1] * p.rate_mbps, prefix + "THROUGHPUT")
            gate(
                owned(p.applied, p.rate_mbps)
                and owned(p.after, p.rate_mbps)
                and fingerprint(p.applied) == fingerprint(p.after),
                prefix + "QDISC",
            )
            if p.after and p.applied:
                after, before = p.after[0], p.applied[0]
                gate(
                    after.get("bytes", 0) - before.get("bytes", 0) >= r.bytes
                    and after.get("packets", 0) - before.get("packets", 0) >= (r.packets if p.protocol == "udp" else 1)
                    and after.get("overlimits", 0) > before.get("overlimits", 0),
                    prefix + "COUNTERS",
                )
        else:
            gate(clean(p.applied) and clean(p.after) and mbps >= GATES["baseline_min_mbps"], prefix + "HEADROOM")
            gate(s.backpressure == 0, prefix + "UNSHAPED_BACKPRESSURE")
        summaries.append(
            {
                "label": p.label,
                "received_payload_mbps": mbps,
                "udp_loss_fraction_including_warmup_and_drain": loss,
                "tcp_total_retransmissions": s.tcp_total_retransmissions,
                "data_latency": p.data_latency.model_dump(),
                "management": p.management.model_dump(),
                "kernel_drops": p.after[0].get("drops"),
            }
        )
    for protocol, base, recovered in [("udp", 0, 9), ("tcp", 1, 10)]:
        b, r = summaries[base]["received_payload_mbps"], summaries[recovered]["received_payload_mbps"]
        gate(
            r >= max(GATES["recovery_min_mbps"], GATES["recovery_baseline_fraction"] * b),
            protocol + ":RECOVERY_THROUGHPUT",
        )
    gate([n["case"] for n in cap.negative_cases] == NEGATIVES, "NEGATIVE_MATRIX")
    for n in cap.negative_cases:
        c = n["preflight"]
        expected = preflight_blockers(c)
        gate(
            bool(expected) and c["allowed"] is False and c["blockers"] == expected and n["policy_preserved"] is True,
            n["case"] + ":REFUSAL_OR_PRESERVATION",
        )
    gate([f["case"] for f in cap.faults] == list(FAULTS), "FAULT_MATRIX")
    refusals = []
    for f in cap.faults:
        gate(
            f["watchdog"]["status"] == FAULTS.get(f["case"])
            and 0 <= f["response_seconds"] <= GATES["recovery_deadline_seconds"]
            and abs((f["watchdog"]["finished"] - f["injected"]) - f["response_seconds"]) < 0.001,
            f["case"] + ":WATCHDOG_RESPONSE",
        )
        gate(
            latency_valid(Latency.model_validate(f["management"]), True) and f["management"]["planned"] == 60,
            f["case"] + ":MANAGEMENT",
        )
        if f["case"] in ("interface_recreation", "policy_conflict"):
            gate(
                f["foreign_before"] is not None
                and f["foreign_after"] is not None
                and fingerprint(f["foreign_before"]) == fingerprint(f["foreign_after"])
                and fingerprint(f["watchdog"]["policy"]) == fingerprint(f["foreign_before"]),
                f["case"] + ":FOREIGN_PRESERVATION",
            )
            gate(
                (f["watchdog"]["ifindex"] != f["state"]["ifindex"]) == (f["case"] == "interface_recreation"),
                f["case"] + ":IDENTITY",
            )
            refusals.append({"case": f["case"], "recovery": "REFUSED_NOT_RECOVERED", "policy_preserved": True})
        else:
            probe = Phase.model_validate(f["recovery_probe"])
            gate(
                probe.receiver.bytes * 8000 / probe.receiver.elapsed_ns
                >= max(30, 0.8 * summaries[0]["received_payload_mbps"])
                and clean(probe.applied)
                and clean(probe.restored)
                and latency_valid(probe.management, True)
                and probe.sender.errors == probe.receiver.errors == probe.receiver.invalid == 0,
                f["case"] + ":POST_RECOVERY_TRAFFIC",
            )
            gate(
                clean(f["watchdog"]["policy"]) and f["watchdog"]["ifindex"] == f["state"]["ifindex"],
                f["case"] + ":ROLLBACK",
            )
    gate(
        fingerprint(cap.unrelated_before) == fingerprint(cap.unrelated_after)
        and fingerprint(cap.management_policy_before) == fingerprint(cap.management_policy_after)
        and clean(cap.final_policy),
        "UNRELATED_OR_MANAGEMENT_POLICY_CHANGED",
    )
    gate(cap.finished_ns > cap.phases[-1].finished_ns, "FINAL_TIMING")
    return {
        "verdict": "LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES" if not blockers else "INCONCLUSIVE_OR_FAILED",
        "blockers": blockers,
        "phases": summaries,
        "refused_recovery_cases": refusals,
        "all_failure_modes_recovered": False,
        "independent_review_complete": False,
        "physical_device_identity_verified": False,
        "production_execution_qualified": False,
    }
