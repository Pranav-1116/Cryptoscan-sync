# ADR-014 Live Hardware Engine — event-driven 24/7 state, not repeated scans

## Status

Accepted. Implemented 2026-08-31 in `services/universal_vendor/universal_vendor/hardware/live/`
(controller, events, heartbeat, reaction, timeline, edge, pqc_impact,
discovery_router, edge_cli), with persistence in `services/database`
(migration 0036), API surface in `services/api/api/routers/hardware.py` and
endpoint documentation in `docs/api-reference/rest-api.md`.

## Context

The hardware scanner originally ran full pipeline scans on demand
(`UniversalHardwareScanner.scan`). The 24/7 requirement changes the model:
the platform must maintain a **live hardware state**, not perform repeated
full hardware scans. The spec (§1–§22) demands event-driven operation,
change-triggered targeted re-discovery, heartbeats, drift, versioned HBOM,
point-in-time reconstruction, tamper-evident evidence, PQC impact, risk
recalculation, alert correlation and edge durability.

## Decision

1. **The database is the current truth.** `hardware_assets` holds the live
   per-asset state (current + previous), `hardware_events` is an immutable
   journal, `hardware_agents` holds heartbeat health. Events are applied
   through `LiveHardwareController.ingest` and persisted atomically.

2. **Events drive everything; scans are targeted.** Every canonical event
   (16 types + TPM/HSM lifecycle events) flows through
   Event → Identity Resolution → Change Classification → Impact Analysis →
   Targeted Scan Plan (`ChangeReactionPlanner`). A BIOS update triggers BIOS
   verification + capability + crypto-capability + PQC reassessment and
   explicitly excludes unrelated storage/network rescans (§6).

3. **A missing agent never removes hardware.** `AgentHeartbeatEngine`
   classifies HEARTBEAT_LOST → STALE → AGENT_UNAVAILABLE → ALERT. Hardware
   removal requires explicit discovery evidence; availability status is
   `UNKNOWN` for unreachable agents (§4).

4. **Timeline reconstruction over the journal.** `HardwareTimeline.state_at`
   replays journal events up to a timestamp through a fresh state engine;
   "show hardware state at 2026-08-31 12:00" is a pure function of the
   journal (§16).

5. **Evidence is hash-chained incrementally.** `build_evidence_chain` gained
   `start_index`/`previous_hash` so per-event appends keep one continuous
   SHA-256 chain; `verify_evidence_chain` uses the stored absolute position
   (§17).

6. **HBOM is versioned.** Every state change freezes a new HBOM version
   (`HbomGenerator.snapshot`); v100 → event → v101 (§15).

7. **Edge durability.** `EdgeHardwareAgent` keeps a local JSONL queue +
   chained evidence; central sync drains only after the control plane
   acknowledges (§21).

8. **Deterministic everywhere.** Classification catalogs, reaction matrices,
   impact thresholds and PQC migration-impact rules are explicit tables —
   no AI, no learned models, no name-based inference (PQC verdicts stay in
   the evidence-backed `PqcReadinessDatabase`).

9. **One §5 mechanism per device type.** `LiveDiscoveryRouter` maps every
   hardware type to exactly one discovery mechanism (agent/DMI for servers,
   SNMPv3/management API for network gear, authorized HSM interface for
   HSMs, OS/TPM for TPMs, storage API for SAN/NAS, hypervisor API for
   virtualization). OT/ICS and IoT are **passive-first**: active probing
   context is stripped, never used. `LiveHardwareController.rediscover`
   (§6) executes only the mechanism for the changed device and ingests the
   observations through the normal event pipeline.

10. **Monitor bridge.** The diagram sources (Agent Telemetry, Management
    APIs, Passive Events → Event Bus) are collected by `LiveHardwareMonitor`
    and ingested through `LiveHardwareController.run_monitor`, so all
    sources share the same classification/evidence/HBOM pipeline.

11. **NIC changes → network relationships.** On `NIC_CHANGED`,
    `HardwareCorrelationEngine.network_relationships` reports the affected
    switch/firewall/load-balancer/application chain (§12) alongside the
    reaction plan.

12. **Deployable edge agent CLI.** `edge_cli.py` provides
    `ingest`/`sync`/`status` subcommands (stdlib only) so real fleets can
    run the §21 durable-queue agent without the control plane.

## Consequences

- Live state queries are DB reads; the in-process controller provides the
  pipeline computation and alert/HBOM surfaces.
- The Makefile test gate now includes `services/universal_vendor/tests` and
  puts the service on `PYTHONPATH` (the API depends on it).
- Existing regex/on-demand scan pipeline is unchanged; the live engine is an
  additive layer.
- The discovery router honors `SafetyController` scope: out-of-scope assets
  are refused and audited, never scanned.
- Edge agents keep local chained evidence even while the control plane is
  unreachable; `sync` returns non-zero and preserves the queue when the
  central endpoint rejects.
