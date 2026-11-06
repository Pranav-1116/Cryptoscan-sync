# Region failover drill

Ran 2026-11-06T12:53:34.070913+00:00 — executable proof (`scripts/region_drills.py`), temporary regions, real bus code.

**Scope — what this drill is, and is not.** The two regions are two
temporary directories inside one process on one machine. This exercises
the replication, promotion and convergence code end to end; it is **not**
a two-site failover, **not** a two-Postgres-instance DR drill, **not** a
measured RPO/RTO, and **not** SOC 2 CC9.3/9.4 evidence. A bank runs the
real drill against its own sites and keeps those receipts.

| Check | Result |
|---|---|
| primary writes 200 events | ✅ PASS |
| replica receives verified shipment | ✅ PASS |
| promoted replica continues sequence (zero loss) | ✅ PASS |
| returning region converges (251 events, all verified) | ✅ PASS |
| replica refuses local writes (split-brain guard) | ✅ PASS |

Model: one **write primary** per topic; replicas receive HMAC-
verified shipments (tampered lines never ship, sequence gaps abort);
promotion continues the replicated sequence; the returning old
primary converges as a replica. API read-replicas are designed to sit
behind a load balancer against any replica dir — not exercised here.

**Verdict: PASS — same-process code drill (see Scope; not a site qualification)**
