# Region failover drill

Ran 2026-09-17T08:09:44.692940+00:00 — executable proof (`scripts/region_drills.py`), temporary regions, real bus code.

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
primary converges as a replica. API read-replicas scale behind a
load balancer against any replica dir.

**Verdict: PASS**
