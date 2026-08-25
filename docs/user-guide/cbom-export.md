# Cryptographic Bill of Materials

A bank with a million systems does **not** know which algorithms those
systems run. CryptoScan’s job is to turn that unknown estate into
CycloneDX 1.5 CBOMs. **A CBOM does not exist until the system is scanned**
(or a vendor document is ingested).

## Bank workflow

1. **Register systems** from the CMDB (`POST /api/v1/systems/import` or the
   CBOM page). Give each row a `scan_target` (git URL or `local://` path).
2. **Coverage** (`GET /api/v1/cbom/coverage`) shows how many systems still
   have unknown cryptography (`NEVER_SCANNED`, `NO_TARGET`).
3. **Scan**. One system: `POST /api/v1/systems/{id}/scan`. The estate:
   `POST /api/v1/cbom/scan-uncovered` (batches of 25, cap 100 — do not
   enqueue a million jobs in one request).
4. The worker discovers algorithms, writes the CBOM, and stamps the system
   `CURRENT`. After 90 days the CBOM is `STALE` and must be scanned again.

## Dashboard

**Overview** is coverage, not vanity scan counts. **CBOM** lists every
system’s status, searches algorithms across the estate, imports CMDB CSV
or vendor CycloneDX, and queues uncovered scans.

## API

```
GET  /api/v1/cbom
GET  /api/v1/cbom/coverage
POST /api/v1/cbom/scan-uncovered   {limit?}
GET  /api/v1/cbom/search?q=RSA
GET  /api/v1/cbom/portfolio
GET  /api/v1/cbom/system/{id}
POST /api/v1/systems/import        {csv} or {systems:[…]}
POST /api/v1/systems/{id}/scan
PATCH /api/v1/systems/{id}         {scan_target}
```

Import CSV header:

```
name,scan_target,owner,environment,business_unit,criticality
payments-api,https://github.com/bank/payments.git,alice,prod,Retail,TIER-1
```

Signed exports still attach HMAC-SHA256 in `metadata.properties`.
