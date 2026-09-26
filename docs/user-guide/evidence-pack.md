# Evidence pack and CRA / NIST zip

A scan is only useful in an audit if someone *outside* CryptoScan can
prove the findings were not edited. The evidence pack is that proof.

## Download

From a scan page:

- **Evidence pack** — `GET /api/v1/scans/{scan_id}/evidence-pack`
- **CRA/NIST zip** — `GET /api/v1/scans/{scan_id}/audit-pack`

Or with curl:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/evidence-pack \
  -o evidence-pack.json
```

## What is signed

1. Every finding already has a SHA-256 `content_hash` and a chain hash:

       chain[0] = SHA256(content_hash[0] + scan_id)
       chain[n] = SHA256(content_hash[n] + chain[n-1])

   Delete, reorder, or edit any finding and the chain breaks.

2. The issuing instance also HMACs the pack with `SECRET_KEY`
   (`integrity.signature`). That proves *this* CryptoScan produced the
   file. Auditors who do not have the secret can still check the chain.

The pack also records the policy **pack hash** so you can show which
rule set produced each FAIL.

3. `extra.analysis` (present when the scan produced it) is inside the HMAC
   too: `evidence_sources` (findings per source type — code, runtime log,
   key inventory), `cascade` (summary, business-system rollup, migration
   waves, key sizes below floor, libraries — not the per-file provider list,
   which stays at `GET /scans/{id}/cascade`), and `key_reconciliation`
   (consumers / orphans / not-in-inventory of a key-export scan). Change a
   number there and `signature_ok` flips to false.

## Verify offline

The CRA/NIST zip includes `verify_pack.py`. No CryptoScan install:

```bash
python verify_pack.py evidence-pack.json
python verify_pack.py evidence-pack.json --secret "$SECRET_KEY"
```

From this repo:

```bash
python scripts/verify_pack.py evidence-pack.json --secret "$SECRET_KEY"
```

Or post the pack back to the API:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"pack\": $(cat evidence-pack.json)}" \
  http://127.0.0.1:8000/api/v1/evidence-pack/verify
```

`result` is `PASS` or `FAIL`. This never changes a finding's
`overall_status`.

## What's in the zip

| File | Why an auditor cares |
| --- | --- |
| `evidence-pack.json` | Inventory + hash chain + HMAC |
| `cbom.json` | CycloneDX 1.5 CBOM (CRA software bill of materials) |
| `work-orders.json` | NIST SP 800-131A replacements, grouped by algorithm+purpose |
| `agility.json` | How much crypto is a hardcoded string vs a factory |
| `gate.json` / `gate.sarif.json` | Purpose-aware PR decision |
| `policy.json` | Rule pack hash + FAIL citations |
| `materials.json` | PEM / cert inventory joined to nearby source |
| `verify_pack.py` | Self-contained verifier |
