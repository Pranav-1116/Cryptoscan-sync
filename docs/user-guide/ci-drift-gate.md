# Purpose-aware PR / CI drift gate

A new MD5 used as a cache key is a warning. A new DES used to encrypt
payments is a merge blocker. The gate uses the same drift detector as
the dashboard; it only changes the *verdict*.

## Decision

| Decision | When |
| --- | --- |
| `FAIL` | Weak algorithm (DES, 3DES, RC4, …) or hardcoded key in ENCRYPTION / KEY_EXCHANGE / KEY_AGREEMENT / SIGNING; or NEW/CHANGED drift of that kind |
| `WARN` | Weak hash (MD5, SHA-1), removed sites, upgrades, other policy FAILs |
| `PASS` | Nothing of the above |

Upgrades (`CHANGED` + reason containing `UPGRADED`) are warnings, not
blockers. The gate never writes `CRITICAL_FAIL`.

## API

```bash
# After a scan finishes
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/gate

# Same payload, intended for CI
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d "{\"scan_id\":\"$SCAN_ID\"}" \
  http://127.0.0.1:8000/api/v1/ci/gate
```

`gate.sarif` is GitHub code-scanning compatible:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/gate.sarif \
  -o cryptoscan.sarif.json
```

## CLI (exit 1 on FAIL)

```bash
export CRYPTOSCAN_API=http://127.0.0.1:8000/api/v1
export CRYPTOSCAN_TOKEN=...
python scripts/ci_gate.py --scan-id "$SCAN_ID" --sarif gate.sarif.json
```

WARN exits 0 (the check is yellow in GitHub via the commit status, not
via process exit). FAIL exits 1.

## GitHub commit status

When `GITHUB_TOKEN` is set, the worker posts two statuses on the
scanned commit:

- `cryptoscan/compliance` — pipeline completed
- `cryptoscan/drift-gate` — PASS/WARN → success, FAIL → failure

Approve a baseline first if you want NEW/CHANGED drift in the gate.
Without a baseline the gate still blocks current weak encryptors.

## Agility and work-orders

`GET /scans/{id}/agility` scores 0–100 from how many sites bake the
algorithm into source (`Cipher.getInstance("DES/ECB/...")`) versus a
factory.

`GET /scans/{id}/work-orders` groups FAILs by algorithm+purpose and
attaches a replacement (AES-256-GCM, SHA-256, ECDH / ML-KEM, …) plus
the rule that failed. These are engineering tickets, not a second
policy engine.
