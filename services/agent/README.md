# CryptoScan agent

A transport process that runs on the bank side and pushes what separate collectors wrote.

```bash
python -m agent.runner --source /var/lib/cryptoscan/observations \
    --server https://control-plane.bank.internal \
    --sign-key /etc/cryptoscan/agent.key \
    --state /var/lib/cryptoscan/agent-state.json \
    --interval 300
```

What it does: merge the per-plane observation files into one observation, hash it, and
`POST /api/v1/ingestion/observations`. What it does **not** do: scan, probe, execute a
collector, or decide anything. An unchanged estate is not uploaded at all.

The source directory contract: one JSON file per plane, e.g. `linux-hosts.json`:

```json
{"plane": "Linux hosts", "estate": "payments", "scope": "production",
 "assets": [], "evidence": [], "relationships": [],
 "coverage": {"expected": 150, "collected": 143}}
```

A file that cannot be read becomes a `FAILED` plane in the observation — never a smaller
estate. A collector that states no `coverage` is reported as `expected: null`, so its
completeness is `UNKNOWN` rather than 100%.

Per-cycle states: `PUSHED`, `UNCHANGED`, `NOTHING_COLLECTED`, `REFUSED`, `FAILED`. Exit
code `2` means the control plane refused the observation or could not be reached; `--once`
runs a single cycle and exits.
