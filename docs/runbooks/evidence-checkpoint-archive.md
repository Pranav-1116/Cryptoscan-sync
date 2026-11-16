# Evidence-chain checkpoints — archive, key and incident runbook

The evidence chains are honestly `anchoring: local-database-only`: they
prove their own continuity, not that the database alone did not rewrite
all of it. A **signed checkpoint** is the external anchor the chain cannot
provide for itself — an operator-held key signs the chain's `head_hash`,
`entry_count`, `last_seq`, `anchored_prev_hash` and declared
`truncated_before_seq` into a small JSON document that the bank archives.
Anyone holding the key can later prove the chain was exactly this long,
with exactly this head, at checkpoint time.

## What runs weekly

`cryptoscan-evidence-checkpoint.timer` (Monday 04:15) runs
`scripts/evidence_checkpoint_timer.sh`, which for each evidence stream
(`network`, `runtime`):

1. **verify** last week's archived checkpoint — its HMAC-SHA256 signature
   must still verify under the operator key (exit 1 = forged archive).
2. **continuity** — the live chain must still contain what that checkpoint
   anchored: the entry at `last_seq` must still hash to `head_hash`.
   - `CONTINUES` (exit 0) — legitimate growth; the anchor holds.
   - `REWRITTEN` (exit 1) — history at or before the anchor changed.
   - `OUT_OF_WINDOW` (exit 2) — declared truncation dropped the anchored
     entry; this checkpoint can no longer prove anything.
3. **sign** this week's checkpoint into a side file, then **verify** it,
   and only then promote it over the previous file.

Any failure preserves the previous checkpoints and fails the unit — hook
alerting to unit failures (same contract as `cryptoscan-audit-verify`).

## Archiving the proof documents

Each checkpoint file is a proof document, not a cache. Every week:

1. Copy `/var/lib/cryptoscan/checkpoints/evidence-checkpoint-{network,runtime}.json`
   to the bank's write-once archive, named with the signing date:
   `evidence-checkpoint-network-2026-10-19.json`.
2. Keep **every** historical checkpoint. Each binds a moment; the sequence
   of them is the chain's external history. Never overwrite an archived
   checkpoint — the provenance rule applies to these too.
3. A checkpoint that fails `verify` during archiving is an incident (below),
   not a file to skip.

## Key management (`EVIDENCE_CHECKPOINT_KEY`)

- The key lives in `/etc/cryptoscan/evidence-checkpoint.env` on the
  production host (mode 0600), sourced by the unit. Operators may export
  it manually for ad-hoc CLI runs.
- Minimum 16 characters; the build refuses to sign with anything shorter
  (`RuntimeError: refusing to sign`) and has **no default key** — a build
  that could sign without an operator would be a build that could forge.
- Hold the key in the bank's secrets manager/HSM; the env file is a
  deployment convenience, not the system of record.
- **Rotation**: generate the new key, run
  `scripts/evidence_checkpoint.py sign --stream <s> --file <new>.json` for
  both streams under the new key, archive both, then replace the env file.
  Old checkpoints remain verifiable with the old key — archive the key
  generations alongside the checkpoints they signed.

## Incident handling

| Symptom | Meaning | Action |
| --- | --- | --- |
| `verify` exit 1 on an archived checkpoint | The archived document no longer signs — it was edited, or the wrong key is loaded | Incident. Preserve the file byte-for-byte, compare with the WORM copy, confirm which key generation signed it. |
| `continuity` exit 1 (`REWRITTEN`) | The entry the checkpoint anchored no longer hashes to the anchored head — history at or before the checkpoint changed | Incident. Freeze writes, pull `scripts/audit_verify.py` output, `/findings/{id}/verify` samples and the PITR timeline (`deploy/ha/pg-primary` + `docs/runbooks/dr-recovery.md`). The checkpoint pair (old + new) is evidence. |
| `continuity` exit 2 (`OUT_OF_WINDOW`) | Declared truncation (`truncated_before_seq`) dropped the anchored entry | Not automatically an incident. Compare the truncation against the retention policy: retention-as-designed keeps the unit green on the NEXT run (fresh anchor in window); unexpected truncation is an incident. |
| `sign` exit 2 | Key missing or too short | Restore the key from the secrets manager. Never work around by weakening the refusal. |

## What a checkpoint does NOT prove

Per the chain's own honesty notes: a checkpoint proves **continuity**
(length, head, truncation window under a key) — it is not a claim that
the observations were true. Content-level verification lives on the
existing surfaces: `scripts/audit_verify.py` (daily unit),
`GET /findings/{id}/verify` (per-record chain_hash), and
`ec.verify(chain, records=...)` with records loaded.
