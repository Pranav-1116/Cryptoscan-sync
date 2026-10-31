# Evidence integrity — what corruption the chain catches

`cryptoscan.evidence-integrity/1` · generated 2026-10-31T17:30:18.854879+00:00 · **8 / 9 tampering attacks detected** · **1 undetectable by design** · **3 / 3 enforcement points reject tampered evidence**

Each attack is applied to a real stored scan — the real ORM rows, chain and scan manifest — and every consumer is asked what it does with the result.

| Attack | What was altered | Expected | Verifier | Verdict |
|---|---|---|---|---|
| `none` | control — nothing altered, the chain must read PASS | PASS | PASS | **CONTROL_OK** |
| `payload_tamper` | the finding body is edited, hashes untouched | FAIL | FAIL | **DETECTED** |
| `content_hash_rewrite` | the content hash is replaced to match a tampered body | FAIL | FAIL | **DETECTED** |
| `chain_link_rewrite` | a chain link is rewritten in place | FAIL | FAIL | **DETECTED** |
| `delete_middle` | a record is deleted from the middle | FAIL | FAIL | **DETECTED** |
| `delete_tail` | the last record is deleted | FAIL | FAIL | **DETECTED** |
| `reorder` | two records swap positions | FAIL | FAIL | **DETECTED** |
| `append_forged` | a forged record is appended with a consistent link | FAIL | FAIL | **DETECTED** |
| `manifest_absent` | the manifest anchor is removed | UNVERIFIABLE | UNVERIFIABLE | **DETECTED** |
| `delete_tail_and_rebuild_manifest` | the tail is deleted and the manifest rewritten to match | UNDETECTABLE_BY_DESIGN | PASS | **UNDETECTABLE** |

## Read paths — does each consumer refuse tampered evidence?

| Surface | Function | Clean | After a payload tamper | Verdict |
|---|---|---|---|---|
| verify_stored_scan (export, audit, rescan, host-evidence) | `verifier` | PASS | FAIL | **DETECTED** |
| GET /scans/{id}/verify | `scan_verify_route` | PASS | FAIL | **DETECTED** |
| digital-twin snapshot | `twin` | PASS | FAIL | **DETECTED** |
| build_evidence_pack | `pack` | PASS | PASS | **UNDETECTED** |

## Per-consumer detail

- `none`: verifier=PASS, scan_verify_route=PASS, twin=PASS, pack=PASS
- `payload_tamper`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=PASS
- `content_hash_rewrite`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=FAIL
- `chain_link_rewrite`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=FAIL
- `delete_middle`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=FAIL
- `delete_tail`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=PASS
- `reorder`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=FAIL
- `append_forged`: verifier=FAIL, scan_verify_route=FAIL, twin=FAIL, pack=PASS
- `manifest_absent`: verifier=UNVERIFIABLE, scan_verify_route=UNVERIFIABLE, twin=UNVERIFIED, pack=PASS
- `delete_tail_and_rebuild_manifest`: verifier=PASS, scan_verify_route=PASS, twin=PASS, pack=PASS

## What this does not prove

- The scan manifest is an unsigned hash over record ids: it catches truncation only while the attacker does not rewrite it. Deleting a record and re-anchoring the manifest verifies PASS, so the anchor needs a signature or an off-site copy to survive an attacker with write access to the scans table.
- No signing key and no off-site anchor: an attacker with write access to the whole scan (payload, content hashes, chain, manifest) can produce a self-consistent forgery that this scheme cannot distinguish from the original.
- The pack carries the stored commitments, not the payload it claims they cover; it is a transport, not a verifier. Enforcement is `verify_stored_scan` at the route.
- A tombstoned (soft-deleted) record stays in the chain by design, so retraction does not read as deletion — that is covered by the disposition path, not this one.
- The store is a fresh SQLite database written by this harness. It does not prove that a bank's PostgreSQL deployment has the same constraint behaviour, that every writer computes the chain the same way, or that a *reader* outside these four paths verifies anything.
