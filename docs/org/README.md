# Org Readiness Documents

Operational artifacts that sit alongside — and are measured by — the
policy pack (`docs/policies/`) and the compliance exhibits
(`docs/compliance/`).

| Document | Purpose | Measured by |
|----------|---------|-------------|
| [training-and-awareness.md](training-and-awareness.md) | mandatory courses, audiences, cadence, completion records (CC1.2) | `scripts/org_readiness_check.py` |
| [joiner-mover-leaver.md](joiner-mover-leaver.md) | access lifecycle: background check → MFA → role → deactivation (CC6.1/6.3/6.7) | `scripts/org_readiness_check.py` |

Related operational documents elsewhere:

- `docs/ops/on-call-and-comms.md` — roster, escalation tree, comms SLAs
- `docs/compliance/risk-register.md` — living risk register (CC9.1)
- `docs/compliance/quarterly-board-report.md` — board reporting cadence
- `docs/compliance/management-rep-letter.md` — management rep letter

Readiness state: run `python scripts/org_readiness_check.py` — or look
at `org-readiness.json` inside the compliance pack
(`scripts/compliance_pack.py`). A placeholder `[ORG: ...]` is an open
item, not a gap in the document: the document is complete, the org
hasn't filled the decision yet.
