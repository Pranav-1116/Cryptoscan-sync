# Compliance Report Generator

Audit-ready reports from stored evidence — requirement by requirement, with
attestation and tamper detection. **Policy is the only source of pass/fail**;
nothing in the report is inferred or AI-generated.

## Templates

| Template | Source | Notes |
|---|---|---|
| `pci-dss-4.0` | native | PCI-DSS 4.0 requirements 3.5.1 / 4.2.1 / 8.3.2 / 12.3.3 |
| `nist-sp-800-131a` | native | SP 800-131A Rev. 2 transition requirements |
| `fips-140-3` | native | FIPS 140-3 approved-algorithm / key-size rules |
| `dora` | mapped | ICT risk → internal baseline; PQC timeline → CNSA 2.0 |
| `soc2` | mapped | CC6.1 / CC6.7 → internal baseline |
| `iso-27001` | mapped | Annex A.8.24 → internal baseline |
| `custom` | custom | pick requirement ids across templates |

`native` templates evaluate rules that cite the framework directly.
`mapped` templates map requirements onto the internal baseline — every
requirement row shows **which rule ids** produced it, so auditors can trace
the chain of evidence. A requirement with no matching rule evidence reports
`NOT_EVALUATED`, never a guessed PASS.

## Usage

```
GET /api/v1/report-templates                                  # list + requirement ids
GET /api/v1/scans/{id}/report?template=pci-dss-4.0            # JSON
GET /api/v1/scans/{id}/report.html?template=pci-dss-4.0       # printable HTML
GET /api/v1/scans/{id}/report?template=custom&requirements=4.2.1,CC6.1
```

Each templated report contains:

- `template_evaluation.requirements[]` — id, title, status
  (PASS/FAIL/NOT_EVALUATED), matched rule ids, failing evidence locations
- `template_evaluation.summary` — pass/fail/not-evaluated counts, compliant %
- `attestation` — scope, scan id, policy pack hash, evidence count,
  deterministic-generation statement
- `report_hash` — SHA-256 over the canonical JSON of the report body

## Integrity model (honest boundaries)

- **Tamper detection**: recompute the hash from any report body
  (`reporting.report_templates.canonical_hash`) — a single changed
  character breaks it.
- **Authenticity**: the attestation binds the report to a scan, a policy
  pack hash, and a timestamp. Full PKI digital signatures require a real
  certificate authority certificate; that integration point is intentionally
  left `signature: null` rather than faked.
- **Scheduling**: quarterly/automated generation is an ops cron away —
  the endpoint is deterministic and side-effect free. See
  `docs/admin-guide/production.md` for the recommended scheduler pattern.
