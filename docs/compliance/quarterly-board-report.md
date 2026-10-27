# Quarterly Board / Audit Committee Report — Template

**Version:** 1.0 (template) · **Owner:** [ORG: CISO] · **Cadence:**
quarterly, within [ORG: 20] days of quarter end · **Audience:** board
/ audit committee · **Criteria:** TSC CC1.1 (tone at the top), CC1.4
(independent assessment cadence)

A standing one-pager per quarter. Every figure has a named data source
so the board can see the number, and the org can re-derive it.

---

**Period:** [ORG: YYYY-QN] · **Prepared by:** [ORG: CISO] · **Date:**
[ORG: YYYY-MM-DD]

## 1. Executive summary

[ORG: 3–4 sentences — overall posture, the single biggest change this
quarter, the single biggest ask of the board.]

## 2. Security posture

| Metric | This quarter | Last quarter | Source |
|--------|-------------|--------------|--------|
| Open Critical/High vulnerabilities | [ORG: n] | [ORG: n] | vulnerability findings pipeline (self-scan) |
| % human accounts with MFA enabled | [ORG: %] | [ORG: %] | `GET /audit-export/access-review` → `active_without_mfa` |
| Stale / never-used accounts | [ORG: n] | [ORG: n] | access-review export → `stale_accounts`, `never_logged_in` |
| Expired-but-unrevoked API keys | [ORG: n] | [ORG: n] | access-review export → `expired_keys_not_revoked` |
| Risk-register items high/critical | [ORG: n] | [ORG: n] | `docs/compliance/risk-register.md` |

## 3. Incidents

SEV-1/SEV-2 incidents: [ORG: n] — [ORG: one line each: date, cause,
duration, data affected (yes/no), lessons-learned status]. SEV-1/2
with personal-data impact (72 h notifications): [ORG: n]. Post-incident
reviews completed: [ORG: n/n].

## 4. Resilience & DR

| Item | Result | Target | Source |
|------|--------|--------|--------|
| DR failover drill | [ORG: PASS/FAIL/SKIP] | RTO 4 h | `deploy/ha/drill.sh` + evidence chain entry |
| Backup/restore drill | [ORG: PASS/FAIL] | RPO 1 h | `scripts/backup_drill.py --record-evidence` |
| Restore verification (monthly) | [ORG: date + result] | monthly | backup tooling + evidence chain |

## 5. Compliance & evidence

- Quarterly access review: [ORG: done / scheduled YYYY-MM-DD] — minutes
  recorded (`GET /audit-export/access-reviews`), findings: [ORG: n open].
- Policy sign-off: [ORG: n] `[ORG:]` items open (was [ORG: n] last
  quarter) — `scripts/policy_signoff_check.py`.
- Risk register: [ORG: n] new, [ORG: n] closed, [ORG: n] accepted.
- Evidence pack: [ORG: pack hash] — `scripts/compliance_pack.py`.
- SOC 2 programme: [ORG: engagement status / observation-window month
  n of m / fieldwork status].

## 6. Forward look (next quarter)

[ORG: top 3 priorities with owners.]

---

**Prepared by:** [ORG: name] · **Reviewed by:** [ORG: MD] ·
**Approved for circulation:** [ORG: audit committee chair]

*Distribution: board/audit committee only. Contains Class-2/3 content
(Data Classification Policy) — do not forward.*
