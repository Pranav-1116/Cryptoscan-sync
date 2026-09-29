# Control register — evidence tiers

Procurement asks two different questions and they are easy to conflate:

1. *Does the product implement this control?*
2. *Can you prove it operates, and who says so?*

Source code answers the first. It never answers the second. This register
keeps them apart, per `fix.md` item 5 — *"having encryption code does not
prove FIPS certification"*.

The register itself lives in [`config/control-register.yaml`](../../config/control-register.yaml)
and is enforced by [`scripts/control_register.py`](../../scripts/control_register.py).
This page explains how to read it.

```bash
python scripts/control_register.py \
  --out docs/readiness-evidence/control-register.json
```

## The four tiers

| Tier | What it means | Who can issue it |
|---|---|---|
| `repository_control` | Code, config or tests exist. The mechanism is real. | This repository |
| `operational_record` | A dated artifact from actually running it — a drill output, an audit export, a release record. | Whoever ran it |
| `customer_attestation` | The customer or operator has signed that they accept or perform it. | The customer |
| `external_certification` | An independent body has certified it — SOC 2, ISO 27001, FIPS 140-3, PCI. | The auditor |

They are ordered, and the gate refuses a claim that outranks its evidence.
The top two cannot be self-issued: a row claiming either while citing only
repository paths is rejected, because that is the vendor attesting to itself.
That rule caught a genuine mistake the first time it ran — a row claiming
`customer_attestation` for deployment location while citing `k8s/`. Those
files describe *how* the product deploys, not *where*, and where is the
customer's statement to make.

## What the gate proves, and what it does not

It proves the register is **internally honest**: every claim is supported by
the tier of evidence it asserts, every cited path exists, every control short
of the top tier states its gap, and no required procurement topic is missing.

It does not make any control true. A row at `none` is a real gap, and a
register full of `repository_control` describes a product that has been built
but not yet operated or audited. That is the current position and the
register says so plainly.

## Current position

As of 2026-09-28, across 17 controls:

| Tier | Count |
|---|---|
| `none` | 6 |
| `repository_control` | 8 |
| `operational_record` | 1 |
| `customer_attestation` | 2 |
| `external_certification` | **0** |

**No external certification of any kind exists.** No SOC 2 report, no ISO
27001 certificate, no FIPS 140-3 validation, no PCI attestation. The
cryptographic code calls FIPS-validatable primitives; that is not a validation
and must never be presented as one. A dedicated test fails if any row starts
claiming otherwise.

The six controls at `none` — patch timelines, backup destruction, incident
notification, support escalation, external certifications, independent
penetration test — are not oversights. They are commitments that have to be
made contractually or earned externally, and stating them as absent is worth
more to a reviewer than an optimistic answer that unravels under questioning.

## Using it to answer a questionnaire

Every answer in [`docs/security-questionnaire.md`](../security-questionnaire.md)
should map to a row here. Where the row is `repository_control`, the honest
answer is "implemented, not independently verified". Where the row is `none`,
say so. One overstated answer discredits the rest of the pack, which is the
practical reason for the discipline rather than merely the principled one.
