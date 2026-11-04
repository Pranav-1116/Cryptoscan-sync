# Accuracy against a planted ground truth

> the fact-derivation rules, scored against a planted answer key.
> The device collectors are not exercised here: every observation is a recorded artefact.
> A pass means the rules keep capability apart from usage, preserve disagreement, and refuse to turn a gap into an absence — not that a real bank's estate scans at this precision.

## The two pipelines

| Metric | Target | Fact rule | Shortcut (`collector → CBOM`) |
|---|---|---|---|
| asset precision | ≥ 95% | 100.0% | 92.6% |
| asset recall | ≥ 95% | 100.0% | 100.0% |
| algorithm precision | ≥ 95% | 100.0% | 68.9% |
| algorithm recall | ≥ 95% | 100.0% | 81.6% |
| key size accuracy | ≥ 98% | 100.0% | 85.7% |
| certificate accuracy | ≥ 98% | 100.0% | 100.0% |
| network accuracy | ≥ 98% | 100.0% | 100.0% |
| dependency accuracy | ≥ 95% | 100.0% | 75.0% |
| system owner accuracy | ≥ 95% | 100.0% | 87.0% |
| evidence attribution accuracy | ≥ 98% | 98.7% | 0.0% |
| false positive rate | ≤ 5% | 0.0% | 100.0% |
| false negative rate | ≤ 5% | 0.7% | 52.4% |

## Per dimension (fact rule)

| Dimension | Precision | Recall | Answered | Unresolved | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| algorithm | 100.0% | 100.0% | 93.3% | 6.7% | 35 | 0 | 7 | 0 |
| asset | 100.0% | 100.0% | 100.0% | 0.0% | 113 | 0 | 9 | 0 |
| certificate | 100.0% | 100.0% | 100.0% | 0.0% | 12 | 0 | 0 | 0 |
| dependency | 100.0% | 100.0% | 100.0% | 0.0% | 14 | 0 | 0 | 0 |
| evidence_attribution | 100.0% | 98.7% | 98.7% | 0.0% | 226 | 0 | 0 | 3 |
| key_size | 100.0% | 100.0% | 100.0% | 0.0% | 13 | 0 | 0 | 0 |
| network | 100.0% | 100.0% | 100.0% | 0.0% | 18 | 0 | 0 | 0 |
| system_owner | 100.0% | 100.0% | 100.0% | 0.0% | 21 | 0 | 1 | 0 |

## What the shortcut costs

* algorithm precision 68.9% against 100.0%
* false-positive rate 100.0% against 0.0%
* 10 gate(s) fail for the shortcut, 0 for the rule

## Counting rules

* **unknown** — UNKNOWN is not a false positive and not a false negative: it is counted as unresolved and reported in `unresolved_rate`, beside the metric and never inside it
* **unobservable** — declining an item the ground truth marks unobservable is a true negative; asserting a value for it is a false positive
* **absent** — declining an item the ground truth does not hold is a true negative; asserting a value for it is a false positive
* **wrong value** — a confidently wrong value costs one false positive and one false negative
* **unpredicted** — an observable truth item with no prediction is a false negative, and is counted separately as `unpredicted`
* **attribution** — evidence attribution asks whether the cited ids are real and belong to this subject — citing more than one is corroboration, not an error; citing an id that does not exist is a false positive and a false negative
* **answered** — `answered` = (TP + FP + TN) / (TP + FP + TN + FN + unresolved): every point of precision bought by answering less shows up here, and the gate requires 80%
* **silence** — a dimension left unresolved above 25% fails the gate: 'UNKNOWN is not wrong' and 'UNKNOWN is not an escape hatch' are the same rule
* **accuracy** — an accuracy dimension counts (TP + TN) / (TP + TN + FP + FN): a wrong 'absent' costs the same as a wrong 'present'
* **not measured** — a dimension with nothing observable fails as NOT MEASURED rather than passing as 0/0

## Hard cases in the corpus

* installed-but-unused
* configured-but-unused
* supported-not-negotiated
* runtime-only
* network-only
* static-only
* vendor-only
* stale-sbom
* container-library-mismatch
* custom-crypto
* duplicate-app-name
* tls-re-encryption
* expired-certificate
* unreachable-hsm
* collection-failure
* permission-denied
* partial-collection
* unmapped-owner
* inferred-only
* parser-disagreement
