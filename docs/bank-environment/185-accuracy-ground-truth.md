# Guide 185 — measuring the accuracy claim with UNKNOWN kept out of the wrong column

> **Scope, first line, because it is the easiest thing to over-read.** This guide builds the
> *measurement programme* and the *fact-derivation rules* it scores. It does not claim the device
> collectors reach these numbers on a real bank. Every observation in the corpus is a recorded
> artefact, so what is measured is the rule — capability kept apart from usage, absence in four
> states, disagreement preserved — against a planted answer key. The report carries that sentence
> in its `scope` field and the dashboard repeats it under the title, so the number cannot travel
> without it.

## 1. The rule that makes "95%" mean something

A scanner that cannot prove an application uses AES-256 must answer `UNKNOWN`. If that `UNKNOWN`
counts as a wrong answer, the product's cheapest route to 95% is to guess — and guessing is what
produces the confident false positives this platform exists to avoid. If it counts as nothing, a
scanner reaches 100% precision by answering three questions and marking the rest unexamined.

Both halves are in the shipped code, and they are one rule:

| Rule | Where it lives | Consequence |
|---|---|---|
| `UNKNOWN` is never a false positive and never a false negative | `accuracy._score_one` | it is counted as *unresolved* and reported as `unresolved_rate` beside the metric |
| declining an item the truth marks **unobservable** is a true negative | same | "no collector reaches this HSM" is the correct answer, not a gap |
| asserting a value for an unobservable item is a **false positive** | same | recall cannot be bought by declaring the estate unwired and guessing |
| a confidently wrong value is 1 FP **and** 1 FN | same | being wrong does not get cheaper by being wrong loudly |
| a metric with nothing to measure is **not measured**, never 1.0 | `accuracy.metrics` | 0/0 fails the gate instead of passing it |
| `answered` and `unresolved_rate` are gated per dimension | `accuracy.evaluate` | `answered ≥ 80%`, `unresolved ≤ 25%` |

The last two are the anti-gaming half. "UNKNOWN is not wrong" and "UNKNOWN is not an escape
hatch" are the same feature, and the gate fails on either side of it.

## 2. Evidence → fact, as the hardest rule in the platform

`services/cbom/cbom/facts.py` is the only path from an observation to a fact:

```
observation → evidence check → normalise → identity → FACT → correlation → BOM
```

Three separations, each enforced by a refusal rather than a convention:

- **Capability is not usage.** A library's algorithm list is a `CAPABILITY` fact: real, and not a
  usage fact. `OpenSSL 3.0.13 installed` produces `OPENSSL_INSTALLED`; it never produces
  `AES-256-GCM USED`. The legality table (`facts._LEGAL`) is exhaustive — `VENDOR_DECLARED`
  cannot back `RUNTIME_USAGE`, `IMPORTED` cannot back `NETWORK_NEGOTIATED` — and constructing
  such an observation raises where it is created, not where it is read.
- **A class is carried, never inferred upward.** `VENDOR_DECLARED` stays `VENDOR_DECLARED`
  however many documents repeat it; corroboration is not promotion. `INFERRED` is recorded, shown
  as a lead, and excluded from every decision (`DECIDING_CLASSES`): a value resting only on an
  inference comes out `UNKNOWN` with an `INFERRED_ONLY` refusal, and the evidence id stays on
  record so the lead can be chased.
- **Absence is four facts.** `NOT_FOUND_WITHIN_SCOPE` (the only state that is evidence of
  absence, and only within the scope it names), `NOT_OBSERVABLE` (no collector reaches it),
  `COLLECTION_FAILED` (the look raised), `UNKNOWN` (nobody recorded looking). A failed HSM
  collection never becomes "HSM crypto = none".

Usage kinds are explicit — `CAPABILITY`, `CONFIGURED_USAGE`, `STATIC_REFERENCE`, `INVENTORY`,
`RUNTIME_USAGE`, `NETWORK_NEGOTIATED` — so a BOM can say:

```
OpenSSL
 ├── AES-256-GCM       → RUNTIME_USAGE
 ├── AES-128-GCM       → CAPABILITY
 ├── RSA-2048          → STATIC_REFERENCE
 └── ChaCha20-Poly1305 → CAPABILITY
```

And disagreement is preserved. `STRENGTH` orders the classes for display; it never settles an
argument:

- runtime `AES-256-GCM` **and** static `AES-128-GCM` → `CONFLICT` (`RUNTIME_STATIC_CONFLICT`),
  `value: null`, every side with its class, source and evidence id;
- an SBOM saying `3.0.13` against a running `3.0.11` → `DEPENDENCY_VERSION_CONFLICT`, both kept;
- a capability beside a usage → **not** a conflict: two claims about two things, stated as such.

`cap_placement()` then decides where a fact may appear: a `CONFLICT` carries no value at all,
because a BOM that printed one side of a disagreement has decided it quietly, in the artefact the
bank files.

This is the REAL-versus-EXPLAINED rule the estate conflict module already applies, applied one
layer earlier — at the moment a fact is minted.

## 3. The corpus, and why it is uncomfortable

`services/cbom/cbom/accuracy_corpus.py` builds a bank-shaped estate with a planted key: 40
applications, 40 hosts (2 outside every scope), 5 HSMs (1 unreachable, 1 whose management API
failed), 20 databases (2 uninspectable), 15 load balancers, plus certificates, TLS paths,
dependencies and owners. 475 truth items, 262 observations.

The hard cases are asserted by a test, so one cannot quietly disappear:

```
installed-but-unused, configured-but-unused, supported-not-negotiated, runtime-only,
network-only, static-only, vendor-only, stale-sbom, container-library-mismatch,
custom-crypto, duplicate-app-name, tls-re-encryption, expired-certificate, unreachable-hsm,
collection-failure, permission-denied, partial-collection, unmapped-owner, inferred-only,
parser-disagreement
```

Three of them are worth naming because they are where accuracy is actually won:

- **supported but not negotiated.** The config offers TLS 1.3; the wire negotiated 1.2. The
  platform reports TLS 1.2 as the usage and keeps TLS 1.3 as a capability. A CBOM saying "TLS 1.3"
  here is a false positive that reads like good news.
- **TLS re-encryption.** WAF 1.3 → LB 1.2 → gateway 1.3. Termination is not re-encryption, and
  one verdict for the path is a claim about no hop in particular.
- **duplicate application name.** Two systems called "Payments API". Identity is the canonical id;
  a pipeline that merges them by name loses one and reports the other twice.

The mix is weighted towards provable cases on purpose. A corpus where most applications are
unprovable would let any pipeline look careful by declining, and the `answered` gate would be
measuring the corpus instead of the rule.

## 4. The two pipelines, and the cost of the shortcut

`scripts/accuracy_ground_truth.py` scores both pipelines against the same key:

| Metric | Target | Fact rule | Shortcut (`collector → CBOM`) |
|---|---|---|---|
| asset precision / recall | ≥ 95% | 100% / 100% | 92.6% / 100% |
| algorithm precision / recall | ≥ 95% | 100% / 100% | **68.9% / 81.6%** |
| key size accuracy | ≥ 98% | 100% | 85.7% |
| certificate accuracy | ≥ 98% | 100% | 100% |
| network accuracy | ≥ 98% | 100% | 100% |
| dependency accuracy | ≥ 95% | 100% | 75.0% |
| system / owner accuracy | ≥ 95% | 100% | 87.0% |
| evidence attribution accuracy | ≥ 98% | 98.7% | **0%** |
| false-positive rate | ≤ 5% | 0% | **100%** |
| false-negative rate | ≤ 5% | 0.7% | 52.4% |

The shortcut is the one the review warned about, implemented deliberately: every algorithm a
library *can* do is reported as one the application *does*, the first answer wins, and one
fabricated evidence id is attached to everything. Its precision falls to 68.9%, its
false-positive rate reaches 100% — every library in the estate becomes a false positive — and its
attribution accuracy is 0% because the ids it cites do not exist.

**Where the honest number is not 100%:** `evidence_attribution` is 98.7% (three items cite an id
that belongs to another subject), `algorithm.answered` is 93.3% with 6.7% unresolved, and the
asset dimension carries 9 `not_observable` items. Those are the applications and HSMs the truth
holds and the scanner could not prove — the number a bank should ask about next, printed on the
same page as the 100%s.

## 5. The gate

```
python scripts/accuracy_ground_truth.py --gate                          # targets only
python scripts/accuracy_ground_truth.py --gate --baseline <report>.json # targets + no regression
python scripts/accuracy_ground_truth.py --naive --gate                  # exercises the failure path
```

`scripts/tests/test_accuracy_ground_truth.py` runs it inside pytest, so a change that trades
precision for a richer-looking BOM fails the build in the same run that made it. `compare()`
blocks a metric that drops by more than 0.5 points, inverts the comparison for the two ceiling
metrics — a false-positive rate that *rose* is a regression even though the number grew — and
treats a metric that stopped being measured as a regression rather than a gap. One test also
regenerates the committed dashboard and fails if it has drifted, so the numbers in this guide
cannot become last quarter's.

Artifacts: `185-accuracy-ground-truth.json` (machine) and `185-accuracy-dashboard.md` (the tables
above, written by the harness that computes them).

`scripts/pending_workflows.py` renders the checked-in `restore-drill.yml` (guide 184) and
`accuracy-gate.yml` in `.github/workflows/`. The first is a weekly disposable restore drill; the
second runs weekly and on accuracy-related pull requests. They are independent workflows, not a
combined release gate. `scripts/tests/test_pending_workflows.py` checks their generated content
and on-disk parity. A scheduled workflow fires only after publication on the repository's default
branch; a local YAML check is not an observed GitHub run, and neither workflow qualifies a bank
restore or accuracy figure.

## 6. What is built here, and what is honestly not

Built, with tests (72 new):

- the evidence → fact boundary, the legality table and the refusals — `facts.py`, 28 tests;
- capability / configured / static / runtime / negotiated / inventory usage kinds;
- deterministic class scoring with disagreement preserved as `CONFLICT`, both sides kept, and a
  conflict that carries no value into the BOM;
- the four-state absence model, `INFERRED`-is-a-lead, and `searched=None` as "nobody recorded
  looking" rather than "nobody could";
- the accuracy engine: TP/FP/TN/FN per dimension, UNKNOWN excluded from precision and recall but
  gated through `answered`/`unresolved_rate`, ceilings, per-dimension gates, regression compare,
  markdown dashboard — 29 tests;
- the corpus, the two pipelines, and the CLI gate — 15 tests including a stale-dashboard check.

Already in the platform, and explicitly **not** rebuilt here: conflict classification
REAL-versus-EXPLAINED (`api/estate_conflicts.py`), per-component completeness
`UNMEASURED / INCOMPLETE / CONTRADICTED` (`cbom/inventory_completeness.py`), BOM depth ceilings
(`api/bom_maturity.py`), per-file scanner precision/recall (`scripts/accuracy_benchmark.py`).

Still open, stated so this guide is not read as more than it is:

- **estate-level coverage denominators** — 38/40 hosts inside a declared scope, measured against
  the bank's own register rather than against itself. Per-component completeness exists; the
  denominator join does not;
- **a confidence gate on identity** — canonical asset identity with aliases, and an
  `UNRESOLVED_RELATIONSHIP` instead of a name-based guess. The graph records identity; the "is
  this identity proven?" test before a relationship is created is not yet one rule;
- **the parser qualification matrix** — valid / malformed / duplicate / Unicode / huge /
  malicious per parser at ≥99% before qualification. The scanner corpus covers the crypto
  detectors, not every parser;
- **AI exclusion** — no model is in the factual path today, and there is no test that would fail
  if one were added. That test should exist;
- **real-estate accuracy** — every number above is rule conformance. The first honest bank number
  comes from a bank.
