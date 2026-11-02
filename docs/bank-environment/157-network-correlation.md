# Network crypto correlation: several changes, one pattern, no verdict

`cryptoscan.nbom-patterns-guide/1` · generated 2026-11-02T19:19:16.007830+00:00 · **5 pass · 0 partial · 0 fail** · 27 probes

Review item 19: a TLS downgrade plus a certificate mutation plus a new endpoint plus a new process is a `CORRELATED_PATTERN` at `SUSPICIOUS_ACTIVITY` — never "attack detected".

```
change ─┐
change ─┼→ signals in one window → pattern (level ≤ 2) → review queue
change ─┘                              └─ not_proven: compromise, actor, intent
```

6 network crypto signal(s) in one 3600s window ending 2026-11-02T00:00:00+00:00

4 pattern(s) in one window; the strongest is SUSPICIOUS_ACTIVITY (CORRELATED_PATTERN, NETWORK_CRYPTO_REGRESSION, TRUST_PATH_SHIFT). This is a reason to investigate, not a finding of compromise

| signal | derived from |
|---|---|
| `TLS_DOWNGRADE` | `TLS_VERSION_CHANGED` with direction `DOWNGRADE` |
| `CIPHER_DOWNGRADE` | `CIPHER_SUITE_CHANGED` with direction `DOWNGRADE` |
| `CERTIFICATE_MUTATION` | `CERTIFICATE_CHANGED` (rotation and replacement look alike) |
| `TRUST_PATH_CHANGE` | `TRUST_PATH_CHANGED` |
| `NEW_ENDPOINT` / `ENDPOINT_LOST` | `ENDPOINT_ADDED` / `ENDPOINT_REMOVED` |
| `NEW_PROCESS` | a runtime trace on the host |

| pattern | level | when |
|---|---|---|
| `NETWORK_CRYPTO_REGRESSION` | 2 `SUSPICIOUS_ACTIVITY` | any weakening in the window |
| `TRUST_PATH_SHIFT` | 2 `SUSPICIOUS_ACTIVITY` | downgrade **and** certificate replacement on one endpoint |
| `NEW_EXPOSURE` | 1 `UNEXPECTED_CHANGE` | a listener appeared |
| `DISAPPEARANCE` | 1 `UNEXPECTED_CHANGE` | a listener went away |
| `CORRELATED_PATTERN` | 2 `SUSPICIOUS_ACTIVITY` | ≥2 of the review's four signals, at least one a weakening |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_signals` | which changes are signals, and in what window? | **PASS** | 5, 0 failing |
| `one_pattern` | what does the coincidence of these changes amount to? | **PASS** | 6, 0 failing |
| `what_it_refuses` | what does the answer refuse to claim, and does it say so? | **PASS** | 6, 0 failing |
| `the_guards` | what keeps a maintenance window out of the suspicious bucket? | **PASS** | 5, 0 failing |
| `the_shape` | does the pattern read like every other finding in the platform? | **PASS** | 5, 0 failing |

## `the_signals` — PASS

*which changes are signals, and in what window?* (review 19)

- **PASS** `the-review-s-four-changes-become-four-signals` — CERTIFICATE_MUTATION, CIPHER_DOWNGRADE, NEW_ENDPOINT, NEW_PROCESS, TLS_DOWNGRADE, TRUST_PATH_CHANGE
- **PASS** `the-window-is-stated-in-the-answer` — 3600s ending 2026-11-02T00:00:00+00:00
- **PASS** `an-upgrade-is-a-change-and-not-a-signal` — TLS1.2 → TLS1.3 produced no signal
- **PASS** `a-signal-with-no-timestamp-is-not-correlated` — an undated change cannot sit in a window
- **PASS** `a-new-process-is-bound-to-the-host-it-was-seen-on` — the process is attributed to its host, not to an application

## `one_pattern` — PASS

*what does the coincidence of these changes amount to?* (review 19)

- **PASS** `the-four-signals-become-one-correlated-pattern` — CERTIFICATE_MUTATION, NEW_ENDPOINT, NEW_PROCESS, TLS_DOWNGRADE
- **PASS** `the-pattern-is-classified-suspicious-activity` — level 2 · SUSPICIOUS_ACTIVITY
- **PASS** `the-pattern-names-its-subjects-and-both-sides-of-the-evidence` — new.bank.example:9443, payments.bank.example, payments.bank.example:443
- **PASS** `each-participating-signal-is-still-listed-separately` — 4 signal(s) inside one pattern
- **PASS** `the-next-action-is-an-investigation-not-a-containment` — open one investigation covering the listed subjects and evidence ids, and confirm or dismiss each signal separately — do not treat the combination as a single finding
- **PASS** `the-strongest-thing-said-is-suspicious-activity` — 4 pattern(s) in one window; the strongest is SUSPICIOUS_ACTIVITY (CORRELATED_PATTERN, NETWORK_CRYPTO_REGRESSION, TRUST_PATH_SHIFT). This is a reason to investigate, not a finding of compromise

## `what_it_refuses` — PASS

*what does the answer refuse to claim, and does it say so?* (review 19)

- **PASS** `no-pattern-contains-a-verdict-phrase` — a downgrade plus a new process is not an attack
- **PASS** `security-incident-is-named-as-something-this-never-returns` — attack detected, compromise confirmed, attacker identified, SECURITY_INCIDENT
- **PASS** `every-pattern-carries-what-it-does-not-prove` — 4 pattern(s), all with not_proven
- **PASS** `attribution-and-intent-are-explicitly-absent` — who did it, or whether it was done at all: no actor, no motive and no external intelligence take part in this correlation
- **PASS** `the-statement-ends-with-not-a-finding-of-compromise` — This is a reason to investigate, not a finding of compromise
- **PASS** `a-collection-gap-is-carried-as-a-blind-spot` — an endpoint that stopped answering narrows what the window means

## `the_guards` — PASS

*what keeps a maintenance window out of the suspicious bucket?* (review 19)

- **PASS** `a-new-endpoint-and-a-new-process-alone-stay-at-level-one` — 1 pattern(s) in one window; the strongest is UNEXPECTED_CHANGE (NEW_EXPOSURE). This is a reason to investigate, not a finding of compromise
- **PASS** `a-lone-certificate-replacement-is-a-regression-not-a-combination` — NETWORK_CRYPTO_REGRESSION
- **PASS** `a-disappeared-listener-is-reported-as-ambiguous` — DISAPPEARANCE at level 1
- **PASS** `a-window-that-is-not-a-window-is-refused` — a foreign document is rejected, not correlated
- **PASS** `the-signal-set-is-fixed-so-a-reviewer-can-see-what-is-modelled` — 10 signal(s), ceiling level 2

## `the_shape` — PASS

*does the pattern read like every other finding in the platform?* (review 19)

- **PASS** `patterns-carry-the-shared-vocabulary-s-level-and-meaning` — SUSPICIOUS_ACTIVITY: several related changes in one window that a sin…
- **PASS** `the-pattern-id-is-stable-for-the-same-participants` — NPAT-4f03963f54d3d5f3
- **PASS** `first-and-last-seen-bound-the-pattern` — 2026-11-02T00:00:00+00:00 → 2026-11-02T00:00:00+00:00
- **PASS** `the-summary-counts-patterns-by-name-and-carries-the-blind-spots` — 4 pattern(s) in one window; the strongest is SUSPICIOUS_ACTIVITY (CORRELATED_PATTERN, NE…
- **PASS** `nothing-in-the-summary-invents-a-score` — blind_spots, by_name, not_proven, patterns, schema, statement, worst

## What this does not prove

- one window is one comparison. An attacker who waits longer than the window, or who changes nothing a collector can see, produces no pattern — an empty result is not a clean estate
- the window is anchored on the newest signal in the set, so the same stored changes always correlate the same way; widening it finds more coincidence as well as more pattern
- a certificate replacement is indistinguishable from an interception without the PKI's own record, so the pattern points at the PKI owner instead of deciding
- a new process is attributed to the host it was observed on, not to the application that started it; process-level evidence is guide 146's job
- the ceiling is level 2. The platform reserves level 4 for combinations it can corroborate across independent planes, and one network window is one plane
- no external intelligence, no actor and no motive take part. The output is a review queue with evidence ids, not an incident
