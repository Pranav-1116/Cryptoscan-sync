# Detection accuracy — production source scanner

_Generated 2026-09-24T07:54:44+00:00 by `scripts/accuracy_benchmark.py` against the hard ground-truth corpus (`services/scanner/tests/accuracy/corpus.py`, 348 files). Scored per algorithm family per file._

## Overall

| Metric | Value |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| F1 | **100.0%** |
| Accuracy (TP+TN over all decisions) | **100.0%** |
| Files scored exactly right | 348 / 348 (100.0%) |
| TP / FP / FN / TN | 550 / 0 / 0 / 65 |

## By language

| Language | Files | Precision | Recall | F1 | Exact files |
|---|---|---|---|---|---|
| c | 31 | 100.0% | 100.0% | 100.0% | 31/31 |
| config | 30 | 100.0% | 100.0% | 100.0% | 30/30 |
| cpp | 3 | 100.0% | 100.0% | 100.0% | 3/3 |
| csharp | 28 | 100.0% | 100.0% | 100.0% | 28/28 |
| go | 26 | 100.0% | 100.0% | 100.0% | 26/26 |
| java | 42 | 100.0% | 100.0% | 100.0% | 42/42 |
| javascript | 37 | 100.0% | 100.0% | 100.0% | 37/37 |
| kotlin | 15 | 100.0% | 100.0% | 100.0% | 15/15 |
| php | 24 | 100.0% | 100.0% | 100.0% | 24/24 |
| python | 54 | 100.0% | 100.0% | 100.0% | 54/54 |
| ruby | 24 | 100.0% | 100.0% | 100.0% | 24/24 |
| rust | 26 | 100.0% | 100.0% | 100.0% | 26/26 |
| typescript | 8 | 100.0% | 100.0% | 100.0% | 8/8 |

## By category

| Category | Files | Precision | Recall | F1 | Exact files |
|---|---|---|---|---|---|
| config | 22 | 100.0% | 100.0% | 100.0% | 22/22 |
| negative | 64 | 100.0% | 100.0% | 100.0% | 64/64 |
| obfuscated | 18 | 100.0% | 100.0% | 100.0% | 18/18 |
| positive | 244 | 100.0% | 100.0% | 100.0% | 244/244 |

## Misses

None — every file in the corpus was scored exactly.

## Held-out first-pass history

Each corpus wave is written blind (labels from the code, before any rule is touched) and scored once *before* fixes.
That first-pass number is the honest estimate of accuracy on unseen code; the table above is the score after the
misses were fixed and locked in as regression tests.

| Wave | Files added | First-pass P / R / F1 | After fixes |
|---|---|---|---|
| 1 — baseline corpus (199 files) on the pre-existing parsers | 199 | — / — / 0.660 | F1 1.000 (199/199 exact); first pass was 106/199 exact |
| 2 — real-world idioms: frameworks, kill-switches, cipher strings, PRNG-for-tokens, config | 91 | 0.968 / 0.899 / 0.932 | F1 1.000 (290/290) |
| 3 — platform/mobile/infra: CommonCrypto & ObjC, Scala, Django/Flask settings, k8s/CloudFormation/Azure/DB configs, gradle.kts | 58 | 0.994 / 0.912 / 0.951 | F1 1.000 (348/348) |

## How to read this

- **Precision** — of the algorithm families the scanner reported, how many were really there. Low precision = noise.
- **Recall** — of the algorithm families really present, how many the scanner found. Low recall = blind spots.
- Labels are written by hand from the code, never copied from scanner output; a scanner change that flips a label is a corpus bug and is reviewed as such.
- The negative set is deliberately hostile: `md5sum` paths, `description`/`shader`/`desired` identifiers, CRC32/base64/UUID, git SHAs, hash maps, comments quoting crypto APIs.
- Regenerate: `python scripts/accuracy_benchmark.py --md docs/accuracy/REPORT.md --json docs/accuracy/report.json`.
