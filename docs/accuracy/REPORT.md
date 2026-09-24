# Detection accuracy — production source scanner

_Generated 2026-09-24T07:46:50+00:00 by `scripts/accuracy_benchmark.py` against the hard ground-truth corpus (`services/scanner/tests/accuracy/corpus.py`, 290 files). Scored per algorithm family per file._

## Overall

| Metric | Value |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| F1 | **100.0%** |
| Accuracy (TP+TN over all decisions) | **100.0%** |
| Files scored exactly right | 290 / 290 (100.0%) |
| TP / FP / FN / TN | 447 / 0 / 0 / 52 |

## By language

| Language | Files | Precision | Recall | F1 | Exact files |
|---|---|---|---|---|---|
| c | 26 | 100.0% | 100.0% | 100.0% | 26/26 |
| config | 18 | 100.0% | 100.0% | 100.0% | 18/18 |
| cpp | 3 | 100.0% | 100.0% | 100.0% | 3/3 |
| csharp | 24 | 100.0% | 100.0% | 100.0% | 24/24 |
| go | 22 | 100.0% | 100.0% | 100.0% | 22/22 |
| java | 37 | 100.0% | 100.0% | 100.0% | 37/37 |
| javascript | 33 | 100.0% | 100.0% | 100.0% | 33/33 |
| kotlin | 11 | 100.0% | 100.0% | 100.0% | 11/11 |
| php | 20 | 100.0% | 100.0% | 100.0% | 20/20 |
| python | 48 | 100.0% | 100.0% | 100.0% | 48/48 |
| ruby | 20 | 100.0% | 100.0% | 100.0% | 20/20 |
| rust | 22 | 100.0% | 100.0% | 100.0% | 22/22 |
| typescript | 6 | 100.0% | 100.0% | 100.0% | 6/6 |

## By category

| Category | Files | Precision | Recall | F1 | Exact files |
|---|---|---|---|---|---|
| config | 13 | 100.0% | 100.0% | 100.0% | 13/13 |
| negative | 51 | 100.0% | 100.0% | 100.0% | 51/51 |
| obfuscated | 18 | 100.0% | 100.0% | 100.0% | 18/18 |
| positive | 208 | 100.0% | 100.0% | 100.0% | 208/208 |

## Misses

None — every file in the corpus was scored exactly.

## How to read this

- **Precision** — of the algorithm families the scanner reported, how many were really there. Low precision = noise.
- **Recall** — of the algorithm families really present, how many the scanner found. Low recall = blind spots.
- Labels are written by hand from the code, never copied from scanner output; a scanner change that flips a label is a corpus bug and is reviewed as such.
- The negative set is deliberately hostile: `md5sum` paths, `description`/`shader`/`desired` identifiers, CRC32/base64/UUID, git SHAs, hash maps, comments quoting crypto APIs.
- Regenerate: `python scripts/accuracy_benchmark.py --md docs/accuracy/REPORT.md --json docs/accuracy/report.json`.
