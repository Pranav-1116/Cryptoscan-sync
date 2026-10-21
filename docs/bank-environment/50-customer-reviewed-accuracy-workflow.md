# 3.5 — Customer-reviewed accuracy, preserved first pass and held-out repeat

## Approval and frozen predictions

A sample proposal contains approved scan IDs, scope/selection method, domain-owner
label **and durable user ID**, approval reference, blind spots and explicit
FIRST_PASS/HOLDOUT units. Unit = file × algorithm family within an unambiguous
approved scan. The current positive definition is **file/algorithm observation**;
security relevance is assessed separately, not silently substituted as ground
truth for algorithm detection.

Fixtures are uploaded as approved, redacted opaque evidence blobs. The actual
scanner now records matching pre/post SHA-256 and successful primary-source
parser completion for at most 1,000 files, each at most 1 MiB. Missing, changed,
failed, oversized, linked or ambiguous file receipts cannot establish a negative
or held-out observation. The API requires the uploaded fixture hash to match
exactly one scan's parsed-file receipt. An old completed Scan with no byte receipt
must be recollected, not grandfathered into high accuracy.

Receipts cover primary discovered source files only—not archive members,
secondary collectors, whole-register completeness or an atomic snapshot of a
mutable legacy checkout. Controlled production additionally uses existing private
staging and read-only isolated parsing. New parser images must be rebuilt.

The server freezes predictions and evidence IDs/hashes/locations from SQL; callers
cannot submit precision/recall or predicted booleans. It does not merge same-name
files across repositories. First-pass/held-out fixture bytes must be disjoint;
held-out hashes already in this estate's regression register are rejected.
A matching single-file receipt also does not bind every surrounding wrapper,
provider, dependency, configuration file or runtime environment; retain the full
approved fixture/release context separately for context-sensitive regressions.
Exact-hash checks cannot detect semantic near-duplicates or prevent an authorized
human from leaking hold-out content: customer evaluation access/process controls
and independent selection are still required.

The nominated domain owner must be active, entitled to review, and an estate
member (or explicitly selected platform administrator). Only that durable human
ID may approve/review the sample, and it cannot be the proposer. A copied owner
label, API key or stale/revoked session is not review authority.

## Practical loop

1. `POST /assurance/evidence-blobs?evidence_ref=...` with approved raw fixture
   bytes; retain the returned blob IDs. Raw download is limited to CISO/admin
   human sessions because quarantine bytes may be sensitive.
2. `POST /assurance/samples` with scope, selection, owner ID and unit file,
   algorithm, source class, partition and fixture blob ID.
3. The nominated, different domain owner approves `/samples/{id}/approve` with
   the current expected revision and actual approval evidence reference.
4. Read `/samples/{id}/workbook?phase=FIRST_PASS`. For **every** frozen unit,
   return PRESENT/ABSENT/UNREVIEWED truth and explanation to `/samples/{id}/reviews`.
   Unknown/duplicate/invented/omitted units are refused. The server calculates
   TP/FP/FN/TN from frozen predictions; zero denominators remain `null`, not 100%.
5. First-pass review is write-once. A second submission returns 409. The original
   observations and predictions remain in immutable revision history.
6. `/samples/{id}/regressions` idempotently registers confirmed FP/FN/TN seeds,
   with fixture hash, actual customer truth and original first-pass review hash.
   **A seed is not a passing executable test.** Export only approved de-identified
   fixtures into the scanner regression suite or submit an approved controlled
   scan of those fixtures. `/regressions/{case_id}/results` checks a newer completed
   scan, exact parsed-file byte hash and actual evidence against the confirmed
   label and records the server-computed PASS/FAIL. It never launches a privileged
   parser on uploaded bytes or trusts caller-submitted test totals.
7. Run the held-out partition after the first review, using new scan receipts in
   the approved target scope. `/samples/{id}/repeat` freezes that new evidence;
   old run IDs, pre-review runs, contaminated or changed fixture bytes are refused.
8. Review the HOLDOUT workbook independently. It gets its own immutable result,
   never overwrites or pools away the first pass.

## Source-class reporting and blind spots

The report retains scope, per-class confusion counts, unreviewed units, undefined
rates, explicit blind spots and uncovered source classes. Classes include source,
wrappers/config, native providers, legacy/mainframe, obfuscated mobile,
proprietary exports, runtime logs, network, hardware and supplier evidence.
A class label is not a declaration that its parser/profile is qualified. A source
class without actual parsed-file evidence cannot be scored through this lane;
it stays uncovered until its own qualified source receipt path exists.

No representative customer samples or domain-owner votes were supplied in this
repository task. Synthetic auth/SQL fixtures test the workflow and real owned
source fixtures test byte capture; **neither is customer-measured accuracy**.
No global 100% claim is generated.

## Legacy compatibility

The older `/scans/{id}/triage` API still accepts its historical workbook/pre-scored
contract in development. It now exact-filters the estate, retains immutable
`legacy_triage` revisions and labels pooled metrics as unapproved submitted
triage, with `approved_customer_sample=false`, `global_accuracy_claim=false`.
An existing newest-only projection can be imported into history; earlier
previously overwritten reviews cannot be recovered or invented. Legacy metrics
are not promoted into the new approval/frozen/held-out workflow. Actual legacy
users now need a valid estate membership; no automatic tenant reassignment is
performed. Controlled production still refuses that old API surface.
