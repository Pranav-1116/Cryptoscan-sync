# Approved-host qualification — intake and return record

**Blank operator/reviewer form. No field below is an approval or a completed test.**
Use with the [operator handoff](../runbooks/approved-host-qualification-handoff.md). Do not enter passwords, private keys, bearer tokens or TPM authorization values. Use approved internal references instead of confidential details where required.

## A. Before execution — owner completes

- Campaign / tenant / system references:
- Approved scope and acceptance criteria reference:
- Approved runtime release and platform source-lock identifiers:
- Authorized Linux host reference; actual systemd/DMI/TPM2 availability:
- Authorized Windows host reference; OS/account/ACL qualification reference:
- Read-only resources/service names and exclusions:
- Approved collection window, timezone and stop contact:
- Data classification and approved transfer/retention channel:
- Linux operator / Windows operator:
- TPM/enrollment custodian / verifier operator:
- Independent assessor / organization / independence-check reference:
- Bank acceptor / organization / separation-of-duties reference:
- Public reviewer key enrollment / trusted policy references:
- Public AK/qualified-signer/PCR/counter enrollment reference:
- Full deployed-worker/adversarial test procedure reference:
- Scope approval by / time / evidence reference:

### Plans agreed before measurement

| Category | Target reference and canonical digest | Truth-plan reference and canonical digest | Approved expected facts/counts | Approver / time |
|---|---|---|---|---|
| systemd | | | | |
| dmi | | | | |
| tpm | | | | |
| windows (SCM + OS) | | | | |

## B. Native execution — each host operator completes

| Category | Actual host / OS / account reference | Start / finish / timezone | Exit status | Original artifact SHA256 | Result / gaps / incident reference |
|---|---|---|---|---|---|
| systemd | | | | | |
| dmi | | | | | |
| tpm | | | | | |
| windows | | | | | |

- Interpreter/tool/release evidence references:
- Out-of-scope reads, privilege changes or modifications attempted (record explicitly; do not silently omit):
- Stop conditions triggered / owner notified:
- Original stdout/exit/approval records retained at:

## C. Quote round trip — verifier and custodian complete

- Exact host/tenant/result covered (do not imply cross-host coverage):
- Target / source-lock / snapshot / committed worker-claim digests:
- Enrollment policy reference and digest:
- Verifier challenge ID / issue / expiry / timezone:
- External TPM agent/tool/version and approved authorization reference:
- Public raw TPMS_ATTEST artifact SHA256:
- Public TPMT_SIGNATURE artifact SHA256:
- Public quoted-PCR JSON artifact SHA256:
- Verification exit status / report SHA256 / evidence reference:
- Consumption/recovery/expiry incidents:
- EK/AK hardware-origin establishment evidence or explicit unresolved limitation:
- Measured executable/boot/event-log/UTC limitations:

## D. Full-worker assessment — independent assessor completes

Do not pre-mark PASS. Record actual observed evidence and a decision for each row.

| Check | Actual procedure / original evidence hashes | PASS / FAIL / NOT_RUN | Findings / limitations / remediation |
|---|---|---|---|
| native_systemd | | | |
| native_dmi | | | |
| native_tpm | | | |
| native_windows | | | |
| host_enrollment | | | |
| quote_replay_and_pcr | | | |
| worker_authority | | | |
| worker_isolation | | | |
| worker_cancellation | | | |
| worker_cleanup | | | |
| evidence_export | | | |
| key_custody | | | |
| recovery | | | |
| adversarial_retest | | | |

- Exact deployed configuration/release assessed:
- Unexpected results and residual risks:
- Assessor's scoped decision / evidence reference:
- Signed statement/envelope reference and expiry:

## E. Bank acceptance — bank acceptor completes independently

- Evidence reviewed / frozen policy and index digests:
- Accepted scope and explicitly excluded claims:
- Organizational independence/separation checks performed:
- Outstanding findings / rejection / conditions:
- Bank acceptor's own scoped decision and evidence reference:
- Signed statement/envelope reference and expiry:

## F. Verification and next-stage authorization — owner completes

- Original artifact transfer/integrity check:
- Separate signature/key/role checks:
- Independent-record verification exit / report reference:
- Unresolved gates (including hardware-origin and production adapter):
- Authorized next action / decision owner / approval reference:

**Default status: WAITING FOR EXTERNAL EXECUTION/REVIEW.** Filling this form does not make evidence genuine, establish hardware origin, enable production or replace the original signed statements and artifacts.
