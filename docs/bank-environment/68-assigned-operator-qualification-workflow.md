# 68. Assigned-operator qualification in the product

**Implemented intake/review workflow, not completed bank qualification.** No real operators, approved hosts, channel approvals, original exports or independent signatures have been supplied in this session. No person has been contacted and no host dispatched. Do not send credentials or private keys.

This continues [guide 67](67-native-quotes-and-independent-qualification.md), the [operator execution packet](../runbooks/approved-host-qualification-handoff.md) and [blank intake record](../templates/host-qualification-intake.md). It adds controls to the existing API/storage and **Crypto & key assurance → Host qualification** tab, not a new service, collector, remote agent or dashboard.

## 1. Establish authority and a real return channel

The bank/change owner must first approve the actual hosts, ordinary-user permissions, resources, target/truth plans, release, time window, stop conditions, public evidence classification and return/retention channel. Reviewers' two distinct **public** Ed25519 keys are pinned in the approved `AcceptancePolicy`; private signing material stays with each reviewer outside the product.

Sign in normally to the product and select the exact tenant. A current trust-authorized human creates the campaign by pasting the approved policy, a change/evidence reference and the actual `return_channel_reference`. This last field is an internal bank approval **reference**, not a destination URL, password, bearer token or network instruction. It is required and immutable along with the policy/campaign identity. The software records the trusted human's reference; it does not verify the approval in another system or attest the channel.

**An authenticated receipt endpoint is not proof of bank-approved secure transport.** The bank must separately approve and configure its ingress/TLS, identity access, tenancy/residency, logging, retention, device/workstation controls and any external transfer mechanism. Do not send bank metadata over an unapproved preview endpoint. The application neither provisions that channel nor sends files to an arbitrary remote address. Public cryptographic material can still contain confidential internal labels or paths.

## 2. Assign actual people before returning originals

Use user IDs from the bank's existing authorized user administration. The UI never seeds demonstration people. Paste a role-to-assignee JSON object in **Assign humans**. Example **shape only, deliberately not valid executable IDs**:

```json
{
  "linux_operator": {"user_id": "<actual active tenant user UUID>"},
  "windows_operator": {"user_id": "<actual active tenant user UUID>"},
  "verifier": {"user_id": "<actual active tenant user UUID>"},
  "independent_assessor": {
    "user_id": "<actual active tenant user UUID>",
    "reviewer_id": "<pinned assessor reviewer_id>"
  },
  "bank_acceptor": {
    "user_id": "<different actual active tenant user UUID>",
    "reviewer_id": "<pinned bank-acceptor reviewer_id>"
  }
}
```

Partial assignments may be saved before evidence intake; **all five** responsibility slots must be valid before an original or decision is accepted. Assignments replace the current map, rather than silently merging omitted slots.

- Users must currently exist, be active/not deleted, have non-viewer membership in the selected ACTIVE tenant and retain the role permission needed for their responsibility. Platform campaigns require platform-authorized assignees.
- Both reviewers must be different user identities from each other, every assigned operator/verifier and the original policy approver. Reviewer IDs must match the pinned policy role/key. Operators/verifier may be the same person if local bank policy permits; organizational separation is not inferred from software roles.
- Operators/verifier need `assurance.manage`; reviewers need `assurance.review`. Creating/assigning/withdrawing requires `assurance.trust`. A permission alone does not substitute for the campaign's human assignment.
- Display names/usernames are resolved from actual current user records; stable user IDs remain in the append-only record. A name is not proof of employment, independence or host ownership.
- Assignments freeze after the first original. To change people, key pins, scope, release or channel reference then, withdraw and explicitly authorize a fresh campaign. Reusing the same campaign identity is refused.

Assigning a person does **not** notify or contact them. The authorized owner distributes the packet through their approved operational process.

## 3. Execute externally; return exact public artifacts

Named operators execute [the existing packet](../runbooks/approved-host-qualification-handoff.md), on the bank-approved hosts, with the pre-agreed truth commitments. This screen cannot execute commands, discover machines, elevate privileges, create keys, obtain TPM authorization or turn missing interfaces into observations.

In the matching campaign:

1. Enter a change/evidence reference.
2. Choose **Native receipt** and select the exact original JSON file. The assigned Linux operator submits systemd/DMI/TPM receipts; the assigned Windows operator submits Windows receipts.
3. Return supporting public records using **Supporting public JSON**. Assigned operators/verifier can return these and the narrowly parsed **Raw TPM public quote/signature** structures.
4. Keep stdout/exit status/approvals and any non-uploadable material in the separate bank-approved evidence store, referenced by permitted public JSON. This endpoint is not a general file/document/archive store.

The client uploads unchanged file bytes, not JSON reserialization. The server computes the artifact digest, validates the native report's approved plan/source identifier and scope/truth contract, and records the actual submitter, assigned responsibility, evidence reference, kind, byte count and native result. A valid negative/gap native report can be retained; it is never changed into a positive. Duplicate originals are refused instead of appending duplicate history.

Bounds: nonempty **≤2 MiB per original**, **≤256 unique artifacts / ≤16 MiB total**, **≤320 campaign revisions**, with the last reserved for durable withdrawal. Accepted forms are strict/bounded JSON or bounded raw public TPM structures; no ZIPs, arbitrary logs, scripts, private signer files or unrestricted binaries. Known credential-key names, private-key PEM/Bearer/basic-auth-URL patterns and duplicate JSON keys are refused. **This is not a secret-detection guarantee**: unfamiliar, encoded or disguised secret values cannot be reliably classified. The human remains responsible for public-only review before submission. Do not upload a private key to test the filter.

Authenticated original download retains the existing `assurance.raw` privilege. An auditor assignment does **not** silently grant raw-download permission. If a reviewer lacks that privilege, an authorized custodian must supply the exact originals through the separately approved channel. Never assess worker truth using only an on-screen state or a digest. Record and compare the original hashes.

## 4. Freeze a complete index; obtain separate external decisions

The assigned verifier prepares and submits the approved `EvidenceIndex` referencing **exactly all retained originals**. It must cover all four native categories and all fourteen existing checks:

`native_systemd`, `native_dmi`, `native_tpm`, `native_windows`, `host_enrollment`, `quote_replay_and_pcr`, `worker_authority`, `worker_isolation`, `worker_cancellation`, `worker_cleanup`, `evidence_export`, `key_custody`, `recovery`, `adversarial_retest`.

Missing/changed, unqualified or cross-plan native originals cannot freeze. Negative evidence is retained; do not rewrite it. If corrected evidence is subsequently submitted, the index must still reference all retained originals (for example in the relevant adversarial/recovery check), or the owner must explicitly start a new campaign. No worker check is marked executed merely because a JSON file is referenced. Once frozen, neither originals nor index can be changed.

**Export current public review record** supplies the immutable policy/index and retained signatures/metadata plus status evaluated at download time. It is not an archive of originals. Each real assessor/bank acceptor examines the actual relevant environments and originals, prepares their own fourteen-check statement and signs externally using the canonical format in guide 67. The product has no private signer and no default PASS statement. Return only the public `SignedReview` JSON while authenticated as the matching assigned human.

The signature must bind exact tenant/campaign/policy/index/release, pinned reviewer identity, checks and aware validity times (maximum seven days). Expired/future, wrong-key/identity/scope or modified signatures are refused. A valid signed `REJECT`, `FAIL` or `NOT_RUN` is **retained**, visibly blocks acceptance and cannot be overwritten. A second reviewer can still record their own independent decision. Revising a decision requires a new authorized campaign, not deleting unfavorable history.

## 5. Interpret states narrowly

| State | Meaning |
|---|---|
| `WAITING_FOR_ASSIGNMENTS` | Five valid responsibility slots are not complete |
| `WAITING_FOR_OPERATOR_EVIDENCE` | Assignments are current; original intake/index freeze is incomplete |
| `WAITING_FOR_SEPARATE_SIGNED_REVIEWS` | Frozen originals/index verify; both qualified positive decisions are not yet present |
| `SCOPED_EXTERNAL_RECORD_VERIFIED` | Exact retained evidence and both distinct pinned positive statements verify at read time |
| `BLOCKED` | Assignment authority changed, a signed decision rejects/leaves unresolved checks, or evidence/review verification/expiry fails |
| `WITHDRAWN` | Trust-authorized owner explicitly stopped this campaign; no further mutation allowed |

Every GET/export recomputes state and rechecks current user authority and review validity. Blob/hash-chain corruption refuses rather than retaining a green result. UI state is labeled with evaluation time; refresh before relying on it. Invalidation on tenant/auth/storage/resume/history changes clears sensitive drafts and results; delayed file reads cannot be uploaded under a newly selected tenant. Aborting a browser request **cannot roll back** a write already committed in the original scope. On uncertainty or HTTP 409, reload before an explicit retry; there is no automatic stale-revision retry.

`NOT_DISPATCHED_NO_REMOTE_EXECUTION` and `AUTHENTICATED_API_REQUIRES_BANK_APPROVED_TRANSPORT` remain explicit. `host_identity_attested`, `full_worker_production_clearance` and `production_execution_qualified` remain **false even for the verified-record state**. Two signatures establish pinned-key statements over scoped bytes, not organizational independence, hardware origin, executed-code provenance, actual worker isolation, a bank's deployment acceptance or full-bank coverage. Separate production admission/deployment approval remains required and unchanged.

All six BOMs (NBOM, CBOM, TechBOM, HBOM, VBOM, SBOM) remain evidence projections of existing scoped facts. This workflow does not invent observations, force unsupported completeness, treat UNKNOWN as absence, enable a production collector or change CycloneDX validation claims.

See the [API contract](../api-reference/host-qualification-workflow.md) and [validation report](../readiness-evidence/host-qualification-product-2026-10-25.md). The immediate external work still requires the bank's actual names, approvals, original host returns and independent public signatures—not credentials or private keys.
