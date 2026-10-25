# 06 — Access, evidence, privacy and governance

[FAQ index](README.md) · Questions Q061–Q070.

## Q061. Who authorizes, runs and reviews a scan?

Keep purpose/scope approval, operation and acceptance distinct. Application owners identify the service/release and risk; entitled administrators/CISO authorize under the relevant route contract; operators collect or execute approved work; reviewers inspect evidence; independent/customer authorities accept only the scope they actually reviewed.

An owner label, analyst role or platform administrator account is not blanket permission to access every estate or production target. Use current session, selected estate, system membership, revision, expiry and method-specific entitlement checks. Signed external reviews do not create people, independence or authority by themselves.

## Q062. How is one bank or estate prevented from reading another's results?

Private routes must bind access to the current durable identity and selected estate/system, enforce ownership/residency and recheck evidence integrity where required. Browser private state must be cleared or ignored on scope/authentication changes; that complements, not replaces, backend enforcement.

Do not describe tenant labels or browser dropdowns as the isolation boundary. Retain cross-estate, revoked-user, unselected-administrator and changed-original negative tests for the exact deployed routes. Shared infrastructure and host-runtime isolation require their own qualification; repository tests alone do not certify a hostile multi-bank service.

## Q063. Does CryptoScan require root, Domain Admin or private-key access?

Those are not the default architecture. The bounded host candidates require ordinary-user/least-privilege execution and refuse elevated execution under their contracts. The controlled source parser must not receive bank credentials or the wider host environment.

Do not request private keys/PFX, HSM PINs, TPM authorization secrets or copied vault values to obtain inventory. An unavailable public metadata interface remains a gap until the bank approves a suitable method; do not escalate automatically or broaden access to make the report green.

## Q064. What is retained as evidence, and can it contain sensitive data?

Depending on the workflow, evidence can include source-derived locations/content, snapshots, allowed metadata, timestamps, manifests, original supplied documents, hashes, reviews and error receipts. Source/supplier artifacts, paths, hostnames and logs can all be sensitive even without keys.

Do not promise that “metadata only” means no customer content anywhere. Inventory actual database/object/file/log/temp/backup fields, classify them, minimize them and restrict raw access. For recent Windows candidates, selected typed metadata is retained, not a process memory dump, private key or provider pointer graph.

## Q065. What do OBSERVED, DECLARED, IMPORTED, INFERRED and UNKNOWN mean?

| Term | Use |
|---|---|
| OBSERVED | The stated fact was obtained through the specified interface; interpret only that interface's meaning |
| DECLARED | A configuration/document/operator/vendor states it; not necessarily effective runtime behavior |
| IMPORTED | Transport/origin basis for supplied evidence; does not authenticate the producer's claims |
| INFERRED | A disclosed deterministic relationship/rule supports the conclusion, not direct operation observation |
| UNKNOWN | Evidence does not establish the requested fact/relationship |

FAILED, UNREACHABLE, DENIED and UNSUPPORTED describe acquisition outcomes/gaps, not positive provenance or absence. Contracts use their own exact status enums; do not force every word into one provenance field. Local OBSERVED and imported transport can coexist without contradicting each other.

## Q066. What do hashes and signatures actually prove?

A hash binds/checks bytes or a canonical representation; it does not identify a host, prove the collector executed, establish supplier truth or grant authorization. A path-text hash is not a file-content hash.

A valid signature establishes that an accepted key signed the verified statement/bytes under the applicable trust rules. It does not independently prove organizational authority, physical residency, native execution, factual accuracy or bank acceptance. Preserve source-lock, identity, custody and review limitations rather than label every signed package “attested.”

## Q067. How are supplier SBOMs, CBOMs and questionnaires handled?

Use exact customer/product/build/revision binding, origin/integrity checks, bounded format validation, quarantine and separate entitled review under the supported supplier path. A trusted signer does not remove quarantine or prove payload truth.

Wrong-customer/build, stale, revoked, malformed and untrusted cases must remain visible and must not produce observed capability. A declaration “supports ML-KEM” remains declared evidence until independently demonstrated through the approved method. Do not fetch arbitrary document URLs or execute vendor-provided code as a parsing shortcut.

## Q068. Where may AI be used, and can bank data be sent to an AI provider?

AI may assist explanation, remediation suggestions, summaries and ambiguous-evidence review. It must not create OBSERVED algorithms, versions, hardware, dependencies or migration success. Deterministic evidence must establish facts first.

An external AI service is a separate data-processing/integration decision requiring bank permission, supported profile availability, classification, residency and egress review. This FAQ does not authorize it or claim an AI connector is enabled. Keep sensitive evidence inside the approved boundary unless an explicit reviewed transfer is permitted.

## Q069. Can auditors download every raw artifact and evidence bundle?

No. Read access, metadata export and raw-byte download are different privileges. The existing host/supplier contracts restrict raw custody more tightly; an auditor/viewer designation does not automatically grant raw source or quarantined supplier downloads.

Check current role/estate, regional storage, original integrity, supplier trust/review state and route admission before disclosure. Apply bank retention/legal-hold/export policy. Do not bypass denied downloads by reading the database directly or creating an unrestricted support archive.

## Q070. Can CryptoScan claim FIPS, PCI DSS, ISO or “PQC ready” compliance from a scan?

Not from a label, schema-valid BOM, cipher name or vendor questionnaire alone. Such conclusions require exact product/version/module/mode, applicable controls, evidence and authorized assessment. A FIPS-related string does not establish the deployed validated configuration.

PQC planning also needs implementation, protocol, hardware/vendor compatibility, key-management and dependency evidence. Report unsupported or unverified criteria explicitly. CryptoScan can support an assessment; it does not manufacture certification, regulator approval, independent audit or migration compatibility.

### References

[Qualified supplier quarantine](../bank-environment/52-qualified-adapters-and-supplier-quarantine.md) · [purpose/applicability evidence](../bank-environment/51-purpose-and-applicability-assessments.md) · [native/review boundaries](../bank-environment/67-native-quotes-and-independent-qualification.md) · [assigned operator workflow](../bank-environment/68-assigned-operator-qualification-workflow.md)
