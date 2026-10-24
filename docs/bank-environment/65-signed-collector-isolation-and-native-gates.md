# Signed collector handoff, isolated Linux stage and native fixture gates

**2026-10-24 · executable hardening increment, not production clearance**

[Linux profile](63-linux-collection-phase-two.md) · [Windows candidate](64-windows-collection-phase-three.md) ·
[Execution report](../readiness-evidence/collector-security-2026-10-24.md)

## 1. Approval-pinned signing identity is now enforced

This is an actual Ed25519 verification boundary, not a hash labeled authenticity.
An administrator/CISO with existing `assurance.trust` permission may pin a public
key/key ID and release identifier when creating a host approval or authorizing a
registered Linux target. No analyst-provided intake key becomes a trust anchor.
No private key argument, key generation in product code, network key discovery,
remote shell or HSM operation was added.

Add this object to `POST /api/v1/host-evidence/approvals`, or to the existing
`POST /api/v1/collection/targets/{id}/authorize` decision body:

```json
{
  "collector_identity": {
    "key_id": "bank-reviewed-collector-key-01",
    "public_key": "<canonical base64 of the reviewed 32-byte Ed25519 PUBLIC key>",
    "release_sha256": "<reviewed 64-hex release identifier>"
  }
}
```

Angle-bracket values above are **documentation placeholders**, not usable keys
or approvals. Preserve the existing system/manifest or expected-revision/reason/
evidence-reference fields. Requesting this policy does not enable production.

The durable approval stores that pin and a fresh 32-byte random challenge nonce.
The signature's canonical statement binds:

- Schema `cryptoscan.collector-statement/v1`;
- Exact approval ID and nonce;
- Key ID and approved release SHA-256 identifier;
- Exact host label, manifest commitment and full canonical snapshot commitment;
- Signed-at time inside the approval/collection/expiry window.

The collector signs **exact UTF-8 canonical statement bytes** (sorted keys,
compact separators, JSON-mode timestamp serialization, no trailing newline).
The statement and canonical base64 64-byte detached signature form
`collector_attestation` alongside `snapshot` in the existing intake body.
No new evidence database, inventory or collection endpoint is needed.

```bash
# Read-only approval export must come from the trusted, exact-estate API.
python scripts/collector_identity.py prepare \
  --approval approved-row.json --snapshot new-snapshot.json \
  --output exact-statement-to-sign.json

# An external approved signer signs those exact bytes. Keep private keys outside
# this tool. Assemble {"statement": <parsed statement>, "signature": <base64>}
# as proof.json, then optionally verify locally:
python scripts/collector_identity.py verify \
  --approval approved-row.json --snapshot new-snapshot.json \
  --proof proof.json --output new-verification-report.json
```

The CLI's approval file is a **trusted operator input**, not self-authenticating
JSON. An attacker who replaces that file can replace its local trust anchor.
Legacy SQLite API row `created_at` metadata may serialize as naive UTC; the CLI
normalizes only that trusted row metadata to UTC. Manifest/snapshot/signed-at
timestamps still require explicit offsets. The API independently verifies against
its own exact scoped immutable approval,
not the CLI's report or a caller-supplied policy.

### Intake/read/replay behavior

- For a policy-pinned approval, missing proof, wrong key/signature, altered nonce,
  host/manifest/snapshot/release/approval or invalid signing time cannot write a
  scan/evidence. Wrong-estate reads remain denied. Registry withdrawal/window
  admission still runs before a new intake.
- Signature and trust-policy commitments are retained/audited with existing
  append-only revisions. Inspection/export rechecks the external signature as
  well as the original snapshot/evidence closure; recomputing a local row hash
  cannot bless a forged signature.
- Exact signed idempotent replay returns the existing receipt, not a second
  collection. Omitting/changing the proof on that path is a downgrade mismatch.
- Historic valid signed evidence remains inspectable after expiry/withdrawal;
  that is historical verification, not current authorization or refreshed data.
- Signed receipts expose `collector_identity_verified=true` with basis
  `APPROVAL_PINNED_SIGNING_KEY_NOT_HOST_ATTESTATION`. Provenance remains IMPORTED,
  whole-host coverage false and cryptographic operational/PQC use UNKNOWN.
- Legacy unpinned **offline-development** approvals are unchanged. They cannot
  claim a supplied signature was verified; proof without an approved pin is
  refused. They do not acquire production clearance.

### What this authenticates—and what it does not

It authenticates possession of the pinned signing key for the exact approval-
bound statement, assuming that key remains secure. The release identifier is a
**signed approved claim**, not measurement of running Python, installed wheels,
executed source, hardware identity, clock integrity or enclave attestation.
Existing `scripts/verify_release_attestation.py` still separately verifies
externally signed release-image locks; it is not silently replaced by this
collector proof. Full signed release distribution, installed-artifact binding,
key custody/rotation/revocation operations and independent review remain gates.
For registry-bound policies, revoke/update/re-authorize a target to withdraw new
admission and pin a replacement key. Standalone approvals retain their existing
one-use/expiry contract; no global retroactive key-revocation service is claimed.

## 2. Actual Linux read-only process isolation

`--isolated` runs a fixed fresh Python child with the existing exact target spec.
It is not a generic command runner, `preexec_fn` in an API thread, privileged
container, Docker socket, shared network shell or elevated fallback.

```bash
python scripts/collect_host.py --target-spec reviewed-linux-target.json \
  --isolated --output new-isolated-snapshot.json
```

### Enforced stage profile: `linux-landlock-seccomp/v1`

| Control | Implementation / boundary |
|---|---|
| Account | Actual ordinary Linux user, no effective/permitted capabilities; no elevation calls |
| Filesystem | Landlock grants READ_FILE on validated exact source leaf descriptors only; no directory recursion, unapproved content reads or filesystem mutation |
| Traversal | Existing no-follow/type/filesystem/hardlink checks; ancestor handles now use O_PATH so traversal does not grant directory listing |
| Kernel profile | Linux x86_64 only, Landlock ABI ≥1; unsupported kernel/architecture refuses the stage |
| Syscalls | Architecture-checked seccomp allowlist; network socket/connect, fork/clone/exec, ptrace, io_uring, filesystem mutation, arbitrary ioctl/fcntl and cross-process prlimit are denied |
| Old Landlock truncate gap | Explicit open/openat flags filter blocks O_RDONLY\|O_TRUNC as well as write/create/append/tmpfile; no openat2 escape |
| Output | Only stdout/stderr writes; inherited unrelated descriptors closed, stdin is a bounded owned target spool; ≤1.5 MB result |
| Limits | 10-second CPU, 512 MiB address space, 64 descriptors, no core/regular-file output; parent wall deadline defaults to 15 seconds, bounded 1–30 through the internal runner |
| Process lifecycle | Sanitized environment, isolated Python startup/no bytecode writes, fixed child command, private temporary cwd, kill/reap process group on timeout/overflow/failure; no unsandboxed retry |

Imports/typed target parsing and descriptor validation happen before the metadata
stage installs its irreversible kernel restrictions. Untrusted file-format parsing
and collection happen **after** them. This is stage isolation, not a claim that
all launcher startup or API JSON parsing already occurs in a sandbox.

Supported isolated kinds: public certificate, nginx literals, binary header,
dpkg status, Alpine installed metadata, OS-release and bounded SQLite RPM export.
**Live proc/sysfs interfaces, systemd bus/subprocess and Windows are refused by
this isolated profile**, not retried outside it. They require separate reviewed
policies. Landlock's restrictions are primarily file-content access; they are not
PID/network namespaces or complete metadata/covert-channel isolation.

Native kernel witnesses actually attempted and were denied: unapproved content
read, write-open, read-only truncate, unlink, socket creation, fork, exec,
io_uring and cross-process prlimit. Approved read still succeeded and files were
unchanged. Separate controlled-child witnesses exercised deadline/output overflow
and reaping. These are real OS-policy tests, **not mocks claiming isolation**.

### Production boundary

This file-stage primitive is executable and demonstrated, but the application
still has no production host execution admission, production worker dispatch or
Windows production permission. It does not turn offline handoff into a remotely
running job. Dedicated runtime-interface policies, worker/scheduler deployment,
resource/identity review, signed installed-artifact binding and independent
security/bank acceptance must precede an allowlist change.

## 3. Broader Linux package profile: bounded SQLite RPM exports

`RPM_SQLITE` accepts an explicitly approved regular file, not a command or an
implicit package-manager database discovery. It reads bounded bytes through the
existing no-follow/mutation/byte budgets, deserializes into in-memory SQLite,
sets query-only/trusted-schema controls and a restrictive authorizer, refuses
views/virtual tables and bounds rows, header indexes, strings and VM work.

It parses only RPM NAME/VERSION/RELEASE and optional EPOCH identity fields from
`Packages(blob)` records. No rpm executable, macros, user config, plugins,
scripts, extra disk databases, extension loading or signature/key extraction.
These remain package-database-record facts → SBOM/TechBOM, not observed algorithm
invocation. The native profile still does not mean all Red Hat/SUSE installations.

Use a reviewed **offline consistent/checkpointed export**. WAL-mode headers are refused. No journal/WAL sidecars
are read, no SQLite backup/transaction consistency of a live database is claimed,
and the main file alone is not a guarantee of current committed package state.
No bytes are silently truncated: exports over the existing 1 MiB limit fail.
Berkeley DB/ndb, multiarch duplicate name/version disambiguation, native RPM-host
fixtures and package signatures remain unsupported/qualification work.

## 4. Native fixture execution, not skip-shaped qualification

The new runner executes real platform collectors on an exact target and compares
a **pre-agreed expected-truth plan**. It has no mock backend, arbitrary test script,
command executor, remote host connection or native-Windows emulation.

```bash
python scripts/qualify_host_profile.py --target reviewed-target.json \
  --expectations reviewed-native-fixture.json --output new-native-report.json

# On an actual reviewed ordinary-user Windows fixture only:
python scripts/qualify_host_profile.py --target reviewed-windows-target.json \
  --expectations reviewed-windows-fixture.json --windows-candidate \
  --output new-windows-native-report.json
```

Plan structure, using **actual reviewed values**, not invented expected hardware:

```json
{
  "schema_version": "cryptoscan.native-fixture/v1",
  "target_sha256": "<canonical target SHA-256>",
  "reviewer_reference": "fixture-review/change-42",
  "expected": [
    {"input_id":"os","facts":[
      {"kind":"OS_RELEASE","software_name":"debian","software_version":"12","local_basis":"DECLARED"}
    ]}
  ]
}
```

The plan must exactly cover approved input IDs with nonempty known-field scalar
assertions and exact expected fact counts, bound to the target digest **before**
collection. Exit 0 is PASS_SCOPED_FIXTURE; missing interfaces, denied paths or
expected-truth mismatch yield exit 2/FAIL_GAPS_OR_TRUTH_MISMATCH. Invalid platform,
scope, plan or output yields exit 64. Output is exclusive-create, requesting 0600 on POSIX; Windows ACL qualification
is still required. No upload.
An operator reference is not independent review—its verified flag stays false.

Use separate actual systemd, DMI and TPM0 positive fixture plans on hosts exposing
those approved interfaces. They cannot be positively qualified by a nonexistent
TPM999 test, fabricated sysfs regular file, pure parser fixture or missing bus.
No TPM mechanism/key/sign operation is introduced to manufacture a positive.

## 5. Windows next increment

`WINDOWS_OS_RELEASE` now reads only local HKLM
`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, fixed ProductName and optional
CurrentBuildNumber, through the existing fixed-size registry-string helper and
query-value-only access. Exact resource: `windows-os://local/current-version`.
It emits DECLARED OS metadata, not an observed running-kernel build or attested
product. Native test is present and skips on Linux. SCM native tests and Windows
registry/package/path/denial/provider/store/module/listener matrices remain open.

No capability catalog entry, signature, native skip or sandbox summary silently
changes `windows_execution_qualified`/`production_execution_qualified` to true.
Phase 4/production admission must not be unlocked by a locally passed parser or
a failed native profile. The supplied tooling lets actual approved fixtures
produce defensible results instead of another checklist with no executor.
