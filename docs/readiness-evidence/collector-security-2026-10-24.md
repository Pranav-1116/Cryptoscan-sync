# Collector security built; next Windows OS increment implemented

**2026-10-24 · engineering execution evidence, not production/bank clearance**

Branch `arena/bb4b80dd-cryproscan` · [PR #34](https://github.com/ZKChainForge/CryproScan/pull/34)

Baseline `c0c4e3fbc77945abbb84ff70b6b2e24d580264bc`. Selected final source/artifact
commitments are in the [manifest](collector-security-2026-10-24/manifest.json).
Prior reports/logs remain historical evidence for their own source versions.

## Built, rather than another gap-only checklist

| Requested area | Delivered implementation | Qualification boundary |
|---|---|---|
| Signed collector identity | Administrator-pinned Ed25519 public key/release ID, random approval nonce, exact snapshot/host/manifest/time statement, enforced existing intake, original-proof storage/audit and signature re-verification on reads | Authenticates the pinned **signing key**, not physical host, installed executable, release distribution, clock or enclave |
| Production isolation work | Actual Linux x86_64 Landlock/seccomp **read-only file stage**, explicit leaves, no network/exec/fork/mutation, bounded fixed child, limits, deadline/output kill/reap and no fallback; CLI `--isolated` | Native kernel stage enforcement demonstrated; not full deployed admission→queue→worker production clearance or runtime/systemd/Windows isolation |
| Broader Linux profiles | Bounded in-memory SQLite RPM export metadata, header identity parser, query-only/authorizer/VM bounds, WAL-mode/view/duplicate refusal, same typed evidence path | Reviewed consistent offline export only; no rpm/macros/plugins, live transactional inventory, Berkeley DB/ndb, package authenticity or native Red Hat/SUSE qualification |
| Native systemd/DMI/TPM/Windows gates | Executable target-bound expected-truth fixture runner; requires positive parsed inputs/exact counts/known scalar assertions; missing interfaces fail rather than skip-to-PASS | Suitable actual hosts are still needed; this sandbox does not expose those required positive interfaces or Windows |
| Move to the next Windows increment | Exact local ProductName/CurrentBuildNumber registry declaration, `WINDOWS_OS_RELEASE`, native test and fixture CLI alongside existing SCM candidate | Native Windows test skips here; registry Windows authorization and production flags stay false |

[Detailed design, API policy, signing protocol, isolation controls, fixture plans
and operator commands](../bank-environment/65-signed-collector-isolation-and-native-gates.md).

## Signed identity is an enforced existing-pipeline boundary

The new policy is optional only for legacy **offline development** compatibility.
For approvals that pin a signing key, unsigned/downgraded submissions cannot bypass
it. Trust comes from the scoped administrator's durable approval, never the
analyst's intake body or a caller-supplied public key. No product private-key or
network trust-discovery interface was added.

Actual API/DB witnesses exercise successful signed intake/inspection, exact
idempotent replay, omitted proof, wrong key, validly signed wrong nonce/host/
release/snapshot/approval, future signing time, revoked registry scope and wrong
bank. Scope-negative cases are re-signed by the **trusted test key**, so rejecting
them cannot be explained merely by stale signatures. A recomputed local row hash
also cannot bless an altered external proof on inspection. Existing ORM
append-only protection was not weakened; deliberate tampering uses test-only
SQL to exercise the external-signature check beyond that guard.

The same contracts run against the owned PostgreSQL backend. No new inventory,
evidence database, scheduler, endpoint executing host commands, migration or
sixth independent scanner was introduced. Original evidence projections and
historical `HostFact` canonical defaults remain unchanged. Four pinned shared
schemas are refreshed for the new input vocabulary.

## Actual isolation witnesses

The fresh child preloads trusted parsers/validates its typed target, installs
no-new-privileges + Landlock + architecture-checked seccomp, then reads/parses the
approved source bytes. It never installs restrictions in the API or parent.

Real kernel tests showed:

- Approved source content remained readable.
- Unapproved content read, write-open, **O_RDONLY|O_TRUNC**, unlink, socket,
  fork, exec, io_uring and cross-process prlimit were denied.
- Approved and unapproved test files remained unchanged.
- Fixed-child deadline and output overflow caused kill/reap with no fallback.
- A real OS-release file was collected with Landlock ABI **2** enforcement.
- Controlled public-certificate, config, ELF-header, dpkg, Alpine and RPM export
  fixture inputs all parsed **inside actual isolation**. They are synthetic
  source contents, not native package-estate or bank application qualification.

Only exact ordinary-file metadata kinds are supported by this stage. Live
proc/sysfs, systemd IPC/subprocess and Windows requests are refused by the isolated
profile. Landlock is not complete metadata/covert-channel isolation or a namespace
VM. Independent syscall/sandbox review and deployed worker resource/identity
controls remain production gates.

## Final validation

| Gate | Final result | Evidence |
|---|---|---|
| Broad Python regression including original CBOM/evidence/host/API/association/foundation controls and new identity/isolation/RPM/native-runner cases | **1,650 passed, 3 skipped**, 12 warnings; 219.82 s | [log](collector-security-2026-10-24/regression.txt), [JUnit](collector-security-2026-10-24/regression.xml) |
| Owned PostgreSQL 16.2 including signed identity success, scope-negative and tamper contracts | **94 passed**, 6 warnings; 149.96 s | [log](collector-security-2026-10-24/postgres.txt), [JUnit](collector-security-2026-10-24/postgres.xml) |
| Frontend compatibility | **620 passed / 58 files**, 163.94 s | [log](collector-security-2026-10-24/frontend.txt) |
| TypeScript / production frontend build | **PASS**, build 2.09 s | Same frontend log |
| Changed Python Ruff, dependencies, whitespace | **PASS** | [quality](collector-security-2026-10-24/quality.txt) |
| Actual native OS/isolation and signing CLI witness | **PASS for scoped OS/file stage/signature controls; required native interfaces FAIL_GAPS** | [outcome](collector-security-2026-10-24/native-witness.json), [replay](collector-security-2026-10-24/run-native-witness.py) |
| Owned backend/temporary cleanup, deadline/overflow kill-reap | **PASS** | [cleanup](collector-security-2026-10-24/cleanup.json) |

Counts overlap and are not a coverage percentage. The three skips are native
Windows file/reparse, SCM and OS-registry execution. Existing Pydantic/Starlette/
Alembic warnings remain. PostgreSQL logs retain nonfatal third-party logging
errors involving a closed capture stream at shutdown; pytest exits zero, the
backend reports stopped and owned resource removal is checked. Test elapsed
seconds do not establish p95/p99 or the agreed bottleneck-improvement target.

Focused authoring also corrected a test-helper import and a tamper test that the
existing append-only ORM guard correctly refused. Final review added legacy
SQLite public-row UTC timestamp compatibility to the signing CLI (without
relaxing manifest/snapshot clocks), strengthened valid-signature scope-negative
witnesses and rejected WAL-mode RPM main files. The complete backend/PG gates
were rerun after these changes; only the final captures are presented as final
results.

## Actual native fixture/CLI run, including honest failure

[Replayable witness script](collector-security-2026-10-24/run-native-witness.py) ·
[Machine-readable outcome](collector-security-2026-10-24/native-witness.json)

| Executed witness | Result |
|---|---|
| Isolated real Debian OS metadata | PARSED under real Landlock ABI 2/seccomp |
| Synthetic public/config/header/dpkg/Alpine/RPM contents under kernel isolation | All six PARSED; not native RPM/Alpine distribution qualification |
| Exact public statement preparation + in-memory disposable test-key signature + verification CLI | Exit 0/PASS signature; not a bank/release signer |
| Existing output overwrite | Exit 64, refused |
| Legacy SQLite API public-row timestamp representation | Signing preparation exit 0; manifest/snapshot timestamp rules unchanged |
| Reviewed exact OS metadata fixture | Exit 0/PASS_SCOPED_FIXTURE, production/host/independent-review flags false |
| Required positive systemd/DMI/TPM0 profile on this sandbox | **Exit 2/FAIL_GAPS_OR_TRUTH_MISMATCH**: no positive facts; unavailable bus/DMI/TPM interfaces are not passed qualification |
| Native Windows | **Not executed**; three native test skips remain unqualified |
| Owned temporary directory/backend cleanup | Removed/stopped; no customer deployment touched |

The fixture runner's expected-truth plan is committed to the exact target digest
before collection. It cannot replace missing hardware with a regular file,
convert a denied path to absence, execute an arbitrary assertion script, treat
port 443 as TLS or change a failed native profile into production clearance.
It does not independently certify an operator's reviewer reference.

## What remains environment/acceptance-gated

The implementable signing/isolation/package work above is delivered, and the
next Windows OS candidate is built. **The entire requested acceptance list is
not declared complete.** Code cannot create genuine positive systemd/DMI/TPM
observations or native Windows execution on a host without those interfaces.
The new runner now produces an explicit failing qualification result rather
than another unexecuted checklist.

Before Windows/production admission or a fully qualified phase progression:

1. Execute reviewed positive/negative fixtures on actual ordinary-user systemd,
   DMI, TPM and Windows hosts; retain scoped expected truth, source and results.
2. Review native RPM/Alpine/other distribution profiles and remaining Windows
   store/provider/module/listener/hardware/permission/path matrices.
3. Establish protected signing-key custody/rotation, signed release distribution
   and installed-artifact/host/clock binding. A signed release **claim** does not
   measure the running collector; the existing release-image attestation verifier
   remains a separate trust boundary.
4. Independently review the actual sandbox, add dedicated runtime/IPC/Windows
   isolation policies, integrate and witness the production admission/worker path,
   and complete bank/deployment/performance acceptance.

No privilege guards, native execution gates or production authorization were
relaxed to manufacture a success. No cloud/Windows/bank machine was contacted,
no existing deployment changed, no workflow edited/manual CI dispatched, and no
PR merged. Publication uses `[skip ci]` on the existing branch/PR.

## Reproduce / continue

[Bundle replay](collector-security-2026-10-24/README.md) ·
[Guide 65](../bank-environment/65-signed-collector-isolation-and-native-gates.md) ·
[Linux profile](../bank-environment/63-linux-collection-phase-two.md) ·
[Windows candidate/native gates](../bank-environment/64-windows-collection-phase-three.md)
