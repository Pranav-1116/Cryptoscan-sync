# CryptoScan platform status — the full plan vs. what ships here

Honest accounting, capability by capability, for every week in the plan
(Part 4: W37–48, Part 5: W49–60). "Built" means code + tests in this repo.
"Partial (honest)" means the testable core is built and the gaps are named.
"Not claimed" means we deliberately did not fake it — usually because it needs
real infrastructure or credentials.

> **Current-state correction (2026-09-08):** the numbers at the top of this
> document were measured at an earlier commit and are now out of date. The
> tables below are a historical record of the plan vs. what existed at those
> commits; they are retained for traceability and should not be read as the
> current state.

Measured at the release HEAD (`v1.0.0` + supervisory portal + telecom scanner + ops layer + enterprise readiness, 2026-09-11):
**583 OpenAPI paths** (measured from the live schema), **56 ordered database migrations** (0001–0056),
**64 frontend pages**, **9 RBAC roles** (superadmin, ciso, security_analyst,
developer, auditor, business_owner, scanner, readonly, supervisor — plus
admin→superadmin / viewer→readonly aliases), and **4,004 test functions**
across every service suite (collected at the release commit). Releases are cut through
`python3 scripts/release_check.py` (VERSION == API version == `v` tag,
dated CHANGELOG section, contiguous migrations, prod-guard intact).

**Update (2026-09-22, binary & firmware scanning):** binaries are now *parsed*, not
name-matched. `services/devsecops/devsecops/binary_scan.py` (stdlib only) reads ELF
dynamic sections/RPATH/build-id/compiler/dynamic symbols and **Go build info including
the module graph**, PE imports/subsystem/.NET, Mach-O fat+thin load commands, `ar`/`.deb`
members with GNU long names, zip archives with Maven/Python metadata, WASM imports, Java
class, RPM and raw blobs, plus firmware container chains (uImage, device-tree
`model`/`compatible`, squashfs, JFFS2, UBIFS, cramfs, gzip/xz/zstd) with offsets and
entropy. Crypto evidence is graded through the existing universal-crypto model, version
banners are read out of the file, weak single-marker library claims are re-verified on
identifier boundaries and anything dropped is reported with its reason
(`suppressed_libraries`), PQC designations are captured in full (`ML-KEM-768`) while
X25519/Ed25519 are classified as classical ECC. Output feeds the existing pipeline
unchanged: CycloneDX/SPDX SBOM (crypto implementations and Go module graphs become
components and dependency edges), CycloneDX CBOM ingested through the same
`ingest_document` path as `POST /cbom/ingest`, then gate / licence / VEX / diff /
rescan. New: `POST /devsecops/binary/scan`,
`GET /devsecops/binary/artifacts/{id}/cbom`, `kind: "binary"` on
`POST /devsecops/sbom/scan`, and a **Binaries** tab in the DevSecOps console. Component
diffs now key on name *and* reference, so a binary called `openssl` and the `OpenSSL`
library inside it are tracked separately. Stated limits: firmware filesystems are not
extracted (`BIN-FIRMWARE-NOT-EXTRACTED`), Stated limits: firmware filesystems are not
extracted (`BIN-FIRMWARE-NOT-EXTRACTED`) and every cap (512 MiB/file, 4 000 files,
750 binaries, 64 MiB per decompression level, depth 2) is surfaced in the manifest and
in `summary.extraction_limits`. Tests: `services/devsecops/tests/test_binary_scan.py`
(46) + `services/api/tests/unit/test_binary_scan_api.py` (7), on byte-level ELF/PE/ar/zip/
firmware/RPM/cpio/Java-class/VS_VERSIONINFO fixtures — including regression tests for the
`RustCrypto`-in-OpenSSL false-positive class.

**Update (2026-09-22, binary scanning depth):** the parser and the container walk went
deeper. ELF now reads **program headers** (segments, `PT_INTERP` interpreter,
`PT_GNU_STACK` executable-stack), **`.gnu.version_r` symbol-version floors**
(`libcrypto.so.3 → OPENSSL_3.0.3`, reported as a floor with the reason CVEs cannot be
matched from it), `.note.gnu.property` CPU features, **hardening flags** (PIE, NX, RELRO,
full RELRO/BIND_NOW, canary, `_FORTIFY_SOURCE`) and **crypto constant tables** located in
`.rodata`/`.text`/`.data` (⇒ `CONSTANT_MATCH` 0.9). PE now reads **delay-load imports**,
**`RT_VERSION` resources** (StringFileInfo strings, `VS_FIXEDFILEINFO`, translation
table), the **debug directory** (CodeView `RSDS` PDB + GUID + age), **Authenticode
presence** (presence and size only — validity is explicitly not claimed), **CLR metadata**
(BSJB → framework version) and the **Rich header**; UEFI subsystems are labelled
`efi-image`. Java **class constant pools** and **RPM headers** (name, version, release,
licence, vendor, `REQUIRES`/`PROVIDES`) are parsed, and a **`.deb` control file** gives
the package identity.

Containers are now **followed, not just listed**: gzip/xz/bzip2/tar/cpio and the payloads
of RPM/deb are opened inside a stated budget and their parseable members are analysed with
the same evidence strength as a loose file (constant tables included). Anything found is
reported as `<container>!<member>` (with `@offset` when the stream sat inside an image) —
`derived_from`, `depth`, SBOM components and CBOM assets carry that provenance, and the
same algorithm found in four containers is one asset with four `evidence.occurrences`.
zstd/lz4 and filesystem images are **refused with the reason** (`BIN-CONTAINER-REFUSED`),
never silently skipped. New findings: `BIN-EXECUTABLE-STACK`, `BIN-NO-RELRO`,
`BIN-PARTIAL-RELRO`, `BIN-NO-STACK-CANARY`, `BIN-UNSIGNED-PE`, `BIN-EMBEDDED-CRYPTO`,
`BIN-CONTAINER-FOLLOWED`, `BIN-CONTAINER-REFUSED`, `BIN-CRYPTO-VERSION-FLOOR`,
`BIN-WEAK-PRIMITIVE-CLASS`, `BIN-PARTIAL-PARSE`, `BIN-HIGH-ENTROPY`; a summary carries
`embedded_binaries`, `containers_followed`, `containers_refused`, `packed_binaries`.

**Update (2026-09-22, Mach-O, cpio and platform APIs):** everything the remaining
formats expose that bears on crypto is now read. **Mach-O** earns its own parser depth:
linked dylibs with their current/compatibility versions, `install_name`, `LC_RPATH`,
platform/minimum-OS/SDK, the section list, the symbol table split into imports and exports
through `LC_DYSYMTAB` (with dyld's leading `_` stripped so the C name keys the fingerprint
and algorithm tables), and the **code signature** — signing identifier, team id, hash
type, flags (hardened runtime, library validation, ad-hoc) and **entitlements**, with
`get-task-allow`/`allow-unsigned-executable-memory`/`disable-library-validation` called
out as findings. Mach-O signature validity, certificate chain and notarisation are *not*
verified, and `signature.note` says so. A **fat** binary lists every slice and parses the
native one; a `cryptid`-encrypted slice is reported as `BIN-ENCRYPTED` rather than being
presented as a file whose strings were read. **Bare cpio/initramfs** archives (newc/crc at
offset 0) are now identified and opened like any other container, and the old ASCII `odc`
form is identified and refused with the reason. **Platform crypto APIs** are mapped to
primitives — `CC_SHA256`/`CCCryptorGCM*`/`CCKeyDerivationPBKDF` (CommonCrypto),
`SecKeyEncrypt`/`SSLCreateContext` (Security.framework), `BCryptGenRandom`/`CryptGenRandom`
(CNG/CryptoAPI), `getrandom`/`getentropy`, `AES_set_encrypt_key`, `RAND_bytes`,
`PKCS5_PBKDF2_HMAC` — at `IMPORT`/`SYMBOL` level, while cipher-agnostic constructors
(`CCCryptorCreate`, `BCryptEncrypt`, `EVP_CIPHER_CTX_new`) stay library markers and are
never promoted to an algorithm. New findings: `BIN-UNSIGNED-MACHO`, `BIN-ENTITLEMENT`,
`BIN-NO-HARDENED-RUNTIME`, `BIN-ENCRYPTED`, `BIN-DELAYED-IMPORT`. Live drill (11 files:
Mach-O signed + unsigned, bare initramfs, uImage, deb, RPM, tar.gz, zstd, PE, class):
11 binaries, 5 embedded, 6 containers followed, 1 refused, and a signed Mach-O scanned
alone yields `Apple CommonCrypto` + `SHA-256` and a two-asset CBOM. Tests: 61 in
`test_binary_scan.py` (+8 binary API, 332 across devsecops + binary API + cbom).

**Update (2026-09-22, uImage firmware headers):** legacy U-Boot images are now read as
images rather than as anonymous blobs: the 64-byte header is decoded (image name, OS,
architecture, image type, compression, load/entry addresses, payload size, build date —
all from the published U-Boot field tables, nothing guessed) and **both checksums are
computed and reported**: the header CRC (over the header with its own field zeroed) and
the payload CRC when present and within the 64 MiB verification cap, otherwise explicitly
`data_crc_checked: false` with the reason. A header mismatch is `BIN-UIMAGE-CRC` (LOW), a
payload mismatch or a truncated payload is `BIN-UIMAGE-PAYLOAD` (HIGH) — a firmware image
that does not match its own checksum is reported, not silently accepted. The generic
firmware pass still runs, so the compressed ramdisk at offset 64 is followed as before.

**Update (2026-09-22, package signatures):** the RPM **signature header** is now read
rather than skipped: RSA/DSA/PGP/GPG entries decide `signed` (a sha256/sha1/md5 digest tag
is integrity metadata and is explicitly *not* counted as a signature, though the digests
themselves are reported as hex), and a package with no signature entry is
`BIN-RPM-UNSIGNED` (MEDIUM — its provenance cannot be established from the file). A `.deb`
is checked for a detached `_gpgorigin`/`_gpgbuilder` member and reported as
`BIN-DEB-UNSIGNED` at LOW with the reason stated (`.deb` signatures normally live in the
repository metadata, not in the package), so the finding informs without implying
tampering. Tests: 66 in `test_binary_scan.py`, 338 across devsecops + binary API + cbom.

**Update (2026-09-22, PE mitigations):** PE now has the mitigation reporting ELF has had.
`DllCharacteristics` is decoded into a hardening map (ASLR/DYNAMIC_BASE, high-entropy VA,
DEP/NX_COMPAT, SEH, isolation, CFG, force-integrity, AppContainer), and
`IMAGE_LOAD_CONFIG_DIRECTORY` is read for the facts that say whether the mechanism is
*live*: a non-null SecurityCookie (`/GS`), the SafeSEH table, and `GuardFlags`
(`GUARD_CF_INSTRUMENTED`). Findings: `BIN-NO-ASLR` (MEDIUM — stable addresses across runs),
`BIN-NO-DEP` (HIGH), `BIN-NO-CFG` (LOW, including the "declared but not instrumented"
case) and the existing `BIN-NO-STACK-CANARY` (LOW) for a load config with a null cookie.
The console renders all three vocabularies (ELF, PE, Mach-O) through one hardening
renderer. Tests: 70 in `test_binary_scan.py`.

**Update (2026-09-23, commit pending, binary artifacts are tenant-scoped and sealed at
rest):** a binary artifact is the most sensitive document this platform writes down —
the SBOM lists every component and path in a shipped image, the CBOM names the algorithms
in use, the manifest counts private keys — and until now all of it sat in one shared
directory in the clear, readable by any reader role in any organization. Two changes fix
that. **Location:** every artifact is written under `tenants/<tenant>/…`, the manifest
records `tenant_id`/`tenant_bucket`, and every read path (list, report, download, verify,
CBOM, diff, gate, licence, VEX, components, advisories, retention) resolves the manifest
through one tenant-filtered lookup — another tenant's artifact is answered as *absent*
(404, no existence oracle), never listed, and never counted in its owner's views. **Key:**
`devsecops/artifact_crypto.py` derives one key per tenant by HKDF-SHA256 from a master
secret (`CRYPTOSCAN_ARTIFACT_KEY`, falling back to `SECRET_KEY`), seals each payload and
CBOM with AES-256-GCM under a random nonce, and stores only the key *id* — so a database
or volume dump carries no key material, two tenants' ciphertexts are unreadable with each
other's key even for identical documents, and a leaked backup of one prefix is not a key
to the other. The manifest stays readable on disk on purpose: it is the index a listing,
gate and diff read without needing a key, which is why it carries counts, labels and an
excerpt rather than the whole document — and that limit is written down here rather than
left implied. The artifact's own `sha256` and HMAC signature stay over the **plaintext**,
so verification, gating, diffing and the SBOM/CBOM digests are unchanged by sealing; a
tampered or key-mismatched object fails authentication (`tampered`/`wrong_key`/`no_key`)
instead of decrypting to an empty document. Sealing is recorded *inside* the signed
manifest (`at_rest: {algorithm, key_id, key_source}`), so "is this scan encrypted, and
under whose key" travels with the artifact; the scan response carries it as `at_rest`,
and `GET /devsecops/binary/at-rest` answers the auditor's two questions together —
algorithm and key id, plus how many artifacts in this tenant are still plaintext, because
"encryption is configured" and "every artifact is encrypted" are different statements.
A queued job carries `tenant_id` in its scan options (a worker has no request to ask), and
an install with no tenant context uses the `platform` estate — where artifacts written
before this existed already live, so nothing on disk became unreadable: a legacy plaintext
object is returned with `at_rest.algorithm: none` rather than assumed encrypted or lost.
No key configured is likewise recorded, not glossed over: the object is written plain and
the manifest says so. Tests: +14 `test_artifact_crypto.py` (round-trip, per-tenant key
stability, tenant separation, tamper and rotation detection, no-key and legacy paths,
scope escaping) and +10 `test_artifact_tenancy.py` (prefix and object-level separation,
the same document under two keys differing, cross-tenant refusal reasons, the platform
estate, a refused tenant id writing nothing), +5 `test_artifact_tenancy_api.py` (a
tenant's scan seals its own artifact; another tenant gets 404 on report/download/cbom/
diff and an empty list while the owner sees it; the at-rest endpoint's counts and key
ids; a session caller cannot name a tenant it is not a member of; a platform scan stays
readable) against a 631-test sweep. Console: the binary panel shows the stored-artifact
sealing line (algorithm + key id, or a red plaintext warning) beside the table set.
Stated limit: the manifest's own body is the index and is not sealed yet, so it should
not be given document-sized content; sealing it needs the store to decrypt on listing,
which is the next step, not a claim made here.

**Update (2026-09-23, commit pending, constant tables in update bundles):** the air-gap
update path reached rules first; the *constant database* was still release-only, so an
algorithm the scanner's tables do not cover could not be taught to a disconnected
install. Packs now carry `tables/*.json` next to `rules/`, and the scanner searches
them exactly like the built-ins — the same `scan_constants` search, the same
byte-count ladder, the same ambiguity handling — with one addition that matters for
evidence: every matched table reports its `source` (`null` for the release's own
tables, `pack:<name>@<version>` for one an operator installed), every scan reports
the table set it searched (`constant_tables`: built-in/installed counts, digest,
sources, errors), and the manifest carries that block next to `binary_summary`.
Validation is strict in the direction that protects the evidence: a table document
must state `algorithm`/`table`/`encoding: hex`/`bytes`, a `minimum` between 4 and the
table length, a `kind`/`weight` from the ladder's vocabularies — and **unknown fields
are refused, not ignored** (a pack author who writes `"mimimum"` has stated a
threshold that would not be applied). A table may not shadow a built-in by name or
relabel its bytes: a pack adds evidence, it never rewrites what a match means for
everyone else. The same checks run at `build` (on the workstation, so an unusable
table never reaches the media) and at `verify`/`install` (on the isolated host, so a
pack from any other tool still cannot get in). Installed tables are re-hashed against
the digest the registry recorded before they are searched — a table edited on the
host after installation is reported as an error on the scan rather than searched as
if it were signed — and the table overlay is scoped to one walk (a context variable
set around `scan_path`, reset after), so two scans cannot leak tables into each other.
The drill found two holes, both fixed and now covered by tests. **A pack that lists
tables could cross the gap without them.** `export_bundle` copies the content
directories the manifest lists, so an archive built from an older pack (before tables
existed) arrived, correctly, without any — and an installer that trusted presence over
the manifest would have installed a pack that is not the pack that was signed. Arrival
now checks the manifest against what is actually in the archive: a listed table that is
missing is a refusal with the file named, not a half-installed pack. There is a test
that exports, unpacks, verifies and installs a table pack as one artefact, and a test
that strips the tables out of an archive and asserts the refusal. **`already-installed` could be a lie.**
Install matched on the pack digest alone, so a table edited on the host after
installation made the next install answer `already-installed` and leave the damaged
copy in place: present, and not what was signed. Re-installing now compares each file
against the digest the registry recorded, and answers `would-repair` (dry run) or
`repaired` with the drifted files named (`changed`/`missing`) — the drill's tampered
table became an error on the scan, then a repair, then `ACME-Cipher` again. Tests: +23
`test_knowledge.py` (incl. bundle round-trip, stripped bundle, repair of edited and
deleted files), +1 end-to-end scan test proving an installed table changes what the next
scan *names* (an algorithm absent before installation, cited as `CONSTANT_MATCH` with
`CONSTANT_COMPLETE`, removed again with the pack), +21 `test_crypto_constants.py` for the
document loader and the collision rules, +3 `test_knowledge_api.py` for the API path
(table-only packs install, a hand-signed pack that relabels the AES S-box is refused 400
with reasons, and a scan over the API names the algorithm the pack taught it). Console:
the knowledge panel shows the table set, each pack's table count, and any table that was
not searched.

**Update (2026-09-23, commit pending, GraphQL + WebSocket surfaces):** the binary scanner
is a service other software calls, and two shapes of caller had no reasonable path in: a
dashboard that wants one round-trip for facts that currently take five REST calls, and a
console that wants scan progress without polling. Both are now served from the data the
REST surface already returns — no new source of truth, and no second opinion about state.
`api/graphql_lang.py` is a **read-only GraphQL subset with no dependencies**: a lexer,
parser and executor for `query` operations with arguments, variables, aliases, fragments,
inline fragments, `@skip`/`@include` and `__typename`; nothing else is accepted, and the
refusals are deliberate and tested — mutations, subscriptions, unknown directives,
duplicate or cyclic fragments, undeclared variables, untyped/fragment-without-type
conditions, and empty selection sets (`{}` selects nothing; answering it with `{}` would
read as "no data", which is a different statement). Limits are enforced *during* execution
and reported in `extensions`: depth 12, 500 resolved fields, 200 rows per list, 100 kB per
query; an over-limit list is truncated and flagged (`LIST_TRUNCATED`) rather than silently
shortened. A bad field is a field-level error with its `path` and a code
(`FIELD_NOT_IN_SCHEMA`, `MISSING_VARIABLE`, `RESOLVER_ERROR`), not a 500: partial results
come back with the errors that describe what is missing. `POST|GET /graphql` serves the
roots `binaryArtifacts`/`binaryArtifact` (findings with severity filter, crypto, CBOM,
YARA), `binaryJobs`/`binaryJob`, `binaryBatch`, `knowledge`, `runtimeFindings` and
`__schema`; writes are refused with 405 `READ_ONLY_SURFACE` naming where they *do* live
(every mutation is a REST endpoint with its own roles and audit trail, and reaching the
same write through a query language would quietly bypass that). `GET /graphql/schema`
returns the field list, the limits and the refused operations for client authors.
`api/job_view.py` is now the single job card REST, GraphQL and the socket all serialise,
so a job that reads `binary_ingest / 100 / COMPLETED` in a stream cannot read differently
in a status page. `WS /ws/binary/jobs/{id}` sends `hello` → `snapshot` → `update` → `final`
and closes 1000; missing jobs close 4404, auth failures 1008, an idle job 4429 after 30
minutes. Its honesty note is in the first frame: the server **polls the job row** (1s
default, `?interval=` clamped 0.25–10s) because the worker is a separate process and the
in-process bus does not cross that boundary — a socket that called this "push" would be
polling with a nicer name. `WS /ws/events` exposes the same bus as the SSE stream with
`topics=` prefixes and `since=`/`last_event_id` resume, pings every 25s, and reports drops
it caused (`warning`, with the count) rather than losing them silently. Reader roles are
admin/superadmin/security_analyst/auditor/readonly on both sockets; a session with no
roles keeps the legacy admin fallback, an API key with no reader role is refused — key
roles are explicit by design. Tests: +50 `test_graphql_lang.py`, +27 `test_graphql_api.py`,
+10 `test_websocket_api.py`; live drill on the running API: `mutation { deleteEverything }`
→ 400 `INVALID_QUERY`, scan of `/usr/bin/openssl` → artifact `002f0eb6` (11 algorithms,
3 findings HIGH/MEDIUM/LOW, CBOM present) read back through GraphQL with the same counts
REST reports → queued job streamed `hello → snapshot QUEUED → update RUNNING → update
COMPLETED → final COMPLETED` then closed 1000 → the events socket replayed 7 events with
`scan.queued` visible under `topics=scan.,binary.`.

**Update (2026-09-23, commit pending, installed knowledge packs / offline detection
updates):** the air-gapped parity gap that mattered most was not feeds — feature 26 already
ingests offline CVE feeds — but **detections**: a disconnected install could only be updated
by updating the image, and a customer who wrote their own rules had no way in at all. New
`devsecops/knowledge.py` splits rule knowledge into **built-in rules** (in the release) and
**installed packs** (signed bundles on removable media), and `scan_path` now loads the
installed set automatically — `include_installed_rules=True` by default — so an update pack
changes what the next scan finds with no call site, flag or restart involved. A pack is
`pack.json` (per-file SHA-256 + pack digest) + `pack.sig` (HMAC-SHA256 over the manifest,
`--key-id` recorded) + the rule files; **installation is a gate, not a copy**: missing/bad
signature, missing file, edited file, a file the manifest never listed, or rule text this
engine refuses all produce a refusal *with reasons* and leave the install untouched — a
half-applied ruleset that quietly stops matching is the failure this prevents. Installs are
idempotent (same digest → `already-installed`), a new digest under the same name replaces
and reports the old version, and both installs and refusals are audited (pack digest,
version, signer). New API: `GET /devsecops/knowledge` (built-in count/digest, every installed
pack, and the digest of the set a scan will actually use), `POST /devsecops/knowledge/install`
(bundle or directory, `dry_run`, `allow_unsigned`; 400 with `reasons` when refused) and
`POST /devsecops/knowledge/uninstall`. New CLI: `python -m devsecops.knowledge
build|sign|verify|install|uninstall|export|extract|list` (exit 0/2/4). Air-gap mode allows
installing — an update on media is what the air gap is *for* — via the governance allowlist
(`knowledge.install`/`knowledge.uninstall`), while the sync and queued scan endpoints now
enforce read-only mode *before* doing work (the queued path previously checked after
queueing). Bundles are unpacked defensively (absolute paths, `..`, links and non-regular
members refused; 3.12+ data filter where available). The scan report already carried the
ruleset digest; it now cites the digest of the set that was actually loaded, packs included.
Tests: +59 `test_knowledge.py`, +17 `test_knowledge_api.py`; live drill on a running install:
8 built-in rules (digest `989031cfc9346db6`) → scan `/usr/bin/openssl` = 3 findings → install a
signed Acme pack from a `.tar.gz` (`verified_with: env:CRYPTOSCAN_BUNDLE_SECRET`) → 9 rules
(digest `0991af73d0ce877c`) → same scan = 4 findings, including `BIN-YARA-MATCH` on
`acme_legacy_dsa_signatures` citing `$dsa x49` at bytes 62975/728455/… → an unsigned pack and
a pack edited after signing both refused (400, file named) → uninstall → back to 8 rules and
3 findings, same digests.

**Update (2026-09-23, commit pending, fleet intake):** the orchestrator-shaped half of the
binary spec is now filled by the queue the platform already has (no Kafka, no Flink).
`devsecops/intake.py` takes a spool directory and decides, file by file, what is worth
scanning: **identity is content, not path** — the same bytes at eleven paths is one scan
(`new content` / `content changed` / `unchanged since the last pass` / `already scanned
under another path` / bounds / pass limit, each a stated reason with the covering artifact id
where one exists). The memory lives beside the spool (`<spool>/.cryptoscan-intake.json`,
written atomically, no database or broker) so a second pass is free, survives restarts and
works air-gapped; an unwritable spool reports `state_saved: false` instead of re-scanning the
fleet in silence. New `POST /devsecops/binary/batch` (dry run by default, `limit` capped per
pass, audited) queues one `BINARY` job per distinct binary with `batch_id` in
`progress.scan_options`, and `GET /devsecops/binary/batches/{id}` aggregates those jobs
(counts by state, per-job stage + report link, running totals) over the most recent 500 jobs,
saying so when that window is exhausted. New CLI: `python -m devsecops.intake DIR
[--queue] [--watch --interval N] [--force] [--limit N] [--patterns …] [--dry-run is the
default]`, exit 0/4/2. `JobRepository.list_by_scan_option` does the batch lookup through a
JSON path (with a Python fallback). Console: *Plan pass* / *Queue pass* with the decision
table and live batch totals. Tests: +25 `test_intake.py`, +12 `test_binary_batch_api.py`;
live drill: 5-file drop → 2 jobs (a duplicate copy and noise skipped with reasons) → both
`COMPLETED` at `binary_ingest` with artifacts, second pass 0 queued naming the covering
artifacts, and a CLI pass whose batch was pollable and whose job completed.

**Update (2026-09-23, commit pending, dynamic analysis under the tracer):** the binary
scanner's one structural gap — it can say what is *in* a file, never what the file *does* —
is now closable without building a sandbox. `devsecops/dynamic_scan.py` drives the platform's
existing **ADR-012 LD_PRELOAD crypto tracer** (no kernel agent, no privileges, no gVisor) and
is off unless the host turns it on: `BINARY_EXECUTION_ENABLED=true` **and** the sample inside
`CRYPTOSCAN_SOURCE_ROOTS`/`BINARY_EXECUTION_ALLOWLIST`, **and** an executable, dynamically
linked ELF/PE/Mach-O matching the host architecture, **and** inside the hourly run budget
(`BINARY_EXECUTION_MAX_RUNS_PER_HOUR`, default 20). Every refusal is a finding
(`BIN-DYNAMIC-REFUSED`, `BIN-DYNAMIC-DRY-RUN`, `BIN-DYNAMIC-TRACER-UNAVAILABLE`), never an
empty result — "not run" must never read as "nothing found". A run is bounded by an explicit
allow, a cache-cleared scratch cwd, a credential-blanked environment, and a wall-clock timeout
that kills the whole **process group** (a forking sample is bounded, not contained); the
result carries `limits[]` saying exactly what is *not* isolating it, and the sample's
sha256 before/after, so a self-modifying binary is a `HIGH` finding. Observations
(`EVP_CipherInit_ex`/`_DigestInit_ex`/`EVP_PKEY_*`/`SSL_CTX_set_*`) are aggregated per
process/function/algorithm and classified by the platform's own registry + quantum
classifiers — `AES-256-ECB` → `HIGH` (registry DISALLOWED), `MD5` → `HIGH` (classically
broken), `AES-128-CBC` → `MEDIUM` (Grover), an unresolvable name →
`BIN-DYNAMIC-UNIDENTIFIED-CIPHER` (`LOW`) instead of a false all-clear. `--submit` /
`submit: true` posts to `POST /scans/runtime-findings`, so binary runtime crypto sits in the
same inventory, verdicts and SSE stream as the eBPF/mesh agents; the ingest now judges a bare
crypto call by its own algorithm (previously only TLS suites were judged) and the runtime
dedup key includes the algorithm and mode, so two ciphers from one process are two rows.
New `POST /devsecops/binary/dynamic` (dry run 200, or 403 with every refusal when
`execute: true` cannot be honoured) and a CLI (`python -m devsecops.dynamic_scan SAMPLE
--execute --submit -- <argv>`, exit 0/4/2/1). Tests: +47 `test_dynamic_scan.py`, +12
`test_binary_dynamic_api.py`, +3 runtime ingest; live drill: `openssl dgst -md5` under the
tracer → `2` observations → `MD5 DISALLOWED` row in the runtime inventory, and a CLI run
landed `7` rows (`AES-256-ECB` DISALLOWED, `AES-128-CBC` ALLOWED+Grover, `SHA-256` hash-marginal).

**Update (2026-09-23, commit pending, embedded key material):** the binary scanner now
finds **key material inside binaries**, byte-first, with a hand-rolled DER/ASN.1 reader
(no third-party crypto dependency): PEM armour for every key/certificate/request label
(including legacy `Proc-Type`/`DEK-Info`), `PKCS#1`/`PKCS#8` (plain and the encrypted
`PBES2` wrapper, identified and *not* decrypted), `SEC1`, `SubjectPublicKeyInfo`, X.509
v1/v3 (subject, issuer, validity, signature algorithm, `CA`, `keyUsage`,
`extendedKeyUsage`, SANs), `PKCS#10` requests, `PKCS#7`/CMS, `PKCS#12`, `ML-KEM`/`ML-DSA`
by OID, OpenSSH `openssh-key-v1` (cipher/KDF/rounds), PuTTY files, OpenPGP packets with
the armour CRC-24 verified or reported as unverified, JKS/JCEKS entries with aliases and
the certificates inside them, `ssh-*` host keys, plus base64/hex-encoded copies wherever
they sit — including inside a filesystem image the scanner does not unpack. Rows carry
kind/type/size/curve/detector/encryption/`material_sha256`/offsets and **never the key
bytes**. Findings: `BIN-EMBEDDED-PRIVATE-KEY` (CRITICAL unencrypted / HIGH encrypted),
`BIN-EMBEDDED-KEYSTORE` (HIGH with private keys, else MEDIUM), `BIN-EMBEDDED-CERTIFICATE`
(MEDIUM, explicitly not a verification), `BIN-EMBEDDED-TEST-KEY` (INFO for keys the
surrounding bytes declare as samples — inventoried, no false alarm). A bare `.jks`/`.der` with no magic is still scanned rather
than dropped, and nested DER candidates are one finding, not two. The SBOM binary row
carries the key facts, `manifest.binary_summary.key_material` counts them, and the CBOM
inventories keys as `related-crypto-material` assets (certificates as `assetType:
certificate`), identified by hash and merged when the same key ships twice. Critical scan findings now also reach the gate
(`GATE-SCAN-CRITICAL`, `allow_scanner_critical`), which previously read only CVEs
from the document and so gated a leaked private key `PASS`. Tests: 41 in
`test_embedded_keys.py`, +2 binary API tests (10 in `test_binary_scan_api.py`),
108 across the two binary suites, 379 across devsecops + binary API + cbom, 694 API unit.

**Update (2026-09-23, commit pending, deep crypto constant database):** the constant
search is now a **table database** instead of seven eight-byte prefixes: ~20 whole tables
(AES S-box/inverse/`Rcon`, SHA-1 H/K, SHA-256 H/K, SHA-512 H/K, Keccak round constants,
MD5 H/K, BLAKE2b/BLAKE2s IVs, BLAKE2 sigma, BLAKE3 marker, Blowfish P-array/S-boxes,
ChaCha20 sigma, TEA delta), each generated from its definition and checked against the
published values (`test_crypto_constants.py` recomputes SHA-256/SHA-1/MD5 digests with
the generated tables; the S-box is checked bijective with the inverse as its inverse).
Matches are graded by a byte-count ladder (FULL .95 / COMPLETE .9 / STRONG .8 /
MODERATE .7 / WEAK .5) and only MODERATE and above may name an algorithm. Two rules the
ladder enforces: a trigger may not be a run of zeros with a bit in it (Keccak's first
round constant otherwise matches padding in every second file, so the whole table is
required where no prefix discriminates), and a table another algorithm also stores
(MD5's H read little-endian *is* SHA-1's H; SHA-256's H *is* BLAKE2s's IV) is reported as
`ambiguous_with`, excluded from the graded byte count, and never named — the tie-breaker
is a second table nothing else shares. The search now runs over PE `.rdata` and Mach-O
`__TEXT,__const` as well as ELF sections (it was ELF-only), every file reports what was
searched (`searched_bytes`) beside what was found, and the manifest carries
`binary_summary.constants` (artefacts searched, bytes, tables, complete tables, named
algorithms) so "no AES constants" always has a denominator. New findings
`BIN-CRYPTO-CONSTANT-TABLE` (INFO), `BIN-CRYPTO-CONSTANT-SHARED` (LOW) and the existing
`BIN-CRYPTO-CONSTANT-PARTIAL` (LOW). The **stored report** now carries a binary-scan
section and a bounded, worst-first excerpt of the scan's findings (`findings_excerpt`,
capped at 60 with the cap stated) — previously an artifact whose manifest said "1 HIGH"
could not say which one, and an embedded private key never appeared in the report at all.
Tests: +17 in `test_crypto_constants.py`, 77 in `test_binary_scan.py`, 13 in
`test_binary_scan_api.py`.

**Update (2026-09-23, commit pending, fingerprints):** a binary scanner now answers the
two fleet questions offline. **Exact**: `file_sha256`, `code_sha256` (code/read-only
sections framed with their names and sizes, so a renamed or split section is visible and a
changed debug path is not), `imports_sha256`/`exports_sha256`, the identity the format
declares (ELF `.note.gnu.build-id`, PE CodeView `GUID`+age, Mach-O `LC_UUID`) and
`build_fingerprint` = code + import surface + format. Rebuilding with a different debug
path moves the file digest and leaves the build fingerprint alone — that is how "same
build, repackaged" is told apart from "different build". **Fuzzy**: ssdeep (CTPH)
implemented from the specification (rolling seven-byte window, FNV-1a pieces,
`blocksize:base:doubled`, reference edit-distance score 0-100); the implementation was
cross-checked against `ssdeep`/`ppdeep` on 3 649 hashes and comparisons during
development, zero divergences after two real fixes, and the vectors are checked in so the
suite needs neither tool. Two deliberate departures, both stated in the docs and tests:
the fuzzy pass samples at most 512 KiB of code per file (`fuzzy_bytes`/`fuzzy_truncated`
report it; a targeted lookup can raise it to 8 MiB), and two empty fingerprints score 0
where ssdeep scores them 100. Scans cluster what they find: `BIN-FINGERPRINT-DUPLICATE`
(INFO, with byte-identical vs repackaged distinguished by the file digests),
`BIN-FINGERPRINT-SHARED-CODE` (identical code, different imports) and
`BIN-FINGERPRINT-NEAR-DUPLICATE` (INFO, resemblance with the score, never identity), plus
`manifest.binary_summary.fingerprints` with complete counts and bounded group lists. New
`POST /devsecops/fingerprints/match` fingerprints a directory inside the same allowed
source roots and answers `identical` / `same-code` / `similar` / nothing for one suspect
binary, with limits and thresholds reported. The console shows duplicate and
near-duplicate counts and a build-fingerprint column. Tests: +27 `test_fingerprints.py`,
+2 API tests (15 in `test_binary_scan_api.py`); frontend typechecks and builds.


**Update (2026-09-23, commit pending, queued binary scans):** a binary scan no longer has to
fit inside one request. `POST /devsecops/binary/jobs` queues it as a real job (202 + job id +
**artifact id chosen up front**, so the report URL is pollable from acceptance), the worker
dispatches `binary://<path>` targets to a binary job instead of the git pipeline
(`worker/pipeline/binary_job.py`), and progress is reported per stage
(`binary_target → binary_scan → binary_sbom → binary_store → binary_ingest`) with the
artifact, counts and by-severity breakdown on the completed job. Failure is explicit: an
unreadable or refused target, a render error or a storage error marks the job FAILED with the
reason, while a walk that finds nothing parseable *completes* and says how many files were
walked (zero findings never reads as zero files looked at). The manifest, signature and
storage keys now come from one shared builder (`devsecops.artifact_store.store_binary_artifact`)
called by both the endpoint and the job, so the same target produces the same artifact either
way — signed with the same key (a queued artifact verifies `OK` against the API's key
resolution). Scan options live on the job row (`progress.scan_options`), so a retry re-runs the
*same* scan rather than silently falling back to defaults, and a job with no artifact id of its
own is keyed by its **job id**: re-running rewrites one artifact instead of adding a duplicate
(verified live: two runs, three files on disk, one artifact). This also fixed a real bug —
`POST /jobs/{id}/retry` declared `background_tasks` without the annotation that makes FastAPI
inject it, so every retry was recorded as QUEUED and never executed. Tests: +10
`services/worker/tests/unit/test_binary_job.py` (real scan, real artifact store, signature
verified and wrong-key rejected, refusal leaves no artifact, idempotent by job id),
+5 API tests (22 in `test_binary_scan_api.py`). The console **Binaries** panel gained
**Check rules** (`POST /devsecops/yara/validate`: rules loaded, digest, every rule refused) and
**Queue as job** (`POST /devsecops/binary/jobs` + polling of `/jobs/{id}`: stage, percent,
then artifact, per-severity counts and a report link); frontend typechecks and builds.
493 passed across
`services/devsecops/tests` + `test_binary_scan_api.py` + `services/cbom/tests` + the worker
unit tests touched here; ruff clean.

**Update (2026-09-23, commit pending, rule matching):** the binary scanner can now be told
what to look for. It runs a **documented subset of YARA**, implemented in Python so the
platform stays air-gapped with no C toolchain and no native `yara`: `private` rules,
`meta`/`strings`/`condition`, text strings with `nocase`/`wide`/`ascii`/`fullword`, hex
blocks with wildcards, jumps and alternatives, regex strings, `$a`/`#a`/`@a`,
`any/all/N of them`, `any of ($prefix*)`, `filesize`, integer and boolean comparisons,
arithmetic, `not/and/or`, parentheses, and **other rules by name** (including private
helpers and forward references; a reference cycle is reported, not recursed). What is not
supported is refused out loud — `for`, `xor`/`base64`, module functions (`uint16()`,
`math.*`), jumps past 2000 bytes, references to strings or rules that do not exist — and a
refused rule becomes a finding (`BIN-YARA-RULE-ERROR`) because a half-loaded ruleset must
never read as "checked and clean". Eight deliberately specific rules ship with the platform
(seven detection rules plus a private helper: key material, miner markers, ransom notes,
credential dumpers, reverse shells, UPX, hardcoded test credentials); customers add
theirs. Every match is `BIN-YARA-MATCH` at the
rule's own severity with the strings, counts and offsets that fired, and the manifest
carries the **ruleset digest** (SHA-256 over every source) so a match can be reproduced
elsewhere; matching is bounded at 64 MiB per file and a truncated scan says so
(`BIN-YARA-SAMPLE-TRUNCATED`). Rules are matched against **container members** as well as
the container — and zip members are now actually extracted (stored/deflate, bounded, with
encrypted or unsupported-method members refused by name), so a binary inside a jar reports
its rules the same way a loose file does. A rule file inside the scanned tree is not
matched against its own strings, and the count skipped for that reason is published
(`rule_files_skipped`). New `POST /devsecops/yara/validate` says exactly what will run
(every rule with tags, severity, strings and rule references) and what was refused, before
anything is scanned. Tests: +31 `test_yara.py`,
+2 API tests (17 in `test_binary_scan_api.py`). 475 passed across
`services/devsecops/tests` + `test_binary_scan_api.py` + `services/cbom/tests`; ruff clean.

**Update (2026-09-12, commit `e90cdd8`):** **585 OpenAPI paths / 644 operations**
(measured live), migrations still 0001–0056, **64 frontend pages**, same 9 RBAC
roles. New since the last measurement: six first-class scanner languages
(Python/Java/C#/JavaScript/Go/Rust — weak-primitive + key-size extraction pinned
by tests), the examiner **audit pack** (`GET /audit-export/pack`), the PoC
**exit report** with deterministic SHA-256 and SC-1…4 scorecard
(`GET /audit-export/exit-report`, SC-4 met only by a human name), the
**engagement archive** (`GET /audit-export/engagement-archive` — pack + report +
manifest, all sha256sum-verifiable), and the hardware catalog PQC refresh
(`GET /hardware/catalog` → 60 device types, `quantum_resistant_count: 10`,
firmware-cited provenance, shipping-only evidence). Full regression lane at this
commit: **1370 passed / 12 skipped / 0 failed**.

**Update (2026-09-20, branch `arena/01a0b9c6-cryproscan`):** UAE
regulatory pack (the #1 named gap for a Dubai-bank pilot). The policy
engine ships a 7th pack, `services/policy/rule_definitions/uae/` — 10
deterministic rules: CBUAE-001…005 (estate-wide forbidden-legacy floor;
strong authenticated encryption for payment/card data — AES-256 GCM/CCM or
ChaCha20-Poly1305; TLS ≥ 1.2 on customer-facing/remote channels; RSA ≥
2048; ECC/DH ≥ 256) and DIFC-001/002 (DP Law No. 5/2020 Art. 23 technical
measures), PDPL-001/002 (Federal Decree-Law 45/2021 Art. 20 — encryption
and pseudonymisation are named in the statute), ADGM-001 (DPR 2021, GDPR
Art. 32-equivalent). Rules are scope-activated by evidence tags (CBUAE /
PAYMENT / CARD / SWIFT / CUSTOMER-FACING / REMOTE-ACCESS, DIFC /
PERSONAL_DATA, PDPL, ADGM); the estate floor applies to everything. The
`ae` jurisdiction pack is fleshed out (CBUAE, DFSA/DIFC, FSRA/ADGM, UAE
Data Office; 7 milestones incl. in-force dates 2020-07-01 / 2021-08-14 /
2022-01-02 / 2025-07-01) and now drives `GET /api/v1/banking/jurisdiction/ae`
plus `?jurisdiction=ae` action plans and HTML exports (Arabic RTL
supported); a `cbuae` framework option was added to the action-plan and
export endpoints. Honest limits: the rules evaluate the cryptographic
inventory (algorithm/mode/key-size/purpose/scope tags) — never prose
claims; the pack asserts no PQC mandate the UAE regulators have not
published, with NIST IR 8547 timelines stated as the de-facto reference
examiners cite.

**Update (2026-09-21):** production evidence runner
(`scripts/production_evidence.py`). One command produces the signed,
tamper-evident report a bank's auditors take away: the fails-closed prod
guard exercised in both directions, a fresh-estate smoke, a real load/soak
run through the repo's own harness (production rate limiting active), and a
DR drill where the host can run it (honest SKIP otherwise — recorded with the
exact command, never a fake PASS). Every run appends to an append-only hash
chain using the platform's own `ContentHasher`/`ChainHasher` and is JWS-signed
(HS256, cbom signer) when a key is present; `--verify` re-walks the chain and
re-checks signatures — editing any embedded report flips the verdict to
`INVALID BROKEN_AT=n`. First recorded run: `docs/production-evidence.md`
(3 PASS / 1 clean SKIP, 0 FAIL; 10,690 requests, 0 errors, limiter
enforcing). The release gate
(`scripts/release_check.py`) now runs this evidence runner for the release
version as a **blocking** check — each cut release carries a fresh
`identity.release = v<version>` evidence entry (clean SKIPs don't block;
`--no-evidence` opts out loudly). A SOC 2 Type II readiness gap analysis
(`docs/soc2-readiness-gap-analysis.md`) maps every CC/A-criterion to what the
platform already evidences (✅/🟡/❌ with pointers) and ranks the
organization-side work; bottom line: technical controls are audit-ready,
the remaining work is the observation window, a pen test, and the policy
pack.

**Update (2026-09-21, continued):** the two most buildable SOC 2 gaps
closed. (1) `GET /api/v1/audit-export/access-review` — the CC6.3 quarterly
recertification export: the full access estate (users with roles/MFA/
last-login/lock state, API keys as display-prefix + hash only — never key
material, per-user active session counts) plus the standing review
signals: privileged accounts, active accounts without MFA, stale and
never-logged-in accounts, locked accounts, expired-but-unrevoked and
revoked keys. `report_hash` is a SHA-256 signature over the canonical
data (the review envelope excluded), so two reviews of an unchanged
estate hash identically — the reviewed estate is reproducible. Auditor/
admin role required; the `active_without_mfa` signal is the recurring
control test for the MFA mandate. (2) `docs/policies/` — the draft
information-security policy pack for the auditor: 11 policies (access
control, authentication & MFA, data classification, data protection &
privacy, incident response, vulnerability management, change management,
BC/DR, vendor & third-party risk, acceptable use, umbrella infosec)
grounded in the implemented controls with code-path citations, each
carrying `[ORG: ...]` placeholders for the owners/dates/sign-offs that
must be resolved before it can be presented as approved. (3)
`scripts/record_evidence.py` — records externally-run evidence (DR drill
on the docker host, restore verifications, pen-test reports, third-party
assessments) into the same tamper-evident chain with the platform's own
`ContentHasher`/`ChainHasher` and the same JWS signing, so the SOC 2
observation window includes drills executed outside the runner. Also
fixed `migrations/env.py` calling
`fileConfig` with `disable_existing_loggers=True`, which silently disabled
every other logger in the process for the rest of the process after an
in-process `alembic upgrade` (regression-tested).

**Update (2026-09-21, continued — CC6.3 minutes):** the access-review
**minutes** gained a system of record.
`POST /api/v1/audit-export/access-reviews` records each completed
quarterly review — period, reviewer, the attested `report_hash`, findings
with actions and due dates — and recomputes the estate hash at sign-off,
storing `estate_unchanged` so a review attested against a since-changed
estate says so; one record per period (409 on re-attestation),
append-only, no update or delete path.
`GET /api/v1/audit-export/access-reviews` is the standing record. New
`access_reviews` table (migration `0058`, schema-parity guarded) and
`AccessReviewRecord` model; the estate computation was extracted into
`_build_access_estate` so the export and the attestation can never drift
apart. 4 new tests (round-trip, changed-estate detection, period
conflict + validation, non-auditor 403). Also defused a fixture time bomb
found by the full suite: `test_payment_crypto_api.py` hard-coded
August-2026 HSM event dates, which aged out of the payment rules' 30-day
evaluation window and had silently disabled PAY-006 (auth-failure storm)
— event dates are now computed relative to now.

**Update (2026-09-21, continued — evidence pack):**
`scripts/compliance_pack.py` assembles the SOC 2 evidence pack: one
hash-verified ZIP carrying the policy pack, the committed
production-evidence record, the signed evidence chain + artifacts, the
access-review minutes (`--db-url`), the SBOM (`make sbom`), the DR runbook
and the current gap analysis — with a per-file SHA-256 manifest, a
`pack_hash` over the manifest, and honest `NO_*.txt` notes for anything
absent (never faked, never silently omitted). `--verify` re-hashes any
pack: a tampered, extra, or missing file all flip the verdict to
INVALID. 7 new tests (build/verify, honest gaps, tamper ×3, DB path,
empty-table note).

**Update (2026-09-21, continued — DR evidence + org artifacts):** the
backup/restore drill was **executed end-to-end** in this environment
(fresh dev estate, hot online backup, restore into a clean data dir,
second instance booted from the backup alone, estate verified through
the real API): **PASS 12/12 checks** — including CBOM hash chain
verifying from genesis on the restored estate — and its verdict was
appended to the signed production-evidence chain (VALID, each check a
phase). `scripts/backup_drill.py` gains `--record-evidence` (fail-closed:
a drill that can't be recorded exits 1 even when it passed) and a
configurable interpreter for the restored instance; the append/sign logic
now lives in one shared helper (`record_evidence.append_and_sign`) used
by the recorder and the drill, so all external evidence goes through one
code path. Org-side artifacts materialised: the missing umbrella
`docs/policies/information-security-policy.md` (the index referenced it
but the file didn't exist), `docs/ops/on-call-and-comms.md` (fillable
roster/escalation/comms-SLA template), `docs/compliance/sub-service-matrix.md`
and `rep-letter-template.md`. `scripts/policy_signoff_check.py`
measures exactly what's still unsigned — **100 `[ORG:]` placeholders**
at drafting, per policy, per line — and the compliance pack now embeds
that report (`policy-signoff.json` + a named gap note) so the sign-off
state is inside the auditor's artifact, not a claim. 5 new tests.

**Update (2026-09-21, continued — org artifacts):** the remaining
org-readiness gaps got their artifacts (all measured, not claimed).
Living **risk register** (CC9.1): 12 scored risks, each with treatment,
owner, target, review date — `docs/compliance/risk-register.md`,
enforced so no risk sits without an owner/treatment. **Management
representation letter** template (all 11 representations + CISO/CEO
sign-off block), **quarterly board/audit-committee report** template
(every metric carries a named data source), **security training &
awareness program** (5 mandatory courses, audiences, cadence,
completion records), and the **joiner/mover/leaver** access lifecycle
(background check → NDA → least-privilege role → enforced MFA →
same-day deactivation incl. SCIM DELETE + key revocation, verified
against the access-review export). `scripts/org_readiness_check.py`
runs 17 structural checks across these five documents (owner named,
treatment valid, JML steps present, platform-enforced steps marked,
rep letter signed…) and the compliance pack now embeds the result
(`org-readiness.json` + `ORG_READINESS_PENDING` note) **plus the
documents themselves** (`ops/`, `compliance/`, `org/` sections +
`evidence/backup-drill.md`) — the pack is now self-contained:
31 files, one hash, honest gap notes. 7 new tests; 26/26 green across
the org/compliance/access suites; ruff clean.

**Update (2026-09-21, continued — API performance pass, measured):**
optimized the API tier step by step with before/after numbers on the
live dev server (method + all figures in `docs/performance.md`).
Findings via py-spy: (a) the event loop spent ~40% of its samples in
`starlette.middleware.base` — all 8 custom middlewares were
`BaseHTTPMiddleware`, which wraps every request in an anyio task group +
memory streams; converted all 8 to pure ASGI (send-wrapping, zero
task-group overhead; SSE responses no longer buffered through eight
layers) — behavior pinned by tests incl. a regression test for the
str/bytes setdefault bug the live SSE test caught. (b) SQLite was on
`NullPool`: a fresh connection + 3 PRAGMAs per request (~2 ms), and the
connect/lock churn serialized 8-way concurrency on the file lock — the
dominant cause of the 7× p50 inflation; switched to `QueuePool(10)`
(WAL readers share; single writer serialized by busy_timeout). (c)
uvicorn's access log duplicated the structured `http_request` log;
`--no-access-log` in the production launch commands (measured ~12% off
sequential). Result, same endpoint/machine: sequential p50 15.0→6.4 ms;
8-way p50 110.6→41.5 ms; throughput ~69→160 rps per process. Standing
guidance: scale workers, not one process (GIL-bound; HA compose already
ships `--workers 2`). 60+ middleware/RBAC/SSE tests green; live checks:
401s, login-burst 429s, SSE, correlation headers all intact.

**Update (2026-09-21, continued — pen-test readiness + collector audit):**
verified on disk that the "unbuilt collectors" cited in the 88% readiness
line were **already built and live-wired** (GCP Cloud KMS with algorithm
mapping, AWS ACM, DB-TDE via RDS/Azure-SQL/Cloud-SQL `DATABASE_ENCRYPTION`
findings, mainframe RACF/ICSF/DB2/CICS → unified BOM with a 4-endpoint
banking API; 23 inventory + 18 mainframe tests green) — corrected the
stale "Explicitly open" line that still claimed they were absent. The
genuinely missing part of the "no independent pen test" gap is now
built: **`POST /api/v1/pentest/findings`** ingests a third-party report's
findings (severity-banded per the Vulnerability Management Policy —
explicit name wins over CVSS, CVSS banded 9/7/4), deduplicated per
report+title so re-ingestion is idempotent and **never re-opens a closed
finding**, status-tracked (`OPEN→IN_PROGRESS→REMEDIATED/ACCEPTED/
WONT_FIX`) with due dates; `GET /pentest/findings` + `/summary` (the
board-report "open Critical/High" metric) + per-finding status updates;
role-gated (write: ciso/security_analyst/superadmin; finding details: +auditor; the board-metric summary is additionally visible to readonly/supervisor).
New `pentest_findings` table (migration `0059`, schema-parity guarded);
`docs/security/pen-test-scope.md` is the tester's scope brief (in/out of
scope, access & rules of engagement, report intake with SHA-256
provenance, remediation SLAs). The compliance pack now carries
`pentest-findings.json` (via `--db-url`) or an honest gap note. 5 new
tests (ingest/bands, idempotency + closure respect, summary, validation,
RBAC); 10/10 green with the schema guards; ruff clean.

**Update (2026-09-22, product-surface audit):** audited every UI→API
contract on a FRESH deployment (168 distinct frontend endpoint paths
probed; 72 routes / 71 pages cross-checked). Three genuine defects found
and fixed: (1) `GET /resilience/audit/attestation` 500'd on every dev
instance — `_ephemeral["secret"]` subscripted an object (`_ephemeral.secret`
now) in the no-persisted-key fallback path; verified live: signed
`VERIFIED` attestation with chain head + tamper counters. (2)
`POST /api/v1/banking/iso20022/parse` was a dead UI button — the parser
(`payment_crypto/iso20022.py`, xmldsig AppHdr extraction, key-strength +
quantum-exposure scoring) and its unit tests existed, but the route was
lost; restored in `banking.py` (auth-gated, no persistence); verified live
against the test vector (rsa-sha256 extraction, weak-key finding).
(3) `Scanners.tsx` network fallback called `/api/v1/network/network/discover`
(doubled segment) with the wrong body (`subnet`/`rate_limit` instead of
`cidr`); now hits the real `POST /network/discover` with `{cidr}`.
Confirmed NON-defects (documented so the next audit doesn't re-chase
them): SAML `404`s are the deliberate "not configured" guard (UI checks
`/auth/sso/status` first); onboarding `GET /scope`/`/connections`/
`discovery/*` 404-before-org is the deliberate "no organization yet"
guard; SaaS `400 X-Tenant-ID` responses are tenant-context by design and
the Tenancy page conditionally renders only with a tenant. Full
onboarding wizard E2E verified on a fresh DB (org → sector → environment
→ CIDR+domain scope → connector → checklist 5/7 with honest 409 gates).
i18n: 217/217 flat keys in both en and ar. Routes: 0 dead, 0 orphan
pages. `vite build` green; banking/iso20022/onboarding suites 37/37.

**Update (2026-09-22, backend code optimization — measured):** audited the
backend for code-level inefficiency (data-driven: slowest real endpoints,
polling frequency of each UI call, O(N)-over-unbounded-table patterns).
Headline fix: **audit-chain attestation was 3× O(chain) per call** — the
router loaded every row, `verify_audit_chain` walked + re-hashed all of them,
and `build_attestation` re-walked them in memory. At a 5-year CBUAE retention
chain that is seconds-to-tens-of-seconds per click, forever. Now
`verify_audit_chain_incremental` (user_repository): re-anchors at the
persisted chain head (`app_settings.audit_chain_anchor`) and verifies only
the appended suffix — a full walk runs on cold start, after any
invalidation, when forced (`?full=true`), or when the last full walk is
older than 7 days (bounding the pre-anchor tamper window; the signed report
states `mode` + `full_verified_at` + total `entry_count`, so consumers see
exactly what was verified). New capability: **tail truncation is now
detectable** (chain shrank below the anchored head — undetectable by a plain
walk of the surviving prefix). `build_attestation` accepts a pre-computed
verification (no duplicate in-memory walk); the router no longer loads the
table. Switched to incremental: `GET /resilience/audit/attestation`,
`GET /auth/audit/verify`, and the control-plane posture tick. The audit
**export** deliberately keeps a full walk (WORM artifact — correctness over
speed). Measured on the live 40,019-row dev chain: full walk 735 ms/call →
incremental steady state **3.4 ms (213×)**; endpoint over HTTP 1.46 s cold →
**10.7 ms** steady. 12 new security tests (cold start, O(0) steady state,
suffix-only verification, content/reorder/tamper, truncation, pre-anchor
window + full-walk fallback, stale anchor, forced full, empty chain,
signed-attestation interop). Secondary fixes: `stats/summary` four COUNTs →
one conditional aggregation (unbounded evidence table, polled by 3 pages);
`onboarding/state` discovery-run history bounded to 20 (JSON plan/summary
payloads grew unbounded; the UI reads only checklist fields); SSO
outstanding-AuthnRequest map bounded (abandoned SAML logins leaked entries
in long-running processes). Ruff clean; DB suite 77/77; identity 25/25;
vite build green.

**Update (2026-09-22, E2E SBOM scanner — new capability):** the SBOM surface
previously had **import** (normalize a CycloneDX/SPDX doc someone else
produced) and **export** (render components *passed in by the client*) — but
nothing that actually **scanned a target and generated the BOM end to end**,
which is what an SBOM request in a supplier/regulator questionnaire means.
Now built: `POST /devsecops/sbom/scan` (roles: admin/auditor/security_analyst/
superadmin) scans either a **source tree** (walks requirements*.txt,
package.json, pom.xml, go.mod, Cargo.toml, Gemfile, composer.json, *.csproj —
8 ecosystems, reusing the deterministic manifest parsers; `node_modules`/
`dist`/`build`/`target`/VCS directories always skipped, `vendor/` opt-in via
`include_vendored`) or a **container target** (filesystem rootfs, docker-save
`.tar`, or registry image via the real `ContainerScanner`), enriches
crypto-relevant components from a curated name registry (pyca, OpenSSL,
Bouncy Castle, libsodium, ring, RustCrypto, AWS-LC, mbedTLS, …), and renders
**CycloneDX 1.5** or **SPDX 2.3**. Every scan is persisted as a **hash-signed
artifact** (`sha256` of the exact bytes, listed by
`GET /devsecops/sbom/artifacts`, downloaded via
`GET /devsecops/sbom/{id}/download` with an `X-SBOM-SHA256` provenance
header) and written to the audit chain (`devsecops.sbom_scan`). Fail-closed
throughout: source paths go through the same allow-listed
`validate_source_target` policy as the scanners (secret paths refused,
escapes rejected), unknown `kind`/`format` values are 422 (never silently
coerced), registry pulls are blocked in air-gap mode (`scan.sbom.container`),
and a missing container runtime returns an honest 503 naming what to install
rather than a fake BOM. Pinning accuracy fix found while building it: the
canonical requirements parser normalizes `pkg>=1.0` down to `1.0`, which
made range pins look exact — raw specifiers are now preserved for the
pinning check (`PIN-RANGE`/`PIN-MISSING`/`PIN-NO-DIGEST`). Frontend: the
DevSecOps → SBOM tab now has the scanner form (kind/target/format + flags),
result badges (components, crypto-relevant, pinned/unpinned, sha256),
BOM preview, artifact download, and the persisted-artifact table — plus the
existing import panel. Verified live end to end (demo tree pip+npm+maven+cargo
→ 10 components, 4 crypto-enriched, 8 pinned/2 unpinned, 31 ms; rootfs scan →
3 components incl. binary; download sha256 recomputed == manifest == header;
SPDX 2.3 path green). Tests: 17 new (10 service + 6 API + 1 rootfs), full
devsecops service suite 58/58, `tsc --noEmit` + `vite build` green, ruff
clean.

**Update (2026-09-22, SBOM scanner extension — resolved graphs, assurance,
provenance):** four upgrades on top of the E2E scanner, each closing a gap a
real SBOM consumer hits:

1. **Lockfile resolution (transitive dependencies).** Scan results now merge
   the *resolved* graphs from ten lockfile formats — `package-lock.json` (v2/v3
   `packages` map + v1 fallback), `yarn.lock`, `poetry.lock`, `Pipfile.lock`,
   `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `go.sum`,
   `packages.lock.json` (NuGet) and `gradle.lockfile` — alongside the declared
   manifests. A manifest-only SBOM under-reports the tree (the usual reason a
   supplier SBOM is rejected): the demo tree goes from **3 declared components
   to 11 with 5 direct / 6 transitive and 5 dependency edges**. Resolved
   versions win while the manifest specifier is retained
   (`declared_spec`, exactly what caught `express ^4.18.0 → 4.19.2`), and
   `direct` is only asserted when the lockfile or sibling manifest actually
   supports it (never guessed — Pipfile.lock's `default` section holds direct
   *and* transitive packages, so it stays unknown without a `Pipfile`).
   `use_lockfiles: false` reproduces the declared-only view on demand.
2. **NTIA minimum-elements validation** (`POST /devsecops/sbom/validate`, also
   returned by every scan). Checks supplier, component name, version, unique
   identifiers, dependency relationships, author and timestamp against
   CycloneDX or SPDX input, with per-element coverage (`PARTIAL 1/2
   components`) and the exact gaps — a supplier SBOM missing the purl on one
   component scores `5/7` and names it. Our own scans now record the operator
   as the SBOM author and fill component suppliers from the curated vendor
   registry where it is actually known (`ring → Mozilla`), so they score
   **6/7 with the one honest gap being third-party suppliers we have no data
   for** — the element is never invented.
3. **SBOM diffing** (`POST /devsecops/sbom/diff`): components added/removed,
   version changes with upgrade/downgrade direction, license changes, and
   crypto-relevant deltas, with a verdict (`UNCHANGED` / `UPDATED` /
   `CRYPTO_REVIEW`). Normalizes both formats, so a CycloneDX SBOM can be
   diffed against the equivalent SPDX one (verified: same scan in both formats
   diffs as UNCHANGED).
4. **Signed provenance + retention + reports.** Every artifact manifest is
   HMAC-SHA256 signed (platform vault/settings key, stable across restarts —
   a process-random key would make verification disagree with itself after a
   reboot, so that fallback was deliberately rejected);
   `GET /sbom/{id}/verify` recomputes the blob digest *and* the manifest
   signature and reports which check failed and why;
   `GET /sbom/{id}/report` renders an auditor summary (crypto inventory,
   pinning findings, minimum-elements table, provenance) as markdown;
   `DELETE /sbom/artifacts?older_than_days=N` applies retention.
   BOM enrichment also adds the resolved dependency graph
   (`dependencies: [{ref, dependsOn}]` in CycloneDX, `DEPENDS_ON`
   relationships in SPDX), declared licenses and package checksums in each
   format's own vocabulary.

Verified live (2026-09-22): scan of the demo tree → 11 components, 5
direct/6 transitive, 3 lockfiles, 5 edges, `6/7` minimum elements, signed
`key_id=settings`, 29 ms; diff declared-vs-resolved → `CRYPTO_REVIEW`, 13
changes including 8 previously invisible transitive dependencies; validation
of a supplier document → `5/7` naming its two real gaps; report markdown
downloaded with attachment headers; **tamper drill** — flipping one byte in a
stored BOM and separately editing its manifest both yield `TAMPERED` with the
correct per-check explanation, and repairing returns `OK`; **restart
persistence** — an artifact signed before an API restart still verifies `OK`
after it. Tests: 98 in the SBOM surface (lockfile parsers per format,
cross-format diff, compliance scoring, signing round-trip, provenance checks,
retention, role gating); ruff clean; `tsc --noEmit` + `vite build` green.

**Update (2026-09-22, SBOM scanner — advisory matching, pipeline gate,
re-scan control):** the scanner now answers the two questions a release
engineer actually asks of it: *is this build's dependency set safe to ship?*
and *did anything change under me since I approved it?*

1. **Deterministic advisory matching.** `POST /sbom/scan` accepts an
   NVD-style advisory feed (offline — no network, no AI) and matches it
   against the discovered versions using the same version-range engine as the
   container scanner, with the manager mapped to the feed's ecosystem
   vocabulary (`pip → pypi`, `go → golang`, `gradle → maven`, …). Matches land
   in the document's own vocabulary (CycloneDX `vulnerabilities[]` with
   severity ratings and `affects` refs onto the exact purls) and are counted in
   the manifest. Version boundaries are honoured in both directions — a
   component at or above the advisory's `fixed` version is not reported.
   **Honesty rule:** an SBOM with zero advisories because nothing was checked
   reads differently from one checked against a feed and found clean, so the
   manifest carries `feed_supplied` alongside `vulnerability_count`; the
   scanner never implies a clean result it did not verify.
2. **Supply-chain gate** (`POST /sbom/{id}/gate`, and a CLI for pipelines).
   One policy object decides pass/fail: critical/high advisory allowances, a
   denied-license list, the NTIA minimum-elements requirement, a maximum
   unpinned count and whether an unsigned artifact is acceptable. Blockers fail
   the build and name the rule that fired (`GATE-CVE-CRITICAL`,
   `GATE-LICENSE-DENIED`, `GATE-UNPINNED`, `GATE-UNSIGNED`,
   `GATE-MINIMUM-ELEMENTS`); everything else is a warning that never changes
   the verdict. Because a gate living only behind an authenticated API cannot
   stop a pipeline, the same engine ships as a CLI:
   `python -m devsecops.sbom_gate sbom.json --policy gate.json` (or stdin),
   with release-manager-grade exit codes — **0** passed, **1** blocked,
   **2** usage/IO error, **3** unparseable document — and `--json` for
   archiving the evaluation as evidence.
3. **Re-scan control** (`POST /sbom/{id}/rescan`). Every artifact now records
   the options that produced it, so the platform can re-run the identical scan
   later, store the fresh artifact, diff it against the previous one and gate
   the result in a single call. Verified live: bumping `jws` 3.2.2 → 3.2.3 and
   `cookie` 0.6.0 → 0.7.0 in the tree produced `UPDATED` with both upgrades
   named and the fresh artifact gating clean. Advisory feeds are deliberately
   not persisted (they can be large and are supplied per scan), so a re-scan of
   a fed artifact says so in `notes` — naming the advisories the previous
   artifact recorded — instead of quietly reporting zero. A drill that reverted
   `jws` 3.2.3 → 3.2.2 and `cookie` 0.7.0 → 0.6.0 made the hazard concrete:
   both show as `downgrade`, and the note lists the two advisories the earlier
   feed had matched, so a "clean" gate verdict on that build cannot be mistaken
   for a checked one.
4. **Stronger provenance and reachable data.** Component hashes are now
   decoded from the ecosystems' real integrity formats — npm/NuGet SRI
   (`sha512-<base64>`, strongest algorithm wins), hex digests, and CycloneDX +
   SPDX vocabularies — while Go's `h1:` directory hashes are deliberately *not*
   converted to component digests (they hash a file listing, not the package).
   Artifact listing gained `kind`/`fmt`/`q`/`limit` filters and provenance
   links; read-only (`readonly`/`viewer`) accounts may now list, download,
   verify, report, diff, validate and gate SBOMs — reading an inventory is an
   auditor task — while scanning, re-scanning and retention pruning stay
   operator-restricted.
5. **Fixed while drilling:** `check_minimum_elements()` returned no
   `component_count` for empty/unsupported documents, which crashed the gate
   for any caller that indexed it; dead leftover lines in the SPDX hashing
   branch; the verify note blamed the signature even when only the blob
   digest failed; the SPDX report counted the document's own subject as an
   unpinned component.

Live drill (2026-09-22, artifacts signed with `key_id=settings`): feed with a
critical golang advisory and a high npm advisory → 2 matches on the demo tree
and `FAIL` with `GATE-CVE-CRITICAL`; the same artifact with
`{"allow_critical": 1}` → `PASS` with both advisories still counted; a
component above the advisory's fixed version correctly not reported; filters
(`fmt=spdx` → 2 of 11, `limit=3` → 3 of 9, unknown target → 0); read-only
account → 200 on reads, 403 on scan and prune; gate CLI → PASS/0, FAIL/1,
raised allowance/0, stdin+policy file, and 2/3 for bad input. Tests: 107 in the
SBOM surface (99 service + 8 CLI) plus 19 API route tests; API unit suite
re-run green; ruff, `tsc --noEmit` and `vite build` clean.

**Update (2026-09-22, SBOM scanner — license compliance, VEX, cross-artifact
index):** the third round closes the reviewer-facing questions that follow a
scan: *what licences did we just adopt, is anything owed legal review, what are
we actually doing about each advisory, and where else is this component used?*

1. **License compliance** (`devsecops/sbom_license.py`,
   `POST /devsecops/sbom/license`, console **Licenses** tab). Every declared
   license is grouped by SPDX identifier with the components carrying it, plus
   the components that declare nothing. SPDX expressions are parsed the way the
   spec defines them (`AND`/`OR` split, `WITH` keeps the base license and
   records the exception), and comparison is **family-aware**: a policy
   forbidding `GPL-3.0-only` also catches a component declaring
   `GPL-3.0-or-later`, never the other way round. Verdicts are `FAIL`
   (forbidden present), `REVIEW` (restricted, undeclared, or a copyleft
   combination needing a human) and `PASS`. Two deliberate refusals: an
   **undeclared** license is reported as undeclared — never permitted, never
   denied — and the strong-copyleft trigger is worded as a **policy flag for
   legal review, not a compatibility ruling**, because the platform will not
   fabricate a license compatibility matrix. The gate can run the same engine
   via `license_policy` in its policy object, where forbidden licenses become
   blockers and the rest become warnings.
2. **VEX statements** (`devsecops/sbom_vex.py`, `POST /devsecops/sbom/vex`,
   `GET /sbom/{id}/vex?dl=true`, CycloneDX 1.5 exchange document). An advisory
   the platform matched is reported `exploitable` — that is what the advisory
   asserts for the version range it matched — and when a fix is known it travels
   with the statement (`recommendation`, plus `affects[].versions[{version,
   status:"unaffected"}]`). `not_affected` is produced only two ways: the
   affected component is provably absent (`code_not_present`), or an operator
   supplied a statement **with a valid justification**. A `not_affected` claim
   without one is rejected 422 — the rubber stamp VEX exists to prevent — and
   inventing a state is refused against the CycloneDX enum. Everything else is
   `in_triage` / `can_not_fix`, because the platform performs no reachability
   analysis and will not imply that a vulnerable path is unreachable.
   **Authoring a statement needs an operator role**: read-only accounts may
   derive statements and gate an artifact, but a statement is a judgement that
   ends up in a compliance artefact, so it is not something a view-only account
   can assert (403, verified live).
3. **Cross-artifact index** (`GET /sbom/components`, `GET /sbom/advisories`,
   console **Index** tab) answers "where is this component used?" and "what does
   this CVE affect across the estate?" The advisory view counts **only artifacts
   that were actually matched against a feed** and reports how many were not, so
   a scan run without a feed can never contribute a "no advisories" row.
4. **Remediation travels with the document** — every matched advisory now
   carries `recommendation` and the fixed version in the CycloneDX-idiomatic
   `affects[].versions` form, so a consumer can plan an upgrade without asking
   the platform again.
5. **Fixes found while testing:** the SPDX `WITH` tokenizer treated the
   exception clause as a second license; `-or-later`/`+` variants of a license
   did not classify at all (`GPL-3.0-or-later` came back `unknown`); the license
   route built a string from a dict and called `.get` on it, 500-ing the
   markdown branch.
6. **New doc: `docs/architecture/sbom-scanner-architecture.md`** maps the
   target 11-source / Kafka-Flink / Neo4j / S3-WORM architecture against what
   this repository actually runs, row by row, with the gaps named (no live
   NVD/OSV/KEV fetch, no host agent runtime SBOM, no SLSA/in-toto ingestion, no
   Kafka/Flink/Neo4j/WORM deployment, SWID + CycloneDX 1.6 + SPDX 3.0 and
   XML/PDF exports absent, no license compatibility matrix — deliberately).

Live drill (2026-09-22, demo tree with npm lockfile licences): scan with a
3-advisory feed → 2 matches, both carrying `upgrade to … or later`; VEX derived
2 `exploitable` statements and a CycloneDX VEX document downloadable as
`cryptoscan-vex-<id>.json`; operator override → `not_affected` /
`code_not_reachable` attributed to its issuer, unjustified override → 422,
invented state → 422; licence policy `forbidden:[GPL-3.0-only]` caught the
declared **`GPL-3.0-or-later`** (family matching) with 4 undeclared components
named and the copyleft trigger wording checked; gate with `license_policy` →
`FAIL` on `GATE-LICENSE-FORBIDDEN` with undeclared/copyleft as warnings; index
returned 11 component rows from 1 artifact, `crypto=true` narrowed to
`cryptography`, and after an unfed scan of the same tree the advisory view
reported "2 across 1 checked artifact; 1 was never checked". Tests: 122 service
(118 previous + 14 new licence/VEX) and 23 API route tests; API unit suite
re-run green; ruff, `tsc --noEmit`, `vite build` clean.

**Update (2026-09-19):** enterprise hardening pass on the SaaS branch. The
2026-09-17 router rewrite (hollow "real router" templates) broke the API
import chain and the frontend build; both are repaired: 25 router modules
restored to their last real implementations (validated by the full API test
suite), the phantom `finding_repository` / `api.repositories` imports
removed (117 files), doubled `/api/v1` route prefixes fixed, and the
algorithms router now serves the canonical
`shared_models.algorithm_registry` catalog (195 entries) instead of asset
rows. Frontend: `react-router-dom` declared, `App.tsx` rewritten to the 71
pages that exist (lazy-loaded, unknown routes redirect to Command Center),
the four missing enterprise shell components (context, modals, admin
drawer, system-health modal) implemented against the live API, and the
shared UI kit gained `Button`/`ProgressBar`; `tsc --noEmit` and the
production build are green. Migration **0057** adds the multi-tenant SaaS
core (`tenants`, `tenant_memberships`, `tenant_usage_events`,
`tenant_provision_events`, `tenant_invites`) plus `tenant_id` scoping on
`api_keys` and `monitor_targets` — the schema-parity tests are green again.
CI workflows restored to `.github/workflows/` from `deploy/ci-workflows/`.

Earlier measurement, kept for traceability — at `24a7a0c` (ZELNX security &
scanning policy): 505 OpenAPI paths, ~44 service packages, 54 migrations
(0001–0054), 60 frontend pages, ~3,660 test functions.

## Scope & honest boundaries

What CryptoScan is (and is not) is a tested, versioned manifest, not prose:
`shared/shared_models/shared_models/platform_scope.py`, served at
`GET /api/v1/platform/scope`, enforced by
`shared/shared_models/tests/test_platform_scope.py` (module-path and
docstring boundary checks + evidence-whitelist leakage tests), documented in
[docs/architecture/platform-boundaries.md](architecture/platform-boundaries.md).

Highlights: **read-only, evidence-chained, key *metadata* only (never key
material)**; no general SAST / malware / SIEM behavior analytics / COBOL or
PL-I application-source scanning / employee endpoints; z/OS mainframe
coverage IS in scope as crypto-configuration inventory via operator-produced
extracts (RACF/ICSF/DB2/CICS) — never application-code parsing; cloud scanning is limited to the
accounts/tenants the operator's credentials can see — external surface only
via public internet scanning of configured targets.

## Part 4 — Months 10–12 (logic-4.md)

| Week | Capability | Status | Where it lives |
|---|---|---|---|
| 37–38 | Crypto agility scoring (6-factor, deterministic, history, recommendations) | Built | `services/agility`, `GET /agility`, `GET /systems/{id}/agility`, `GET /agility/roadmap` |
| 39–40 | Quantum deep analysis (Shor/Grover, HNDL, Mosca, deadlines, PQC picks) | Built | `services/quantum`, `GET /quantum/plan`, `POST /quantum/mosca`; classifier in `shared_models` |
| 41–42 | OT/ICS passive scanning (OPC-UA/DNP3/Modbus/IEC 61850, zones, device CVEs) | Built | `services/ot_scanner`, `GET /ot/*`; read-only verified (zero packets to OT net) |
| 43–44 | Vendor crypto discovery — 4 methods, risk 0–100, dashboard | Built | `services/vendor_intel`, `POST /vendors/{id}/api-scan`, `/cbom`, `/docs`, questionnaire, `GET /vendor-risks` |
| 45–46 | Analytics v2 (trends, heat maps, forecast, top-10, executive summary) | Built | `GET /analytics/{trends,heatmap,forecast,recommendations,executive}` |
| 47–48 | Exception management (approval, expiry auto-revert, audit) + migration readiness (5-factor, waves) | Built | `GET/POST /exceptions/*`, readiness stage in worker pipeline |

## Part 5 — Months 13–15 (logic-5.md)

| Week | Capability | Status | Where it lives |
|---|---|---|---|
| 49–50 | CI/CD policy gates (standard/strict/lenient profiles, 422 at boundary, fail-open recording, PR comments) + GitHub/Jenkins/GitLab/ArgoCD | Built | `drift/core/gate.py`, `POST /ci/gate`, `GET /ci/gate-evaluations`, `scripts/ci_gate.py`, `integrations/` |
| 51–52 | Remediation templates: language-specific snippets, testing checklists, real standards refs, multi-step guides, fix-branch payloads | Built | `remediation/templates.py` — 15 rules × 4 languages = 60 snippets + 3 guides (`kms-migration`, `pqc-hybrid`, `tls-upgrade`); `GET /remediation/*`, `POST /remediation/fix-branch` (advisory — never pushes) |
| 53–54 | Migration tracking (auto-project from scan, tasks/milestones, derived progress, velocity forecast, GitHub export + sync) | Built | `POST /migrations/from-scan`, `GET /migrations/{id}/{tasks,progress,forecast}`, `export/github-issues`, `POST /sync`; demo: 207 assets → 207 tasks, 50 done → 24.2% |
| 55–56 | Compliance reports (6 templates, requirement-by-requirement from policy evidence, attestation + canonical SHA-256 hash) | Built | `reporting/report_templates.py`, `GET /scans/{id}/report[.html]`, `GET /scans/{id}/report.pdf`, `GET /report-templates`. NOT_EVALUATED never guessed as PASS. **PDF built**: deterministic A4 rendering of the same report JSON (`reporting/pdf_export.py`, `fpdf2`) — a basic structured PDF, not branded layout. PKI signing built: set `REPORT_SIGNING_KEY` and reports carry a real RS256 signature (OpenSSL-verifiable, `POST /report/verify`); absent when unconfigured — never faked. Scheduling built: `POST /report-schedules` + `run-due` cron entry, immutable `report_snapshots` (migration 0027), email via configured SMTP (`SKIPPED_NO_SMTP` recorded honestly) |
| 57–58 | Hardening: MFA (RFC 6238 TOTP + recovery codes), lockout, RBAC, rate limiting, tamper-evident audit, security headers, prod config fail-closed | Partial (honest) | Migration 0022 (MFA), 0025 (audit chain); `RateLimitMiddleware`; `GET /auth/audit/{verify,export}` (WORM-ready JSONL); OIDC SSO verification (`POST /auth/oidc`, bring-your-own-IdP). RBAC ships 3 roles (admin/auditor/viewer), not the spec's 8. **Not claimed:** mTLS, WAF/DDoS, multi-AZ/DR, Prometheus/ELK/Jaeger, 7-year WORM storage — infrastructure, deployed by you (see `docs/admin-guide/hardening.md`) |
| 59–60 | Performance & polish: measured scan benchmark, hot-path composite indexes, gzip, estate CSV export | Partial (honest) | `scripts/benchmark_scan.py` (10k files in 59.1 s vs 300 s budget, regression-caught history in `docs/admin-guide/performance.md`); migration 0026 indexes; `GET /export/findings.csv` with honest truncation headers. **Not claimed:** Redis caching, materialized views/partitioning, a general GraphQL server (a read-only query subset ships — see the 2026-09-23 update), PWA/frontend polish, Lighthouse, uptime numbers |

## Beyond the plan: live monitoring (24/7)

Not in the original W37–60 plan — added later as `scripts/run_monitor.py`:
watch-list daemon (network endpoints probed live every interval, cloud via
`scan_live`, repos via the job pipeline, containers via image scan), failure
backoff, alert-once semantics, BLOCKED-honesty for unscannable targets, event
feed, `GET /monitor/status` + dashboard "Live monitor" view (5 s refresh).
Migration 0028. See `docs/user-guide/live-monitoring.md`.

**Unified live scan flow (the "one product")** — instead of four independent
scanners, Network / Hardware / Vendor / Cryptography are now driven by ONE
integrated **scan orchestrator** (`api/live_scan/orchestrator.py`,
`GET/POST /api/v1/live/orchestrator/*`, `GET /api/v1/live/environment`). Every
run gets ONE global scan id (`SCAN-YYYY-NNNN`, unique across restarts via the
persisted `scan_seq` counter) and a deterministic phase machine
(`scope_validated → discovery → correlation → risk_calculation →
live_monitoring`). Scope is **fail-closed** (empty authorized scope denies the
scan) and execution delegates to the real `LiveScanRunner`. Run history is
rebuilt from the durable platform event log (`GET /live/orchestrator/history`),
so past integrated scans survive restarts and are visible from any worker.

**Payment crypto (bank gap #1)** — HSM key inventory + ceremonies, audit-trail
ingestion (JSONL/syslog/CSV, timestamp-deduped), TR-31 header parsing, 10
PAY-xxx rules (weak algorithms, rotation, dual control, clear-key exports,
auth storms, firmware changes, B0 blocks), risk acceptance that survives
re-evaluation, `PAYMENT` monitor target, CEF/webhook/SMTP alert routing,
HA compose stack + DR runbook, threat model + dependency audit (0 known CVEs),
API load-test tool. Migration 0030. See `docs/user-guide/payment-crypto.md`.

**Scale/observability/DR/compliance (current round)** — multi-region event
log replication (HMAC-verified, seq-continuous, failback-converging; drill
`docs/region-failover.md`), PITR snapshot+replay to any epoch
(`docs/pitr-drill.md`), platform self-observability (W3C trace-context +
Prometheus `/ops/*`: metrics, traces, SLO burn, self-alerts, capacity
forecast — `docs/round-scalability-observability.md`), signed registry
webhook live burn (`docs/registry-webhook-burn.md`), compliance evidence
pack from live state + JWS attestations + 7-year WORM gate + auditor API
(`docs/compliance-burn.md`).

**Scale/HA/DR (bank gap #2)** — monitor **leader lease** (run N daemons,
exactly one scans; SIGTERM = instant failover, hard loss = failover within
TTL — *verified live* in this environment), Postgres streaming-replication
overlay + `promote-replica.sh` (split-brain guarded), `/api/v1/readyz` LB
drain endpoint (unauthenticated, 503 when DB is down), cluster-wide rate
limits via shared Redis (honest per-replica fallback), automated quarterly
`drill.sh`, load test re-run with throttle accounting (capacity ~1.5k rps
single-process; per-identity budget enforced under 30-VU flood). Migration
0031. See `docs/runbooks/dr-recovery.md`.

**Payment usage analytics (Aug 30)** — key-usage telemetry (ops per key/day,
dormancy PAY-011, dead-key usage PAY-012, shadow keys PAY-013), daily
transaction-volume series + crypto-per-transaction correlation (PAY-014,
honest `insufficient_data` under 14 days), HSM feed connectors (HTTP JSONL
poll with since-cursor, rotation-safe syslog tail, labeled payShield drill
simulator), PAY-xxx evidence wired into the PCI-DSS 4.0 report template with
a `payment_crypto` block. Migration 0032.

**Payment loop automation (Aug 30, pm)** — PAYMENT monitor runner now polls
connector feeds (HTTP `?since=` cursor or rotation-safe file cursor), ingests
daily transaction exports (`transactions_path`), and runs usage + correlation
inside every sweep (PAY-011..014 fire from live data); bulk transaction push
endpoint; dashboard usage/correlation card with ops/tx trend.

**Rotation calendar (Aug 30, evening)** — expiry forecasting across payment
keys and the TLS certificate inventory (horizon buckets, per-ISO-week load),
PAY-015 (rotation inside 90d without a scheduled ceremony), `GET
/payment-crypto/forecast`, dashboard rotation-calendar card, and the payment
section in scheduled report emails (keys, findings, upcoming rotations).

**Ceremony scheduling (Aug 30, night)** — ceremony lifecycle PLANNED/HELD/
ABANDONED (migration 0033): future-dated bookings clear PAY-015, ABANDONED
does not; **PAY-016** flags planned ceremonies past their date (missed
rotation window); PATCH /ceremonies/{id}, ?upcoming=true listing, dashboard
ceremonies card with schedule/mark-held/abandon.

**Certificate renewals + audit pack (Aug 31)** — certificate renewal workflow
(NONE/PLANNED/IN_PROGRESS/DONE, ticket + timestamp, migration 0034),
**CR-001** (certificate ≤30d from expiry with no renewal in flight; sev 4
inside 7d), dashboard "Plan renewal" action, and **GET /audit-export/pack**:
one examiner ZIP (payment keys/ceremonies/findings/forecast, HSM events 90d,
certificate inventory, watch-list, latest PCI report with payment evidence,
evidence chain verification) with a per-file SHA-256 manifest and honest
NO_*.txt notes for anything absent.

**First full end-to-end scan (Aug 31)** — `POST /scans/trigger` on the live
stack scanned this repository itself (HTTPS clone of
`ZKChainForge/CryproScan@96cd6ec`, branch `arena/01a03d0e-cryproscan`):
940 files → 197 deduped findings (10 collapsed) → 197 evidence records with
an intact hash chain (independently re-verified) → gate decision FAIL
(5 blocking: DES/3DES/RC4 in `demo/` apps), quantum HNDL CRITICAL (69
vulnerable sites), agility 67.0, 17 work orders. The audit pack now ships a
real `compliance/pci-dss-4.0-report.json` (attestation + policy-pack hash,
`signature: null` honestly) and `evidence/chain-verification.json` = PASS —
no more NO_COMPLETED_SCAN placeholders. Known cosmetic defect surfaced by
this run: dependency-manifest findings record workspace-prefixed paths
(`data/workspaces/job-…/repo/…`) instead of repo-relative ones.

**Real-time API + machine access (Aug 31)** — the product moved from
poll-and-refresh to push. `GET /events/stream` (SSE, Last-Event-ID resume,
drop-oldest backpressure, heartbeat) backed by an in-process event bus:
scan queued/stage/completed (with gate decision), monitor probe outcomes
(federated from the separate monitor process by a 2s DB tailer — latency
stated, not hidden), logins, API-key changes; `GET /events/recent` for
fallback. Dashboard "Live events" view subscribes live and degrades to
polling honestly. **Machine API keys** (`X-API-Key` on every endpoint,
SHA-256-at-rest, shown once, own RBAC role set, immediate revocation,
throttled `last_used_at`, admin-only management + audit trail, migration
0035) for CI/SIEM integration; rate limiter buckets per key. Honest limits
documented: single-process fan-out (Redis bus is the upgrade path), history
not durable across restarts. See `docs/user-guide/realtime.md`.

## Platform-wide (earlier parts, for completeness)

Evidence hash chain (content + chained hashes, verification script) · CBOM
export (CycloneDX 1.5 crypto-asset) · container SBOM (SPDX-2.3) · deterministic policy engine
with 7 standards packs (baseline, cnsa, fips, hipaa, nist, pci_dss, uae) · multi-user auth with sessions + revocation · HMAC
webhook signing (`X-CryptoScan-Signature`) · dedup via canonical identity
tuples · dependency graph (Tarjan) + blast radius + reachability · drift
detection with blocking severities · cloud/container/network/host scanning ·
air-gap install guide (`docs/admin-guide/air-gap-install.md`).

## Explicitly open (needs real credentials/infrastructure — never stubbed)

- **SSO federation** — OIDC (token relay + server-side authorization-code flow with signed state/nonce), SAML 2.0 SP (metadata/AuthnRequest/ACS with signature verification) and LDAP/AD group→role login are all built, bring-your-own-IdP; what still needs yours: a real issuer/IdP. PKCE for pure-SPA public clients is the next hardening step (`docs/enterprise-readiness.md`)
- **Cloud KMS / cert / DB-encryption / mainframe collectors** — all built and live-wired (verified 2026-09-21): AWS KMS, **GCP Cloud KMS** (algorithm-mapped), Azure Key Vault, **AWS ACM** certificates, **DB-TDE** (RDS `StorageEncrypted`+KMS key, Azure SQL TDE per-database status, GCP Cloud SQL encryption — all surfaced as `DATABASE_ENCRYPTION` findings), and **mainframe** z/OS crypto (RACF `RACDCERT LIST`, ICSF CKDS/PKDS, DB2 TLS, CICS TCPIPSERVICE → one unified BOM with ingest/inventory/analyze/assess API). Read-only metadata; unknown key types are skipped with their reason, never faked. (This line previously claimed GCP KMS/ACM/DB-TDE/mainframe were unbuilt — stale; corrected.)
- **PKI-signed reports** — needs a signing certificate; reports carry an
  HMAC integrity hash today and `signature: null` honestly
- **Live burn-ins** (10k scans/day, 100k assets, uptime) — needs production
  hardware; the repo ships the reproducible benchmark instead
- **Email distribution** — needs SMTP credentials
- **Frontend polish (PWA, dark mode, Lighthouse 97)** — no web frontend ships
  in this repository
