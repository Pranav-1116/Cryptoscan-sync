# OS & Kernel Intelligence Engine

    Engine: OS & Kernel Intelligence Engine (module name: "OS & Kernel Intelligence Engine")
    Status: IN PRODUCTION for Phase-1 Linux read-only collection (tested against the actual local
    Linux configuration); Tier 2 runtime monitoring is NOT IMPLEMENTED (separately approved)
    NOT AVAILABLE here: Windows/macOS adapters, eBPF runtime tracing (Tier 2), MOK-level Secure
    Boot validation, LUKS metadata extraction beyond lsblk-level reporting
    Register-only forever: bank validation, real-estate data flows, bank qualification runs

The ZELNX OS & Kernel Intelligence Engine (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md) discovers OS identity, kernel configuration, Kernel
Crypto API registrations, loaded modules, crypto providers, certificate
metadata, disk-encryption metadata, hardware trust facts and their
coverage. It is an inventory and a source of evidence-backed detections —
never a verdict (§1).

Read-only by default (Tier 1, §11): the engine reads supported OS
interfaces and normalizes evidence. It never modifies kernel state,
never installs modules, never accesses key material (recovery keys, key
files, passwords, session secrets), and never intercepts application
data. Kernel instrumentation, runtime tracing and configuration changes
belong to Tier 2 and require separate approval.

## The decisive field

`runtime_usage_confirmed: false` on every finding (§10): /proc/crypto
is an inventory of REGISTERED implementations — it is not proof that
any application used them (§2.2). One algorithm can have several
implementations (the recorded host shows sha384 with sha384-avx2 and
sha384-avx); the generic algorithm name and the implementation driver
are kept distinct.

## Honest degradation (§2.1)

- an unavailable source is recorded as UNAVAILABLE with its reason —
  never treated as "disabled", "absent", or as evidence a feature does
  not exist;
- a failed command yields "unavailable or permission-denied" — never a
  zero, never "no cryptography found";
- a flag missing from a config snapshot is not recorded as "disabled" —
  only an explicit `# CONFIG_X is not set` line is a recorded disabled
  state;
- error lines never parse as data (a shell "cannot open" message is not
  a kernel module);
- one successful collection on a development machine is never enterprise
  qualification (§12) — `environment_development_only: true` and the
  qualification note travel with every identity record.

## Phase-1 scope (delivered)

- OS/kernel identity: uname, os-release, cmdline, kernel taints (flag
  meanings decoded from the documented taint bits; a taint is a state
  record, never a defect verdict);
- /proc/crypto parser: bounded, fail-safe, with driver/module/key-size
  metadata and unknown key sizes left unknown;
- kernel modules (LKM) inventory with fail-safe row validation;
- kernel configuration flags of interest (Crypto API, module signing,
  IMA/LSM, RNG trust) with not_set vs missing distinction;
- disk-encryption METADATA via lsblk-style view — never key files or
  recovery keys (§7);
- hardware trust facts (TPM device presence, RNG device presence) —
  device presence is metadata, never a trust verdict.

## BOM integration (delivered)

`bom.py` projects one collection into the SHARED BOM ecosystem (§15
step 6) — never a seventh disconnected BOM: `sbom` (OS, kernel,
modules, provider modules), `cbom` (every registered implementation
with the generic name distinct from the driver), `hbom` (hardware trust
facts + acceleration indicators), `techbom` (the union). The
provides/uses discipline is structural: the kernel PROVIDES a
implementation; this engine emits NO 'uses' edge, ever, and never
infers application↔kernel relationships from same-host co-location
(§8). Versions the sources do not report stay unknown — module
versions are never guessed.

## Console (delivered)

`/os-kernel-intelligence` — nine views (hosts & identity, kernel crypto
API, modules, configuration, disk encryption, hardware trust, findings,
coverage, OS-CRYPTO rules) with the honesty rules as display rules: an
unknown renders "unknown (never guessed)", 'not detected' renders its
"never absent" text visibly, every capability row shows "runtime usage
not confirmed", unavailable coverage sources render their reasons, and
every host carries its development-only / qualification caveat.

## OS-CRYPTO rules (delivered)

The OS-CRYPTO-001…018 catalogue (§9) evaluates over every collection:
detections, never automatic vulnerability verdicts. A rule whose
evidence source is missing reports NOT EVALUABLE with the missing
source named — never a clean result. Severity is computed by
risk.py (R=f(S,E,X,B,C), model os-risk/1.0) with preserved factors and
a written derivation — never a multiplied "scientifically validated
score". 'critical' is reachable only through B=registered_high with
X=observed; business impact is never invented (B stays
"requires_registered_mapping" until a registered mapping supplies it).

## Windows adapter (delivered with stated provenance)

`windows.py` normalizes captured Windows outputs (systeminfo, certutil
-csplist CSP/KSP registrations, SCHANNEL protocol registry, cipher
order, manage-bde BitLocker metadata, Get-Tpm, Confirm-SecureBootUEFI,
driverquery) into the SAME canonical OSInventory model (§15 step 4).
Rules evaluate with platform honesty: Linux-specific rules report
NOT EVALUABLE ("Linux-specific source"), and OS-CRYPTO-006 implements
the ENABLED-BY-CONFIG axis in the §9 example format — supported and
observed-negotiated stay distinct and unestablished.

PROVENANCE (§12): the test fixtures are RECONSTRUCTED from documented
output formats — NOT captured from a live Windows host. The adapter
status is "validated against documented output formats"; live-Windows
validation and enterprise Windows fleet qualification are NOT DONE and
never claimed. ETW runtime tracing is Tier 2 and NOT implemented.

## macOS adapter (delivered with stated provenance)

`macos.py` normalizes captured macOS command outputs (sw_vers/uname
identity, csrutil SIP, spctl Gatekeeper, fdesetup FileVault METADATA,
kmutil kernel extensions) into the SAME canonical model. Per the spec
boundary (§5/§7): Security framework / Keychain command OUTPUTS only —
protected storage files and keychain databases are NEVER scraped. The
crypto provider inventory is recorded UNAVAILABLE ("macOS exposes no
/proc/crypto equivalent — never 'no providers'"). OS-CRYPTO-010 now
evaluates the Windows-collected Secure Boot state; on macOS the note
keeps SIP as a distinct claim.

PROVENANCE (§12): fixtures RECONSTRUCTED from documented output
formats — NOT captured from a live macOS host; live validation and
fleet qualification are NOT DONE and never claimed.

## Certificate metadata (OS-CRYPTO-008's source, §7)

`certificates.py` normalizes certificate METADATA from two documented
formats: `openssl x509 -noout` output (Linux + macOS — the fixture is
REAL host corpus captured from this machine's actual CA bundle) and
`certutil -store` blocks (Windows). PUBLIC attributes only: subject,
issuer, validity dates, SHA-256 thumbprint, public key size — private
keys are NEVER collected, exported, displayed or stored. Certificates
persist to `os_certificates` (migration 0144) and serve via
`GET /assets/{id}/certificates`.

OS-CRYPTO-008 evaluates expiration from the collected dates
(expired / ≤30 days = near_expiration). Unparseable validity dates are
UNKNOWN — never 'not expired'; no certificate metadata is never
'all valid'. Severity is computed by os-risk/1.0 — without a registered
business mapping 'high' is UNREACHABLE and the derivation records the
cap.

## Tier-2 runtime observation (approved — built)

`runtime.py` ingests runtime METADATA events from the approved
tracepoints/eBPF collector: bounded event filter (allowlisted fields
only — plaintext, keys, passwords, tokens, secrets and crypto I/O
buffers are REFUSED with reasons and counted), schema validation,
deduplication with notes, and event-loss accounting from the
collector's own LOST lines (recorded, never guessed).
`runtime_usage_confirmed` is raised ONLY by observed runtime events,
scoped to the observed process identity, and never overwrites the
static registration row (§2.2).

Real capture tooling for an authorised host:
`tools/runtime_capture/crypto_trace.bt` (scoped bpftrace program,
metadata-only output) + `capture-linux-runtime.sh` (prerequisite
checks, enumerates and RECORDS the instrumentation points actually
attached — tracepoints are never assumed, folds loss accounting into
LOST|N). The development sandbox has no root and no bpftrace, so the
trace fixtures are RECONSTRUCTED from the documented capture format
and labelled; the collector program and driver are real code to run
under an approved profile.

OS-CRYPTO-017 evaluates from a runtime session: event loss = 'Runtime
collector losing events' (observability gap — capabilities without
runtime events remain 'usage not confirmed', NEVER 'unused'); no
session is never 'healthy'; a zero-event session is UNKNOWN, never
'no cryptographic activity'.

Live-host validation (Windows/macOS): `tools/live_capture/
capture-windows.ps1` and `capture-macos.sh` capture the documented
sources with manifests (macOS: command outputs only — protected
storage files and keychain databases are never scraped); `validate_
capture.py` feeds a capture directory into the matching collector and
the OS-CRYPTO catalogue. One capture validates THAT HOST'S CAPTURE
ONLY — never fleet qualification (§12).

## Not implemented (recorded, never hidden)

- runtime monitoring (Tier 2, eBPF): not implemented — no runtime events
  are collected;
- macOS live-host validation and fleet qualification: NOT DONE (the
  adapter is fixture-validated against documented output formats
  only);
- Windows live-host validation and fleet qualification: NOT DONE (the
  adapter is fixture-validated against documented output formats
  only);
- TLS configuration/observation correlation (the three distinct TLS
  findings — supported / enabled / observed): not implemented
  (OS-CRYPTO-006 reports NOT EVALUABLE, never clean);
- Secure Boot state, certificate metadata, provider-version
  vulnerability correlation: not collected (OS-CRYPTO-008/010/011
  report NOT EVALUABLE);
- SBOM/CBOM/HBOM/TechBOM registration into the external CycloneDX
  export pipeline: the local projection (bom.py) is delivered; the
  export-schedule wiring is not.
