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

## Not implemented (recorded, never hidden)

- runtime monitoring (Tier 2, eBPF): not implemented — no runtime events
  are collected;
- Windows / macOS collectors: not implemented;
- TLS configuration/observation correlation (the three distinct TLS
  findings — supported / enabled / observed): not implemented;
- SBOM/CBOM/HBOM/TechBOM registration: not implemented.
