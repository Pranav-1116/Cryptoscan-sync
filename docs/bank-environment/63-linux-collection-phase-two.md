# Phase 2 — scoped Linux runtime and package collection

**2026-10-24 · Linux runtime implementation, followed by Windows candidate work**

[Foundation](62-universal-collection-foundation.md) ·
[Windows candidate / native gates](64-windows-collection-phase-three.md) ·
[Execution evidence](../readiness-evidence/linux-runtime-windows-candidate-2026-10-24.md)

## What changed from the initial Linux increment

OS declarations, package databases and public certificate/configuration/header
metadata were not substitutes for runtime evidence. This increment adds actual
explicit PID, mapped-path, listening-socket, named-systemd-service and kernel
hardware interfaces, and an additional Alpine package database profile. It keeps
one intake and one normalization path, not a new scanner for each BOM.

**Implementation and native qualification are separate.** Ordinary-user Linux
process/library, owned TCP listener and CPU-topology witnesses run here. Positive
systemd-service, DMI and TPM execution cannot be qualified on this sandbox: no
usable system systemd bus, DMI metadata or approved `tpm0` interface is readable. Their missing/denied
interfaces produce receipts, not invented assets. Full Linux/bank qualification
is therefore still open; the Windows work is explicitly candidate development,
not a declaration that every Phase 2 acceptance gate passed.

## Explicit approved inputs

| Input kind | Approved resource example | Fact / contribution | What it does **not** establish |
|---|---|---|---|
| `LINUX_PROCESS` | `linux-proc://1234/process` or `linux-proc://self/process` | PID, start tick, boot ID, comm; optional cgroup service membership → TechBOM | Executable signature/version, service ActiveState, authenticated host or cryptographic invocation |
| `LINUX_PROCESS_MAPS` | `linux-proc://1234/maps` | `.so`/`.so.*` named mapped paths tied to PID/start/boot, deleted-file marker → SBOM/TechBOM | ELF validation, `dlopen`, executable mapping permissions, library version, provider/algorithm calls or a package-to-process relationship |
| `LINUX_LISTENERS` | `linux-sockets://self/tcp` or `linux-sockets://self/tcp6` | Current-network-namespace LISTEN address/port/inode → NBOM/TechBOM | TCP ownership by a process, reachability through firewalls/NAT, TLS because of port 443, served certificate or negotiated traffic |
| `LINUX_SERVICE` | `systemd://payments.service` | Named service LoadState/ActiveState/MainPID → TechBOM | Health SLA, cryptographic operations, executable provenance or service↔process-start identity |
| `LINUX_HARDWARE` | `linux-hardware://cpu0` | Explicit CPU/core/package indexes reported by kernel sysfs → HBOM/TechBOM | Physical-asset attestation, affinity/quota, all CPUs, TPM/HSM capability or use |
| `LINUX_HARDWARE` | `linux-hardware://dmi` | Available vendor/product/BIOS-version strings → HBOM/TechBOM | Serial-number identity, authenticated physical manufacturer or hardware mechanism use |
| `LINUX_HARDWARE` | `linux-hardware://tpm0` | Explicit TPM device's kernel-reported major version only → HBOM/TechBOM | TPM mechanisms, PCR attestation, key inventory, signing operations or HSM/KMS use |
| `APK_INSTALLED` | Explicit regular `/lib/apk/db/installed` file | Installed database package name/version → SBOM/TechBOM | Native Alpine estate qualification, package origin/signature, library linkage or algorithm invocation |
| `DPKG_STATUS` | Explicit regular dpkg status file | Existing installed-package name/version profile → SBOM/TechBOM | All distributions, RPM support, executed packages or package authenticity |
| `LINUX_OS_RELEASE` | Explicit regular `/usr/lib/os-release` file | Literal ID/optional VERSION_ID, DECLARED → TechBOM | Attested running kernel/OS |
| `BINARY_METADATA` | Explicit ELF/PE regular file | Existing header presence → SBOM/TechBOM | Binary execution, dynamic linking or algorithm use |
| `PUBLIC_CERTIFICATE` | Explicit public certificate file | Existing public key/certificate metadata → CBOM/TechBOM | Served certificate, private keys or key operation |
| `NGINX_TLS_CONFIG` | Explicit regular config file | Existing allowlisted literals, DECLARED → CBOM/TechBOM | Includes/variable expansion or effective negotiated sessions |

`self` means the **collector process**, not the application operator wishes to
inspect. Approve an exact application PID to inspect that process. Neither URI
accepts a wildcard, arbitrary `/proc` filename, command line, environment or memory
read. No PID enumeration, UDP probe, packet capture, active handshake, serial read,
TPM operation or elevated fallback is introduced.

A service name observed in a process cgroup is membership metadata, **not** an
SCM/systemd state query or proof the service is healthy. Facts intentionally do
not fabricate graph edges from a service MainPID, socket inode, library path or
co-existing package alone.

## Boundary and resource controls

1. Existing exact authorization, estate, time window, least-privilege and intake
   admission controls still apply. Root/effective/permitted capabilities are
   refused. Denied PID visibility is not retried with privilege.
2. Runtime resource grammar is validated in the shared input contract before
   authorization/execution; import validation also binds facts to approved PID,
   network address family, named service or hardware resource and native
   interface. Duplicate runtime identity slots within one input are refused.
3. Kernel pseudo-files are opened without following the **leaf** symlink and
   checked by descriptor `fstatfs` against procfs/sysfs. They are not passed
   through the ordinary-file reader or accepted as arbitrary temporary fixtures.
   Fixed kernel-interface parents can contain kernel-controlled links; the TPM
   class link is deliberately resolved only under `/sys/devices`, then sysfs is
   verified on the opened attribute. This is **not** a generic symlink exception
   for approved filesystem inputs. Regular-file no-follow traversal remains.
4. Source reads, repeat checks and encoded runtime projection share the existing
   per-input/total charged-byte limits. There is a one-byte overflow detection
   read, never a truncated positive fact set. Existing 100-input/1,000-fact limits
   remain. Runtime `byte_count` is charged metadata work, **not** the length of a
   single original file or RPC/network traffic measurement.
5. PID start ticks and boot identity are checked before/after. Mapped-path sets,
   listener projections/netns and CPU indexes are checked again for changes;
   process comm/cgroup are rechecked too. This is sampled consistency, **not** an
   atomic host snapshot. Kernel reads do not gain a guaranteed global wall-clock
   deadline; isolated worker cancellation remains a production qualification gap.
6. Service collection executes only root-owned, non-writable, non-setid,
   capability-free ELF `/usr/bin/systemctl`, pinned by descriptor through
   root-owned non-writable directories. Fixed `--system ... show` arguments,
   strict `.service` name, `--` separator, sanitized environment, no shell,
   stdin closed, stderr discarded, bounded stdout, three-second deadline and
   child process-group kill/reap cover timeout/overflow/error cleanup. No
   service start/stop/reload, credential use, remote bus or arbitrary executable
   is accepted. Hosts with another systemctl layout are unsupported, not guessed.
7. Missing/denied/unsupported interfaces, changed reads, malformed records,
   expired windows and exhausted budgets return typed failed receipts with no
   positive facts/content hash. No listening rows or qualifying shared-object
   paths also remains an unqualified empty surface, not host-wide absence.

## Commitments, identity and projection

New `RuntimeFact` is a separate strict union member: old `HostFact` fields and
canonical defaults are untouched. The four pinned shared schemas are updated.
Runtime interface SHA-256 commits the ordered length-framed source-read chunks
(including repeat checks); receipt SHA-256 commits the canonical allowlisted fact
projection carrying that interface commitment. Raw proc maps, unrelated socket
rows, unallowlisted cgroup text and service stderr are not uploaded. These are
local integrity commitments, **not** signed collector/clock/host authenticity or
a self-contained replay of discarded original source bytes.

Process identity uses boot/PID/start ticks; mapped-path identity additionally
includes path hash/deletion marker; listeners include boot/netns/inode. These
feed the existing target/input-scoped metadata slot, preventing all libraries in
one input from collapsing into one subject. Socket inode reuse, namespaces,
changing paths and untrusted imported host labels still preclude an attested
cross-host/global asset identity claim.

Local basis is OBSERVED **interface metadata**; API provenance remains IMPORTED.
`LOADED_LIBRARY` is explicitly tagged
`mapping_basis=SHARED_OBJECT_PATH_SUFFIX_ONLY`: this is a named file mapping,
not a verified dynamic-linker library type. Every runtime fact retains algorithm,
cryptographic runtime/operation/PQC use UNKNOWN and policy NOT_EVALUATED.

All six views remain available. Listeners now populate NBOM; supported hardware
populates HBOM; library mappings/packages populate SBOM; services/processes and
all supported metadata populate TechBOM. Existing certificate/config evidence
can populate CBOM. VBOM remains empty UNKNOWN without vendor evidence. Views
reference the **same original observation IDs** and are not native standard
BOM documents. The official-schema-validated CycloneDX 1.6 CBOM path remains
separate and excludes runtime metadata that provides no algorithm evidence.

## Practical operator example

Add only independently reviewed resources to the actual approved manifest:

```json
[
  {"input_id":"payment-process","kind":"LINUX_PROCESS","path":"linux-proc://1234/process"},
  {"input_id":"payment-mappings","kind":"LINUX_PROCESS_MAPS","path":"linux-proc://1234/maps"},
  {"input_id":"namespace-listeners","kind":"LINUX_LISTENERS","path":"linux-sockets://self/tcp"},
  {"input_id":"payment-service","kind":"LINUX_SERVICE","path":"systemd://payments.service"},
  {"input_id":"cpu-zero","kind":"LINUX_HARDWARE","path":"linux-hardware://cpu0"}
]
```

The namespace TCP table is an explicit namespace-level approval, not an
application-PID-only approval. Get the bank's consent for that wider surface.
The registry `address`/`host_id` remains an operator label; it is not SSH/DNS
resolution or authenticated device binding.

```bash
python scripts/collect_host.py --target-spec reviewed-target.json --output new-snapshot.json
```

Output is exclusive-create 0600, no automatic upload. Exit 0 means every approved
input produced metadata; exit 2 means receipt gaps, **not an insecure host**;
exit 64 means invalid scope/input/output. No overwrite/replay/remote shell.

OS-release is still parsed literally, never sourced/expanded; only ID and optional
VERSION_ID survive. Symlink `/etc/os-release` is still refused: approve a reviewed
regular file explicitly. Alpine only exports P/V installed-record fields, checks
ambiguous/missing/duplicate identities and never invokes apk or install scripts.

## Remaining qualification and implementation boundaries

- Positive native systemd, DMI and TPM fixtures; denied/changed/interface-missing
  variants on the intended hosts; independently reviewed expected-truth results.
- Alpine native-host review, RPM/other package profiles, alternate systemd
  layouts, additional distributions/architectures and package/binary signatures.
- Verified ELF/provider attribution, algorithm invocation, effective TLS, hardware
  mechanisms and HSM/KMS operations require **additional actual evidence**;
  none can be obtained by relabeling mapped paths or hardware metadata.
- Signed collector release/identity and authenticated host/time binding, isolated
  admission→queue→worker execution, external security review and bank approval
  remain open. Existing local hashes do not close them.
- No full-bank coverage denominator, p95/p99/20% performance qualification,
  deployed HA/TLS/monitoring acceptance or production collection is claimed.

The next [Windows candidate](64-windows-collection-phase-three.md) deliberately
keeps native Windows and production qualification false rather than enabling a
future-phase adapter based on Linux mocks.
