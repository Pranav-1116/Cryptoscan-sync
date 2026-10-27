# ZELNX Universal Vendor Scanner

Vendor-neutral crypto + crypto-configuration discovery across every vendor
category, per the ZELNX Universal Vendor Scanner spec (§1–§24) — plus the
**24/7 Live Vendor Engine** (`universal_vendor/live/`, spec §1–§26) that
monitors vendor infrastructure continuously, and the **Universal Hardware
Scanner** (`universal_vendor/hardware/`, spec §1–§25) that inventories and
monitors physical hardware: servers, network, HSM/TPM/smart cards, storage,
GPUs, virtualization, and OT/ICS — always read-only.

## What it does

One plugin contract (`UniversalVendorPlugin`), one canonical pipeline:

```
Vendor Data → Plugin → Raw Observation → Evidence → Normalization →
CryptoObservation → Canonical Asset
```

Every vendor plugin produces the same canonical output; vendor-specific
fields are preserved verbatim in `vendor_specific` (§20) — nothing is lost.

## Package layout

| Module | Spec | Purpose |
|---|---|---|
| `models.py` | §1, §15, §20, §22–§24 | enums + canonical observation models |
| `plugin.py` | §1 | common plugin contract + secret scrubbing |
| `registry.py` | §17, §18 | plugin registry (trust-gated) + capability registry |
| `detection.py` | §16 | multi-signal vendor detection engine (~120 patterns) |
| `normalizer.py` | §1, §20 | UniversalObservation → CryptoObservation via shared `parse_algorithm` |
| `evidence.py` | §1 | SHA-256 evidence chain + verification |
| `graph.py` | §21 | universal vendor dependency graph (nodes/edges/paths) |
| `pqc_readiness.py` | §22 | versioned, evidence-backed vendor PQC readiness DB |
| `lifecycle.py` | §23 | versioned lifecycle DB + migration priority |
| `scan_modes.py` | §24 | six scan modes driving any registered plugin |
| `sdk.py` | §19 | plugin SDK: `manifest.yaml` parsing + package loading |
| `plugins/` | §2–§15 | 68 bundled vendor plugins across all 16 categories |
| `sdk_template/` | §19 | copyable third-party plugin template |
| `live/` | 24/7 §1–§26 | **live vendor engine** — see below |
| `hardware/` | HW §1–§25 | **universal hardware scanner** — see below |
| `hardware/plugins/` | HW §25 | 30 hardware plugins (server/network/hsm/tpm/storage/gpu/virtualization/iot/industrial) |
| `tests/` | — | 267 tests covering every component (scan framework + live engine + hardware scanner) |

## 24/7 Live Vendor Engine (`universal_vendor/live/`)

Continuous, low-load vendor monitoring wired into the scan framework:

| Module | Spec | Purpose |
|---|---|---|
| `monitoring.py` | §1 | seven live monitoring modes + `LiveConnector` / `LiveVendorMonitor` |
| `events.py` | §2 | universal event gateway + `EventNormalizer` (vendor alias resolution) + canonical `UniversalVendorEvent` |
| `state.py` | §3 | persistent per-asset live state (NEW / CHANGED / REMOVED / NO_CHANGE) |
| `vendor_monitors.py` | §4–§8 | Cisco (NETCONF/RESTCONF/SNMPv3/telemetry), firewall, load balancer, PKI, HSM live monitors — HSM is metadata-only with a secret-material guard |
| `cert_watcher.py` | §9 | universal certificate watcher (new/renewed/expired/revoked/algorithm/key-size/chain) |
| `drift.py` | §10 | EXPECTED vs CURRENT drift → NO_CHANGE/EXPECTED/APPROVED/UNEXPECTED/CRYPTO_DRIFT/CRITICAL_CRYPTO_DRIFT |
| `firmware.py` | §11 | firmware tracking with evidence-backed PQC recheck (never assumed) |
| `fingerprint.py` | §12 | config fingerprints + crypto-relevant diff gating for deep scans |
| `identity.py` | §13 | shared asset identity across network/vendor/cloud scanners |
| `correlation.py` | §14, §18, §19 | vendor↔cloud edges, blast radius, one-incident alert correlation |
| `pqc_live.py` | §15 | live PQC monitoring with six capability states + migration impact |
| `health.py` | §20 | connector health (8 states) |
| `offline.py` | §21 | local event queue + evidence store + secure sync for isolated networks |
| `regions.py` | §22 | control plane + regional edges (UAE/EU/USA) that keep working offline |
| `credentials.py` | §23 | credential references → vault → short-lived scoped access (never inside plugins) |
| `plugin_runner.py` | §24, §25 | plugin sandbox (timeout/limits/scrubbing) + plugin lifecycle stages |
| `cbom.py` | §26 | event-sourced live vendor CBOM (reuses `CbomGenerator` when present) |
| `engine.py` | — | `LiveVendorEngine` orchestrator: collect → normalize → resolve → state → CBOM → graph → PQC |

```python
import os
from universal_vendor import LiveVendorEngine

# The endpoint, vendor identity, asset identity, and optional auth_env are
# operator configuration. No endpoint means UNAVAILABLE; no demo event is made.
os.environ["CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS"] = (
    '[{"endpoint":"https://router.example.invalid/restconf/data/crypto",'
    '"vendor":"Cisco","product":"IOS-XE","asset_id":"r1",'
    '"source":"restconf","auth_env":"CISCO_READONLY_TOKEN"}]'
)
engine = LiveVendorEngine()
print(engine.tick())   # polls the configured source and scans returned evidence
```

For production API workers, use the tenant onboarding connector path instead
of process environment configuration. Store only the endpoint, vendor/product,
asset id, source method, and a non-secret `auth_ref`/`vault_ref` in connector
metadata. The API worker resolves a short-lived read-only vault lease for each
poll. `HttpVendorConnector` supports JSON/text management API and telemetry
polling; `JsonLinesEventConnector` consumes a deployed JSON-lines syslog or
telemetry forwarder spool; `UdpJsonEventConnector` accepts structured
syslog/telemetry datagrams on an explicitly configured local listener.
Missing source, credentials, permissions, or reachable evidence is reported as
`UNAVAILABLE`, never as a finding.

## Scan modes (§24)

`AUTO_DETECT` · `INVENTORY_ONLY` · `CRYPTO_DISCOVERY` ·
`CONFIGURATION_DISCOVERY` · `DEEP_DISCOVERY` · `CONTINUOUS_MONITORING`

```python
from universal_vendor.plugins import build_registry
from universal_vendor.scan_modes import UniversalVendorScanner

scanner = UniversalVendorScanner(registry=build_registry())
report = scanner.run(
    {"banner": "Cisco IOS-XE Software, Version 17.9.4a",
     "config": open("device.cfg").read()},
    scan_id="scan-1",
)
print(report.detection, len(report.observations),
      report.evidence_verification["chain_intact"])
```

## Trust model (§18)

Bundled plugins are first-party and trusted. Third-party plugins (SDK §19)
default to `trusted: false` in their `manifest.yaml`: they can be registered
and inspected, but automatic execution raises `UntrustedPluginError` until an
operator explicitly reviews and flips the flag.

## Non-negotiable invariants

- **HSM is metadata-only** — private keys, master keys, PINs and credentials
  are never extracted (enforced by an assertion in `plugins/hsm.py`).
- **Never infer PQC support from a product name** — every PQC verdict is
  evidence-backed, versioned, last-verified; unknown → `UNKNOWN` (§22).
- **No single-signal detection** — vendor detection aggregates network
  banner / DNS / TLS cert / SNMP / API metadata / HTTP headers / SSH banner /
  MAC OUI / cloud metadata / controller metadata / authenticated API (§16).
- **SaaS honesty** — only API-exposed crypto configuration is reported;
  otherwise `OBSERVED` / `API_VISIBLE` / `UNKNOWN` / `NOT_SUPPORTED` (§15).
- **EKS/AKS/GKE are not separate systems** — one Kubernetes core scanner plus
  provider adapters (§14).
- **EDR/SIEM are intelligence sources only** — no duplicated EDR behavior
  analytics; SIEM events feed crypto intelligence → evidence → Live CBOM.
- **Hardware identity is never serial-dependent alone** — multi-signal
  resolution (serial/MAC/UUID/tag/BMC/hostname/cloud) with ≥2 kinds → HIGH (§3).
- **CPU/TPM/HSM/smart-card discovery is metadata only** — instruction-set
  presence is a capability, not usage; secret material is refused by hard
  assertions (§5–§8).
- **OT/ICS scanning is passive-first**; ACTIVE/DEEP require approved scope,
  and every scan passes the §23 safety gates (authorized scope, read-only,
  rate limits, maintenance windows, kill switch).
- **Cloud hardware honesty** — physical host knowledge is only reported when
  the provider exposes it: OBSERVED / PROVIDER_DECLARED / INFERRED / UNKNOWN (§13).

## Universal Hardware Scanner (`universal_vendor/hardware/`)

A read-only hardware intelligence platform covering compute, network,
security (HSM/TPM/smart card), storage, GPU and industrial/IoT hardware:

| Module | Spec | Purpose |
|---|---|---|
| `models.py` | §1 | canonical `HardwareObservation` / `HardwareIdentity` + `HardwareType` (compute/network/security/storage/industrial), `DiscoveryMethod`, `HardwareConfidence`, `CloudVisibility`, `FirmwareComponent`, `HardwareDriftType` |
| `plugin.py` | §25 | `UniversalHardwarePlugin` contract (detect/identify/inventory/discover_firmware/discover_crypto/discover_capabilities/collect_evidence/normalize/health_check) + registry by category/manufacturer + banner detection + secret scrubbing |
| `discovery.py` | §2 | agent (DMI/PCI/USB/BMC) + network (SNMP/SSH/LLDP/CDP/passive) + API collectors; orchestrator merges by `asset_id`, higher confidence wins — never one source alone |
| `fingerprint.py` | §4 | weighted multi-source fingerprinting (dmi/serial/bmc/snmp/api/firmware/mac/lldp/cdp/pci/usb/banner/cloud) → HIGH ≥1.8 / MEDIUM ≥0.9 / LOW; sha256 `FingerprintTracker` |
| `identity.py` | §3 | multi-signal identity resolver (serial/MAC/UUID/tag/BMC/hostname/cloud) — ≥2 distinct kinds → HIGH; serial alone is never enough |
| `cpu.py` | §5 | vendor/family/model/arch/extensions/cores/threads/microcode; AES/SHA/RNG/trusted-execution recorded as **capability**, never as usage |
| `tpm.py` | §6 | TPM present/version/manufacturer/firmware/algorithms/PCR/secure-boot — metadata only, secret material refused; drift → `SECURITY_HARDWARE_DRIFT` |
| `hsm_hw.py` | §7 | HSM hardware metadata + vendor HSM scanner integration + `HSM_CAPABILITY_CHANGED` / `FIRMWARE_CHANGED` / `CRYPTO_SUPPORT_CHANGED` / `CONFIGURATION_CHANGED` events; keys never extracted |
| `smartcard.py` | §8 | smart card / secure element vendor/model/interface/firmware/algorithms/cert-references/app-deps — metadata only |
| `firmware.py` | §9 | 11 monitored components (BIOS/UEFI/BMC/NIC/RAID/HBA/TPM/HSM/storage/appliance/GPU); change → targeted crypto re-evaluation hook |
| `capabilities.py` | §10 | `CryptoCapabilityEngine` — supported-by-hardware strictly separate from actually-used-by-software; `CapabilityRegistry` by model |
| `correlation.py` | §11–§13 | hardware→software chains, hardware→network (server→NIC→switch→FW→LB→app), cloud visibility OBSERVED/PROVIDER_DECLARED/INFERRED/UNKNOWN |
| `lifecycle.py` | §14 | evidence-backed EOS/EOL/replacement/PQC; legacy HSM + no PQC + EOS → CRITICAL migration candidate; unverified → UNKNOWN |
| `live.py` | §15–§17 | `LiveHardwareMonitor` sources, `HardwareStateEngine` (NEW/CHANGED/REMOVED + 24/7 fields), `HardwareDriftEngine` expected-vs-current |
| `risk.py` | §18 | risk = criticality + crypto deps + age + firmware + PQC + exposure + replacement difficulty → CRITICAL ≥12 / HIGH ≥9 / MEDIUM ≥6 |
| `hbom.py` | §19 | HBOM (hardware + firmware + security hardware) connected to CBOM/SBOM/live dependency graph |
| `alert.py` | §21 | one root hardware change with child events — never four unrelated incidents |
| `ot.py` | §22 | passive-first OT/ICS mode; SAFE/CAUTIOUS always allowed, ACTIVE/DEEP require approved scope |
| `safety.py` | §23 | mandatory controls: authorized scope, exclusions, read-only, rate limits, connection limits, timeouts, vendor profiles, maintenance windows, audit log, kill switch; NEVER extract keys/secrets, bypass auth, modify configs, disable security controls |
| `regions.py` | §24 | control plane → regional edges; offline: local durable queue → local evidence → central sync |
| `evidence.py` (shared) | §20 | observation → canonical serialization → content hash → previous-evidence hash → chained evidence record |
| `scanner.py` | — | `UniversalHardwareScanner` pipeline: discovery → fingerprint → evidence chain → HBOM → graph → PQC → lifecycle → risk |
| `plugins/` | §25 | 30 concrete hardware plugins in `hardware_plugins/` by category |

```python
from universal_vendor.hardware.plugins import build_registry
from universal_vendor.hardware.scanner import UniversalHardwareScanner

scanner = UniversalHardwareScanner(plugins=build_registry())
result = scanner.scan({
    "dmi": {"serial": "SN-E2E", "product": "PowerEdge R740",
            "bios_version": "2.10", "manufacturer": "Dell Inc."},
    "bmc": {"firmware": "5.2"},
    "cpu": {"vendor": "GenuineIntel",
            "instruction_extensions": ["aes", "sha_ni", "rdrand"]},
    "tpm": {"present": True, "version": "2.0",
            "supported_algorithms": ["SHA-256", "RSA"]},
    "asset_id": "srv-e2e",
}, scan_id="scan-1")
print(result["evidence_verification"]["chain_intact"], len(result["hbom"]["hardware"]))
```

## Building a vendor plugin (§19)

```bash
cp -r sdk_template my_vendor_plugin
# edit manifest.yaml + implement connector.py / discovery.py / normalizer.py
```

```python
from universal_vendor.sdk import load_plugin_package
manifest, plugin = load_plugin_package("my_vendor_plugin")
```

## Running tests

```bash
python -m pytest tests/ -q   # 267 tests (scan framework + live engine + hardware scanner)
```
