# ZELNX Universal Vendor Scanner

Vendor-neutral crypto + crypto-configuration discovery across every vendor
category, per the ZELNX Universal Vendor Scanner spec (§1–§24).

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
| `tests/` | — | 114 tests covering every component |

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
python -m pytest tests/ -q   # 114 tests
```
