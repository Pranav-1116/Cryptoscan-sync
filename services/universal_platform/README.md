# Universal Platform — the ZELNX control plane

Deterministic, **no-AI** control plane that combines **Network + Cloud +
Vendor + Hardware + Cryptography** into one system (the combined
architecture, §1–§33). Every stage is a pure function of evidence and
explicit catalogs; unknown stays unknown.

```
UniversalDiscoveryEngine   §1  discover → identify → correlate → verify → monitor
PlatformEventBus           §18/§19 live events → state → change detection → targeted rescan
DriftEngine                §20  approved baseline vs live (9 categories)
CombinedBomProducer        §21/§22 CycloneDX 1.6 CBOM + HBOM in one document
PlatformRiskEngine         §29  crypto + criticality + exposure + deps + quantum +
                               migration + vendor + hardware → CRITICAL/HIGH/MEDIUM/LOW
BlastRadiusAnalyzer        §30  “what is affected if X changes?” impact queries
PlatformWhatIfEngine       §31  replace algorithm → check deps/libraries/hardware/
                               vendor/cloud → impact → migration plan
SecurityControls           §33  read-only default, scope, exclusions, maintenance
                               windows, emergency stop, secrets never stored
EvidenceChain              §23  SHA-256 chained evidence records
```

The five domain scanners are the existing services: `network_scanner`,
`cloud_scanner`, `universal_vendor` (vendors + hardware incl. HBOM/TPM/HSM)
and `universal_crypto`. The platform consumes their reports, correlates
assets across domains (certificate ↔ load balancer ↔ cloud service,
VM ↔ host ↔ HSM, vendor ↔ product, …), and exposes one API + CLI.

## CLI

```bash
PYTHONPATH="$(ls -d shared/* services/* | tr '\n' ':')"

python -m universal_platform.cli discover request.json --state-out state.json
python -m universal_platform.cli risk --asset hsm-1 --state state.json
python -m universal_platform.cli blast --seed svc.internal --state state.json
python -m universal_platform.cli whatif --current RSA --target ML-KEM-768 --state state.json
python -m universal_platform.cli bom --state state.json
python -m universal_platform.cli drift baseline.json live.json
python -m universal_platform.cli security request.json
python -m universal_platform.cli evidence
```

## API

`/api/v1/platform/*` — `discover`, `bom`, `drift`, `risk`, `blast`,
`whatif`, `security`, `evidence`, `scope` (RBAC `crypto.read` /
`crypto.manage`).

## Tests

```bash
make test   # includes services/universal_platform/tests (20 tests) and
            # services/api/tests/unit/test_platform_api.py (6 tests)
```

See `docs/architecture/combined-architecture.md` for the §1–§33 map.
