# Synthetic banking estate laboratory

This is an **additive engineering sandbox, not a production scanner replacement**. It generates a varied, linked banking estate and exercises existing CryptoScan code against selected inputs. It never contacts the addresses in its inventory. It does not turn configuration, packages or vendor assertions into observed crypto.

## Quick start (repository root)

Use the repository Python environment with `cryptography`, `jsonschema`, `referencing` and the normal scanner's dependencies installed. Tests additionally use `pytest`; the VM builder needs the documented native toolchain and pinned assets. Generation, validation and static collection need no downloads once these dependencies are present.

```bash
# Start small. Output must not already exist; do not place estates in Git.
.venv/bin/python generate_sandbox.py --banks 1 --profile minimal \
  --output /home/user/.cache/my-bank-lab
.venv/bin/python -m tools.banking_sandbox.cli validate \
  --root /home/user/.cache/my-bank-lab --full-schemas
.venv/bin/python -m tools.banking_sandbox.cli scan \
  --root /home/user/.cache/my-bank-lab --output /home/user/.cache/my-bank-results
.venv/bin/python -m tools.banking_sandbox.cli serve \
  --root /home/user/.cache/my-bank-lab --host 0.0.0.0 --port 8080
```

The static run calls **`scanner.registry.language_scanners.scan_file`**, not a lab detector. It stages only source, never executes source snippets, records its source hash, and denies sockets and oracle reads. Linux x86_64 with Landlock ABI ≥2 and stackable seccomp is required; no privileged fallback is attempted. One staged run per estate; generate a fresh estate for another run. A collector failure returns nonzero and is not a successful no-crypto result.

```bash
.venv/bin/python generate_sandbox.py --banks 150 --scale large \
  --crypto-complexity high --network-complexity high --vendor-complexity high \
  --pqc true --legacy true --conflicts true --drift true \
  --output /home/user/.cache/banking-150-large
```

Default system budget is 50,000. A 150-bank `large` run may exceed it; inspect the refusal and choose a bounded, explicitly approved budget with `--max-systems` (hard maximum 200,000), or use `mixed`. Generation refuses before creating output when the computed system total exceeds the budget. Bank count supports 1–2,000, including the requested 1/10/50/100/150/200; **200 has not been load-benchmarked**. Scale bounds are small 10–30, medium 30–100, large 100–500, mega 500–700; mixed is 10–500. `minimal` fixes ten systems and named size profiles override scale. Every system has two apps, each with six component records and two endpoints/certificates. Deliberate missing-source/runtime/SBOM cases change visibility, not ownership.

Profiles: minimal, small-bank, medium-bank, large-bank, global-bank, legacy-bank, cloud-bank, crypto-heavy-bank, pqc-bank, worst-case-bank, chaos-bank. Twenty archetypes rotate under the mixed/worst-case portfolio; some profiles select a dedicated archetype. Named profiles are portfolio/size selectors, **not fifteen independently implemented runtime products**. Complexity changes source/algorithm pools, network-zone pools and vendor-category counts (6/14/23). Feature flags control the associated synthetic declarations; they are not universal filtering of every adverse static scenario. The same seed/options/epoch reproduce public fixture bytes and manifest; elapsed-time metrics intentionally differ.

## Layout and data handling

```
estate/
  LAB.json                 # label, options, simulated clock and access policy
  manifest.json            # exact public-file hashes and sizes
  generation-metrics.json  # fixture counts/storage/time, not discovery metrics
  public/                  # only this subtree may be served
    banks organizations assets systems applications source
    sbom cbom hbom vbom nbom techbom certificates pki hsm kms
    network containers kubernetes cloud vendors runtime fixtures
    scenarios drift pqc schemas docker compose docs
    catalog.json index.html
  control/                 # mode 0700, never served or staged
    ground_truth/ expected_results/
  scanner-inputs/          # source-only staging created by scan
```

Generator, validator, schemas, Docker recipes and documentation live in `tools/banking_sandbox/`, not copied executable tooling inside every generated estate. Truth is deliberately under a separate `control` subtree rather than alongside scanner-visible inputs. The dashboard is a fixture explorer: Bank → DC → Zone → System → Application → Component and declared crypto/evidence. It is not a normal CryptoScan results dashboard. No cloud/Kubernetes apply command is emitted; exports explicitly disallow application. OCI layers are real, deterministic **inert layouts**, not running bank images.

All institutions, hardware-equivalent identities, vendors and addresses are synthetic. Names end in `.invalid`; documentation-range addresses are labels only. Never substitute production networks, credentials, customer data or real bank exports. Only pinned public RSA SPKIs and public certificates persist. Fixture CA/public-key derivation is synthetic, not a secure PKI or a recommended key-generation practice. The live guest creates disposable private keys only inside its RAM filesystem; they are not exported.

See [architecture and evidence](architecture.md), [scenarios and coverage](coverage.md), [operator exercises](operations.md), and the [measured readiness record](../../../docs/readiness-evidence/banking-sandbox-2026-10-26.md).
