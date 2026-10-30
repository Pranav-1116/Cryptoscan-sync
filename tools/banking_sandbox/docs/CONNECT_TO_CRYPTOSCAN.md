# Connecting the synthetic bank to CryptoScan

Two products, run separately, joined by one bridge that goes **through CryptoScan's
HTTP backend**. Nothing here writes to CryptoScan's database, imports its Python
modules, or reads the bank's operator-only `control/` subtree.

| | what it is | how it runs |
|---|---|---|
| **Product 1 — the bank** | a generated synthetic bank (`bank-0001`): systems, applications, endpoints, certificates, HSMs, packages, vendors, declared SBOM/CBOM documents | `tools/banking_sandbox` (`generate_sandbox.py`, `cli connect`, `cli serve`) |
| **Product 2 — CryptoScan** | the scanning/evidence platform, its API and console | `scripts/run_dev_stack.sh up` (API `:8010`, console `:3003`) |

The bank is an **institution**, not an environment: the observation it posts is named
after the bank (`estate: bank-0001`, scope `SYNTHETIC Zelnx Institution 0001 —
synthetic bank sandbox`), and it lands in the estate/BOM views as that bank's estate.

---

## 1. Run product 1 (the bank)

```bash
cd /home/user/CryproScan

# generate a fresh estate (the bank's own documents)
.venv/bin/python generate_sandbox.py --banks 1 --profile minimal --output /home/user/.cache/bank-lab

# validate it against the schemas it ships
.venv/bin/python -m tools.banking_sandbox.cli validate --root /home/user/.cache/bank-lab --full-schemas

# the sandbox's own collector pass: static scan + load-balancer config scan,
# producing its six BOMs, validation report and fixture dashboard
PYTHONPATH="$PYTHONPATH:services/cbom:shared/shared_models" \
  .venv/bin/python -m tools.banking_sandbox.cli connect \
  --estate /home/user/.cache/bank-lab --output /home/user/.cache/bank-lab-connected

# serve the bank's read-only public fixtures (its own dashboard, its own port)
.venv/bin/python -m tools.banking_sandbox.cli serve --root /home/user/.cache/bank-lab --host 0.0.0.0 --port 8080
```

`cli connect` refuses to run without its isolation receipt (Landlock ABI ≥ 2,
`socket_creation_denied`, `seccomp == ACTIVE_NETWORK_DENIED`) and demands a non-existent
output directory, so a second run always means a fresh estate.

Measured on the `--profile minimal` estate: 1 bank / 10 systems / 20 applications /
120 components / 64 SBOM documents / 20 CBOM documents / 40 certificates / 10 load
balancers / 23 vendors / 5 HSMs / 20 KMS keys / 3 pass-through buckets
(`boms/summary.json`: SBOM 20 components, CBOM 16, HBOM 20, VBOM 23, NBOM 81, LB-NBOM 30).

## 2. Run product 2 (CryptoScan)

```bash
bash scripts/run_dev_stack.sh up     # API :8010, console :3003
bash scripts/run_dev_stack.sh status # /ready + console proxy check
```

Point `CRYPTOSCAN_SOURCE_ROOTS` at the estate if you want the console's scan triggers to
be allowed to read it:

```bash
CRYPTOSCAN_SOURCE_ROOTS="$PWD:/home/user/.cache/bank-lab" bash scripts/run_dev_stack.sh up
```

## 3. Connect them (through the backend)

```bash
PW=$(grep ADMIN_PASSWORD data/run/dev-stack.env | cut -d= -f2-)
ADMIN_PASSWORD="$PW" .venv/bin/python scripts/connect_bank_sandbox.py \
  --estate /home/user/.cache/bank-lab --api http://127.0.0.1:8010
```

The bridge makes three calls, all existing doors, and prints what CryptoScan read back:

1. **`POST /api/v1/scans/trigger`** — `local://<estate>/public/source`. The bank's source
   tree is scanned by the real static pipeline, so the crypto findings and cascade in the
   console are things CryptoScan *observed in the bank's code*.
2. **`POST /api/v1/cbom/ingest`** — the bank's declared CBOM documents. CryptoScan stores
   them as `IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS`: a vendor's declaration is
   inventory, never an observation.
3. **`POST /api/v1/ingestion/observations`** — one estate observation built from the
   bank's own inventory documents (systems, applications, endpoints, certificates,
   hardware, HSMs, packages, libraries, vendors, SBOM dependency graph). CryptoScan
   stores it as a discovery run and projects the six BOMs from it.

Re-posting the same estate returns `NO_CHANGE` with the same `projection_id` — the state
hash is content-addressed, so an unchanged bank is not re-stored.

### What the bridge sends, and how honestly

| bank fact | sent as | never sent as |
|---|---|---|
| system / application / endpoint inventory | `IMPORTED` evidence | a scan result |
| endpoint protocol (`TLS1.2`, `mtls`) | `CONFIGURED` (the bank records `actual_negotiation_executed: false`) | `NEGOTIATED` |
| certificates (serial, sha256, validity) | `IMPORTED` certificate metadata | a live handshake |
| HSM operations list | `CONFIGURED` with `actual_execution: false` carried in the facts | `OBSERVED` |
| hardware capabilities | `VENDOR_DECLARED` / capability (`SUPPORTED`) | usage |
| packages, libraries, dependency edges | `IMPORTED`, `depends_on`/`contains` | "loaded" or "invoked" |
| vendors, declared CBOM algorithms | `VENDOR_DECLARED` | estate usage |
| source code | the real static scan (`POST /scans/trigger`) | — |

Unresolved relationships in the delivered observation: **0** (an edge without a basis or
evidence is refused by the estate engine, not silently kept).

## 4. Where to look in the console (`:3003`)

| view | what it shows for the bank |
|---|---|
| **BOMs → CBOM** | 199 components, 159 observed crypto artifacts from the bank's source scan + 40 certificates; usage states split `SUPPORTED 119 / CONFIGURED 40 / OBSERVED 0` |
| **BOMs → SBOM** | 54 components (17 libraries, 17 packages, 20 images), **220 dependency edges** (100 `contains`, 100 `depends_on`, 20 `deployed_as`) — and the estate-observation strip naming which rows came from the bank's documents |
| **BOMs → HBOM** | 15 devices (10 hardware + 5 HSMs), each row tagged *imported* when it came from the bank's config export rather than an agent; document `metadata.sources` names both sources |
| **BOMs → NBOM** | 40 endpoints, all `CONFIGURED` — the bank executed no handshake |
| **BOMs → VBOM** | 23 declared vendors (declared capability, `LIFECYCLE`/`PQC` fields as the bank declared them) |
| **BOMs → Technology BOM** | 199 components across four layers (`sbom 33 · cbom 128 · hbom 15 · vendor 23`) plus 220 dependency edges |
| **`/collector-depth` → Six BOMs** | the six projections of one evidence graph, `all_boms_share_snapshot: true`, projection `aeb0a45d…` |
| **CBOM coverage** | 23 systems, 2 with a CBOM, 21 `NO_TARGET` → 8.7 % — the scan reached the bank's source, not its runtime |
| **Scans** | the bank's source scan (`local://…/public/source`): 17 files, 19 findings, 10 libraries, 1 used-but-undeclared, 0 package dependencies (the estate's source tree declares none) |

## 5. What the connection does *not* prove

* Coverage is **per surface and measured**: 8.7 % CBOM coverage is the honest number, and
  21 systems stay `NO_TARGET` until something scans them.
* Declared ≠ observed everywhere: 119 of the bank's CBOM artifacts are capability
  (`SUPPORTED`), 40 are configured certificates, and **none** is an executed operation.
* The bank records `actual_negotiation_executed: false` and
  `actual_execution: false`; the console shows those as configured, not negotiated.
* Static findings prove the algorithm is **present in code**, not that it ran.
* A duplicate run is `NO_CHANGE`, not a second estate. The bridge reports which happened.
