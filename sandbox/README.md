# CryptoScan Banking Sandbox ("Meridian Bank")

A **fully fictional** banking estate you can run next to CryptoScan so the
console shows realistic data on first login and the scanners have real TLS
endpoints to talk to. Every identity, account and key here is invented —
this stack must never reach a production network.

## What you get

### 1. Simulated banking estate (Docker)

The estate lives on its own fake bank LAN — the `cryptoscan-sandbox-net`
bridge with the fixed RFC1918 subnet **10.210.0.0/24** — so every system has
a stable IP you can configure as a scan target, exactly like a real estate.
(The CryptoScan API container is joined to this LAN; its scanner reaches the
IPs below. DNS names on `cryptoscan-net` keep working too.)

| IP            | DNS name                       | Port        | Poses as                                    |
| ------------- | ------------------------------ | ----------- | ------------------------------------------- |
| `10.210.0.2`  | `internet-banking.bank.sandbox`| 443 (TLS)   | Internet banking portal — TLS 1.2/1.3, RSA-2048 |
| `10.210.0.3`  | `mobile-api.bank.sandbox`      | 443 (TLS)   | Mobile app backend — TLS 1.2/1.3, RSA-2048  |
| `10.210.0.4`  | `swift-gateway.bank.sandbox`   | 443 (TLS)   | SWIFT/ISO 20022 hub — RSA-3072              |
| `10.210.0.5`  | `legacy-branch.bank.sandbox`   | 443 (TLS)   | **Weak on purpose**: TLS 1.0/1.1 + RSA-1024, expiring soon |
| `10.210.0.6`  | `hsm-sim.bank.sandbox`         | 8443 (TLS)  | payShield-style HSM admin — JSON over TLS   |
| `10.210.0.7`  | `core-banking-db.bank.sandbox` | 5432 (STARTTLS) | PostgreSQL ledger with SSL **on**       |
| `10.210.0.8`  | `payments-bastion.bank.sandbox`| 22 (SSH)    | **Weak on purpose**: sha1 KEX, ssh-rsa, CBC ciphers |
| *(seeds the main Redis)* |                   | 6379        | Session, UPI/SWIFT rate and FX cache keys   |

IPs are consecutive on purpose: a discovery sweep of **`10.210.0.0/29`**
(plus `10.210.0.8/32` for the bastion) touches almost no dead addresses, so
the console wizard finishes well inside its 60-second budget. Never aim the
UI sweep at the whole /24 — every dead address costs a full ARP timeout.

Every certificate carries both its DNS name and its IP as SANs, so scanning
by IP produces clean, realistic cert records — no artificial name mismatches.

### 2. Seeded scan history (one command)

`scripts/seed_sandbox_bank.py` writes, tagged `seed: sandbox-bank`:

- **10 banking systems** with owners, criticality, coverage and PQC-readiness scores
- **143 cryptographic assets** (TLS, signing, storage, PIN/EMV keys — including the weak ones a real audit finds: DES, MD5, TLS 1.0, RSA-1024, one hardcoded key)
- **11 scans** (9 completed, 1 failed, 1 queued) with **hash-chained evidence** using the real pipeline algorithm
- **14 certificates** (valid, expiring-soon with change tickets, expired, self-signed) + endpoint usages
- **6 open drift events** and approved baselines, so drift dashboards show deltas

## Run it

> **Port conflicts:** every host port is an env var (`POSTGRES_PORT`,
> `REDIS_PORT`, `API_PORT`, `FRONTEND_PORT`, `NGINX_PORT`, …). If another
> project holds a default (e.g. 55432), put the override in `.env` —
> **not** as a one-off `VAR=x` prefix, which silently reverts on the next
> command:
>
> ```bash
> echo "POSTGRES_PORT=55433" >> .env
> ```

```bash
# from the repo root — one command brings up the core stack + the estate and
# seeds the DB.
bash sandbox/run_sandbox.sh up        # docker compose stacks the files for you
bash sandbox/run_sandbox.sh status    # container overview
```

Startup is split into two waves: the **data plane** (Postgres, Redis, the fake
estate, and the seeder) runs first. The seeder applies the Alembic migrations
itself, so a slow or broken API can no longer block the sandbox. The **app
plane** (API, worker, frontend, nginx) comes second; if `cryptoscan-api` is
unhealthy you'll see a warning with the exact log command, and the console
will 502 until the API is fixed — but dashboard data is already seeded and
the estate is up.

Seeding runs in a throwaway `python:3.12-slim` container (service
`sandbox-seed`) that installs sqlalchemy/psycopg itself and talks to the
stack's Postgres over `cryptoscan-net` — **no Python deps needed on the
host**. Prefer host Python instead? Install the requirements first, then:

```bash
pip install sqlalchemy 'psycopg[binary]' pydantic
DATABASE_URL="postgresql://cryptoscan:cryptoscan_secret@127.0.0.1:55432/cryptoscan" \
  python scripts/seed_sandbox_bank.py
```

Open the console at http://127.0.0.1:3003 and sign in — CommandCenter / CBOM /
certificates / drift / PQC-readiness are all populated.

Verify a TLS endpoint by hand (from any container on `cryptoscan-net`):

```bash
openssl s_client -connect internet-banking.bank.sandbox:443 -servername internet-banking.bank.sandbox </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
openssl s_client -connect legacy-branch.bank.sandbox:443 -tls1_1 </dev/null     # connects — that's the finding
```

## Run it like a real bank (live scanning)

The seeded data is the bank's *history*. The steps below are the *real
onboarding flow* — you point CryptoScan at IPs and it collects everything
live. This is what a deployment at an actual bank looks like.

**1. Estate scope is declared for you** — a real bank declares its networks
at onboarding; the seeder does the same: `10.210.0.0/24` is written as an
authorized network scope entry and all 7 estate endpoints are registered as
scan targets (visible under **Network → Targets**, and picked up by the due
-scan rotation). Nothing to configure before scanning. If you ever run
`reset`, scope is re-declared on the next `seed`.

**2. Get the target list** — `bash sandbox/run_sandbox.sh targets` prints it,
or copy from the table above.

**3. One-click discovery sweep** — **Scanners** page → select the **Network**
workflow → target **`10.210.0.0/29`** → Run. The wizard sweeps the estate,
TLS-scans every open endpoint it finds, and shows the discovered services
within ~15 seconds. Sweep `10.210.0.8/32` separately to include the bastion.
(Why /29 and not /24: the wizard's request budget is 60 s and every dead
address in a sweep costs a full connect timeout — a real bank's discovery
jobs run scheduled and ranged for the same reason.)

**4. Detect protocols** — **Network** page, endpoint probe box:

```
10.210.0.2:443, 10.210.0.3:443, 10.210.0.4:443,
10.210.0.5:443, 10.210.0.6:8443, 10.210.0.8:22
```

The probe detects what each endpoint actually speaks (TLS vs SSH) before any
scan runs — port is never assumed to equal protocol.

**5. Run the live TLS scan** — every finding, certificate and usage persists
with hash-chained evidence:

```bash
TOKEN=<your API token>
curl -s -X POST http://127.0.0.1:8010/api/v1/network-scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"hosts":["10.210.0.2:443","10.210.0.3:443","10.210.0.4:443",
                 "10.210.0.5:443","10.210.0.6:8443"],
       "scan_versions":true,"scan_ciphers":true,"check_chain_sent":true}'
```

Expect: strong TLS 1.2/1.3 on .2–.4; **TLS 1.0/1.1 + RSA-1024 + near-expiry
findings on .5** — the scanner catching the legacy branch, live.

**6. Scan the database and the bastion:**

```bash
# PostgreSQL STARTTLS (port 5432 → sslmode handshake → server cert)
curl -s -X POST http://127.0.0.1:8010/api/v1/network-scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"hosts":["10.210.0.7:5432"],"starttls":"postgresql"}'

# SSH key-exchange + host-key posture of the legacy jump host
curl -s -X POST http://127.0.0.1:8010/api/v1/network/ssh-scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"hosts":["10.210.0.8:22"],"include_kex":true,"strict_kex":true}'
```

**7. Watch the BOMs fill with collected (not seeded) data** — open
**Certificates** (the estate's real certs, incl. the RSA-1024 one),
**CBOM** and **NBOM** workspaces, then run the TLS scan a second time and
check **Drift** for scan-to-scan deltas. The six BOM workspaces
(SBOM · CBOM · HBOM · NBOM · VBOM · TechBOM) reconcile the seeded software/
hardware/vendor inventory with what the network scans just observed.

> The sweep gate fail-closes on anything outside authorized scope — with
> `10.210.0.0/24` declared, every estate IP passes; a target outside that
> range is refused with a scope violation, same as in the bank.

## The living bank — how the whole thing works

A real CryptoScan deployment at a bank has three moving parts, and the
sandbox reproduces all three:

```
   REAL BANK                                    SANDBOX
┌────────────────────────┐                  ┌──────────────────────────────┐
│ servers, HSMs, DBs,    │  scan targets    │ estate containers on         │
│ apps, vendors          │ ◄─────────────── │ 10.210.0.0/24 (nginx TLS,    │
└─────────┬──────────────┘                  │ postgres+SSL, OpenSSH, HSM)  │
          │ agents/observers               └──────────┬───────────────────┘
          ▼                                           ▼
┌────────────────────────┐   POST ingestion/    ┌──────────────────────────┐
│ bank collectors/agents │ ──observations────► │ sandbox-collect (the     │
└────────────────────────┘                     │ "bank agent")            │
                                               └──────────┬───────────────┘
┌─────────────────────────────────────────────────────────▼───────────────┐
│ CryptoScan: evidence store → hash chain → graph → 6 BOM projections     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Data lineage per BOM** — every workspace reads from collected rows, and
each row arrives through the channel a real bank would use:

| BOM | Content | Sandbox channel |
| --- | --- | --- |
| NBOM | endpoints, protocols, posture | live network scans (you trigger) |
| CBOM | ciphers, TLS versions, certificates, HSM key slots | live TLS/SSH scans + collector handshakes |
| SBOM | packages & versions per system | collector reads the REAL package DB inside each estate container (apk/pip) |
| HBOM | hosts, devices, firmware | collector: docker inspection + HSM banner |
| VBOM | vendors & observed product versions | collector derives from observed banners/packages |
| TechBOM | the unified projection | re-materialized by the platform from all of the above |

**The dynamic loop:**

```bash
bash sandbox/run_sandbox.sh collect     # one live pass: docker + TLS + SSH + DB + HSM
```

**Driving each BOM from the console (no terminal):**

| BOM | UI action | Where the data comes from |
| --- | --- | --- |
| **NBOM** | Scanners → Network workflow → sweep `10.210.0.0/29` (+ `10.210.0.8/32`) | live port/protocol discovery |
| **CBOM** | CBOM workspace → **Live network collection** panel → enter `host:port` targets → Run live scan | real TLS handshakes; certs/usages persist into the workspace tabs |
| **SBOM** | agent-fed: `bash sandbox/run_sandbox.sh agent` once, then the workspace updates on every pass | real apk/pip package DBs read inside each estate container |
| **HBOM** | same agent feed; HBOM workspace → "Pin estate HBOM" to freeze a version | docker inspection + the HSM's real banner (firmware, key slots) |
| **VBOM** | same agent feed | vendors derived from observed product versions |
| **TechBOM** | TechBOM workspace → "Capture snapshot" after any scan/collect | platform re-projection over all of the above |

Agent mode is the real-bank cadence: put `CRYPTOSCAN_USERNAME` /
`CRYPTOSCAN_PASSWORD` (your console login) in `.env`, run
`bash sandbox/run_sandbox.sh agent` once, and the collector re-observes the
estate every 5 minutes — change the estate and the BOMs follow on their own.

Each `collect` run pushes one observation to `POST /api/v1/ingestion/observations`.
The platform stores it **only if something changed** (content fingerprint),
and the BOM workspaces re-project from the newest observation — so edit the
estate (upgrade a package, change a cert, stop a container), run `collect`
again, and watch the BOMs and drift views move. That is exactly the cadence
of a real deployment: agents observe, the platform projects, drift appears
when reality moves.

The seeded history (scan back-story, baselines, drift) remains as the bank's
past quarter; scans and `collect` runs are the living present.

### Cryptava agents — one agent on every bank server

The `collect` pass looks at the estate from outside. Cryptava is the agent a real
bank installs **on each server**: it reads that machine from the inside and sends
one signed observation per server. In the sandbox **all seven bank servers get an
agent, automatically**: `bash sandbox/run_sandbox.sh up` starts them as soon as the
API is healthy, waits for their first signed reports and prints a check:

```
BANK SERVER        AGENT
internet-banking   CONNECTED  mrdn-sbx-dc1-ibank01 -> http://api:8010 · last report … · signature verified · HBOM:complete SBOM:complete …
mobile-api         CONNECTED  mrdn-sbx-dc1-mobileapi01 -> …
…
```

The agents enrol once with your console login — put it in `.env`
(`CRYPTOSCAN_USERNAME=admin`, `CRYPTOSCAN_PASSWORD=...`) or type it when asked.
`SANDBOX_AGENTS=0 bash sandbox/run_sandbox.sh up` skips them.

```bash
bash sandbox/run_sandbox.sh agents          # connect every bank server (if `up` did not, or after `agents stop`)
bash sandbox/run_sandbox.sh agents check    # one line per bank server: connected? last report? six BOM results
bash sandbox/run_sandbox.sh agents stop     # stop them (enrolment is kept)
```

| Agent name | Bank server | Business system |
| --- | --- | --- |
| `mrdn-sbx-dc1-ibank01` | internet-banking (10.210.0.2) | Internet Banking |
| `mrdn-sbx-dc1-mobileapi01` | mobile-api (10.210.0.3) | Mobile Banking API |
| `mrdn-sbx-dc1-swiftgw01` | swift-gateway (10.210.0.4) | SWIFT Gateway |
| `mrdn-sbx-br0142-legacy01` | legacy-branch (10.210.0.5) | Branch Banking |
| `mrdn-sbx-dc1-hsmsim01` | hsm-sim (10.210.0.6) | Payment HSM |
| `mrdn-sbx-dc1-coredb01` | core-banking-db (10.210.0.7) | Core Banking |
| `mrdn-sbx-dc1-paybastion01` | payments-bastion (10.210.0.8) | SWIFT Gateway |

How an agent is "connected" to its bank server: it runs beside the server and
shares the server's **processes and network**, and reads the server's **files**
through `/proc/1/root` — exactly the view an agent installed on the machine has. It
reaches the console at `http://api:8010` over the bank LAN, signs every report with
its own key, sends a heartbeat every minute and a full report every 5 minutes.

Open **Discovery → Cryptava agents** in the console: each agent shows as `online`,
with its six BOM results and `verified` once its signed report is checked. Click an
agent for the reason behind each result, **how each BOM was collected** (every
source it read and what came back), and links to the BOM workspaces. Their findings
are added next to the `collect` pass and never overwrite it. See
`services/cryptava/README.md` for what each BOM contains and how to install the
agent on a real server.

#### Live performance of the bank servers

Each agent also sends a signed **performance sample every minute** for its server:

* CPU, memory, disk and network;
* process health;
* how long a TLS handshake with the server takes;
* for `hsm-sim`, the HSM's response time on `:8443`.

Open **Performance → Live Systems (Cryptava agents)** in the console. You get one card
per bank server:

* `LIVE`, `STALE` or `NO SAMPLES YET`;
* the newest figures with a short trend;
* the TLS version and cipher each listener negotiated;
* every figure the agent could not read, with the reason, never as a zero.

The same servers are listed at the top of **Performance Overview**. The page refreshes
every 15 s.

The agents run beside their servers, so they measure the **server's own processes**
(`workload` scope). They do not measure the Docker host. `agents check` shows each
agent's last delivery (`· live metrics 17 sent …`). To look at one sample:

```bash
docker exec cryptoscan-cryptava-swift-gateway sh -c 'PYTHONPATH=/opt/cryptava python3 -m cryptava perf --print'
```

If a server shows anything other than `CONNECTED`:

| Check says | Do this |
| --- | --- |
| `NO AGENT` | `bash sandbox/run_sandbox.sh agents` |
| `NOT ENROLLED` | the console login was missing/wrong — fix `.env`, then `docker restart cryptoscan-cryptava-<server>` |
| `NOT DELIVERED … cannot reach` | the API is down — `docker logs cryptoscan-api --tail 80`; the agent retries by itself |
| `AGENT exited` | `docker logs cryptoscan-cryptava-<server>` |

#### Connect a bank server from the console (the real enrolment flow)

To do it the way an operator adds a new server — with a name and a one-time token
from the console — pick any bank server; your agent **replaces** its built-in one:

1. Console → **Discovery → Cryptava agents → Add a server**.
2. Type a unique name, e.g. `mrdn-sbx-dc1-mobileapi02`, and click **enrol**.
   The console shows the agent id and a one-time token.
3. Choose **Sandbox bank server**, pick the server (`mobile-api`), click **copy**.
4. Paste the command in a terminal in the repository folder:

   ```bash
   bash sandbox/run_sandbox.sh agents add mobile-api <agent-id> <token>
   ```

   The built-in agent on that server is removed (retire its old name in the
   console), your agent enrols with the token, and its first signed report shows on
   the page within a minute. Later `up` / `agents` runs leave that server's agent alone.

```bash
bash sandbox/run_sandbox.sh agents list              # every agent container and its state
bash sandbox/run_sandbox.sh agents remove mobile-api # stop + delete it; `agents` then puts the built-in one back
```

A token works once and expires. If enrolment fails, open the agent in the
console → **new token**, run `agents remove <host>`, then `agents add` again.

#### Why HBOM and VBOM are complete here

A container cannot read firmware tables, and contracts are never on a server.
Like a real bank, each sandbox server has a **CMDB record** —
`sandbox/cryptava/<host>.json` — mounted into its agent at
`/etc/cryptava/asset-record.json`:

* **HBOM** takes the platform identity (manufacturer, model, serial, asset tag,
  rack, warranty) from it, marked as *imported from the asset register*, never as
  observed. `core-banking-db` and `swift-gateway` are physical Dell/HPE servers,
  `legacy-branch` is an HPE Gen9 **past its warranty**, the rest are VMware VMs.
* **VBOM** matches its contracts to the vendors the agent found. Each vendor gets a
  contract state: `active`, `expiring soon` (core-db's OpenSSL support ends
  2026-12-31), `expired` (legacy-branch's HPE contract), `community` (Alpine) or
  `internal` (the bank's own CA). A vendor with no contract is flagged as a
  finding — `no contract on record` — it does not make the BOM partial.

Edit a record and the next report (≤ 5 minutes) reflects it. Remove the mount and
HBOM/VBOM go back to `partial`, saying exactly what is missing.

## Dependencies — crypto map and cascade (Twin & dependencies)

The seed also records the bank's dependency register, so both dependency
views have complete, attributable data:

| What | Where it comes from | Where to see it |
|---|---|---|
| system → software component → library → algorithm | each `crypto_assets` row, its owning-system link (`system_assets`) and its recorded library | **Twin & dependencies → Graph explorer** (full map + "which software uses each algorithm" table with file:line) |
| live TLS endpoints → system | scan target ownership (`10.210.0.2:443` → Internet Banking, `.3` Mobile, `.4` SWIFT, `.5` Legacy Branch, `.6` Payment HSM, `.7` Core Ledger, `.8` Bastion) | the same map, as `LIVE` components — every new CBOM/Network scan links itself |
| system → system (consumer → provider) | 20 declared architecture edges (e.g. ATM → Card Management → Payment HSM), provenance DECLARED with the interface as evidence | **Twin & dependencies → Cascade** (diagram + "who depends on whom" table) |
| cascade simulation | walks only ACTIVE `CALLS` / `DEPENDS_ON` / `IMPORTS` edges | **Cascade** → tick systems and/or algorithms → *Simulate cascade* |

Databases seeded before this existed pick it up with a plain, non-destructive
re-seed (it only adds links, never deletes):

```bash
./sandbox/run_sandbox.sh seed
```

## Tear down and clean up

```bash
bash sandbox/run_sandbox.sh down      # removes ONLY the sandbox containers +
                                      # sandbox_certs volume; the main
                                      # CryptoScan stack and its data volumes
                                      # (postgres_data, redis_data, …) are
                                      # never touched — do NOT run
                                      # `docker compose … down -v` with both
                                      # compose files or you will wipe the
                                      # main database volume too.

bash sandbox/run_sandbox.sh reset     # delete only the sandbox-seeded rows,
                                      # then reseed (runs inside Docker)
```

## Notes

- **Migrations first**: the Postgres schema is created by Alembic (the seed
  container runs `upgrade head` before seeding). If the API fails to start
  with `Database migration status is missing (applied: [])`, run
  `bash sandbox/run_sandbox.sh migrate` and restart the API. If a stale
  seeder version created tables *without* migration bookkeeping (the schema
  then blocks `upgrade head`), run `bash sandbox/run_sandbox.sh db-rebuild`
  once — it drops only the CryptoScan `public` schema and rebuilds it.
- Reseeding is idempotent: a second run detects the marker row and exits.
- SQLite also works for a quick local demo: the script defaults to
  `sqlite:///./data/cryptoscan.db` (create schema via the app's normal startup first).
- The legacy endpoint's weak TLS is intentional — never reuse those configs.
