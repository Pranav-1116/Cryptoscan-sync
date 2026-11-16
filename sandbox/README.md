# CryptoScan Banking Sandbox ("Meridian Bank")

A **fully fictional** banking estate you can run next to CryptoScan so the
console shows realistic data on first login and the scanners have real TLS
endpoints to talk to. Every identity, account and key here is invented —
this stack must never reach a production network.

## What you get

### 1. Simulated banking estate (Docker)

| Container / DNS name             | Port in-net | Poses as                                    |
| -------------------------------- | ----------- | ------------------------------------------- |
| `internet-banking.bank.sandbox`  | 443 (TLS)   | Internet banking portal — TLS 1.2/1.3, RSA-2048 |
| `mobile-api.bank.sandbox`        | 443 (TLS)   | Mobile app backend — TLS 1.2/1.3, RSA-2048  |
| `swift-gateway.bank.sandbox`     | 443 (TLS)   | SWIFT/ISO 20022 hub — RSA-3072              |
| `legacy-branch.bank.sandbox`     | 443 (TLS)   | **Weak on purpose**: TLS 1.0/1.1 + RSA-1024, expiring soon |
| `hsm-sim.bank.sandbox`           | 8443 (TLS)  | payShield-style HSM admin — JSON over TLS   |
| `core-banking-db.bank.sandbox`   | 5432        | PostgreSQL ledger with customers/accounts/cards |
| *(seeds the main Redis)*         | 6379        | Session, UPI/SWIFT rate and FX cache keys   |

### 2. Seeded scan history (one command)

`scripts/seed_sandbox_bank.py` writes, tagged `seed: sandbox-bank`:

- **10 banking systems** with owners, criticality, coverage and PQC-readiness scores
- **143 cryptographic assets** (TLS, signing, storage, PIN/EMV keys — including the weak ones a real audit finds: DES, MD5, TLS 1.0, RSA-1024, one hardcoded key)
- **11 scans** (9 completed, 1 failed, 1 queued) with **hash-chained evidence** using the real pipeline algorithm
- **14 certificates** (valid, expiring-soon with change tickets, expired, self-signed) + endpoint usages
- **6 open drift events** and approved baselines, so drift dashboards show deltas

## Run it

```bash
# from the repo root — one command brings up the core stack + the estate and
# seeds the DB.
bash sandbox/run_sandbox.sh up        # docker compose stacks the files for you
bash sandbox/run_sandbox.sh status    # container overview
```

Startup is split into two waves: the **data plane** (Postgres, Redis, the fake
estate, and the seeder) runs first. The seeder creates the schema itself if
the database is empty, so a slow or broken API can no longer block the
sandbox. The **app plane** (API, worker, frontend, nginx) comes second; if
`cryptoscan-api` is unhealthy you'll see a warning with the exact log command,
and the console will 502 until the API is fixed — but dashboards data is
already seeded and the estate is up.

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

Then run a network scan from the console targeting e.g.
`internet-banking.bank.sandbox`, `mobile-api.bank.sandbox`,
`swift-gateway.bank.sandbox`, `legacy-branch.bank.sandbox`,
`hsm-sim.bank.sandbox:8443` to compare live evidence with the seeded history.

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
