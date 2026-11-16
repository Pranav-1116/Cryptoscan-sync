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
# from the repo root

# 1. start CryptoScan core + the banking estate
docker compose -f docker-compose.yml -f sandbox/docker-compose.sandbox.yml up -d

# 2. check the estate answered
docker logs cryptoscan-sbx-certgen            # certificates generated
curl -k https://$(docker compose port ...)    # optional

# 3. seed the dashboards (points at the stack's Postgres by default)
DATABASE_URL="postgresql://cryptoscan:cryptoscan_secret@127.0.0.1:55432/cryptoscan" \
  python scripts/seed_sandbox_bank.py

# 4. open the console and sign in — CommandCenter / CBOM / certificates /
#    drift / PQC-readiness are all populated.
```

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
docker compose -f docker-compose.yml -f sandbox/docker-compose.sandbox.yml down -v

# remove the seeded rows only (leaves everything else untouched)
DATABASE_URL="postgresql://cryptoscan:cryptoscan_secret@127.0.0.1:55432/cryptoscan" \
  python scripts/seed_sandbox_bank.py --reset
```

## Notes

- Reseeding is idempotent: a second run detects the marker row and exits.
- SQLite also works for a quick local demo: the script defaults to
  `sqlite:///./data/cryptoscan.db` (create schema via the app's normal startup first).
- The legacy endpoint's weak TLS is intentional — never reuse those configs.
