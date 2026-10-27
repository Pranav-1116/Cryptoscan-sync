# PoC operator checklist — two weeks, fixed scope

Companion to `docs/proposals/fab-poc.md`. Every box maps to a real platform
surface; nothing on this list requires code changes — configuration and
operation only. Read `docs/enterprise-readiness.md` first for the honest
capability matrix.

## Before day 1 — pre-engagement

- [ ] Scope sheet agreed and SIGNED: network ranges/CIDRs, cloud accounts
      (read-only roles only), whether the telecom module is in scope.
- [ ] Read-only cloud role created by the bank:
      AWS `kms:List*`, `kms:Describe*`, `acm:List*`, `acm:Get*`,
      Azure Key Vault **Reader**, GCP `cloudkms.keyRings.list`,
      `cloudkms.cryptoKeys.list` (+ `get`). No write permissions. Ever.
- [ ] A jump host / workstation inside the bank network with Docker.
- [ ] Named crypto owner on the bank side (success-criteria sign-off).

## Day 1 — bring-up (half a day)

- [ ] `cp deploy/poc/poc.env.example deploy/poc/poc.env` — fill `SECRET_KEY`
      (`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`) and
      a non-default `ADMIN_PASSWORD`.
- [ ] `docker compose -f deploy/poc/docker-compose.poc.yml --env-file deploy/poc/poc.env up -d --build`
- [ ] `bash scripts/smoke_test.sh` → healthz/readyz/metrics all 200.
- [ ] Sign in, **change the admin password**, create named accounts per
      person (superadmin for the operator, `auditor` for the bank's audit
      witness — the audit export pack is auditor-readable by design).
- [ ] Optional but recommended: point `OIDC_ISSUER`/`OIDC_CLIENT_ID` at the
      bank's IdP and watch the login screen grow the SSO button.

## Days 2–4 — network discovery

- [ ] Register scope via onboarding (read-only TLS/cert probing — no agents,
      no credentials harvested).
- [ ] Run the bounded scans; review verdicts in the dashboard
      (TLS_OK / NO_TLS / UNREACHABLE / …, each with severity + references).
- [ ] Record the skipped/unreachable list with reasons — the PoC report
      needs the honest gap list, not just the hits.

## Days 3–6 — cloud keys and certificates

- [ ] `POST /api/v1/inventory/cloud/collect` per provider/region
      (`dry_run: true` first, review, then persist).
      Providers: `aws-kms`, `azure-keyvault`, `gcp-kms`, `aws-acm`.
- [ ] Check the skipped list: every unknown key type is named with its
      reason — quote it verbatim in the report (it proves nothing was guessed).
- [ ] ACM certificates should already surface in expiry/renewal surfaces —
      confirm the renewal queue shows cloud-issued certs.

## Days 5–8 — analysis

- [ ] CBOM review with the bank's crypto owner (families, Shor-exposure,
      Grover-relevance).
- [ ] Generate the migration roadmap (NIST IR 8547 buckets) — this is the
      board-ready artifact.
- [ ] If telecom in scope: register NF targets, run scans, review the
      roaming matrix incl. `pqc_ready`
      (`docs/runbooks/telecom-operations.md`).
- [ ] Optional: wire one automation rule → ServiceNow/Jira/Sentinel and
      dispatch one real run (ITSM integration is config, not code).

## Days 8–10 — evidence and exit

- [ ] `GET /api/v1/audit-export/pack` (as the `auditor` account) — one ZIP:
      payment keys, certificates, cloud KMS inventory, ACM certs, code
      findings summary, telecom posture, compliance report, chain
      verification, and a SHA-256 `manifest.json` covering every file.
- [ ] Have the bank's audit witness verify the manifest independently
      (any `sha256sum -c`-style check on the extracted files).
- [ ] Exit report = pack + roadmap + the honest skipped/gap list + the
      commercial path section of `fab-poc.md`.

## End of engagement — data handling

- [ ] Export anything the bank keeps (the pack), then:
      `docker compose -f deploy/poc/docker-compose.poc.yml down -v`
      The `poc_data` volume holds the only state — destroying it destroys
      every finding. Nothing ever left the tenancy.

## Air gap

If the PoC environment has no outbound internet: build the images on a
connected machine, `docker save` them, and follow
`docs/admin-guide/air-gap-install.md`. All SSO/verification paths support
file-based JWKS (`OIDC_JWKS_FILE`).

## Optional: continuous monitoring (after the core weeks)

The PoC stack can add the 24/7 monitor daemon without changing the
two-container footprint (it is compose-profile gated):

```bash
docker compose -f deploy/poc/docker-compose.poc.yml --env-file poc.env \
  --profile continuous up -d --build monitor
```

Register targets as during the weeks (NETWORK endpoints, or
`target_type: "TELECOM"` for the registered 5GC/roaming estate) — the daemon
re-probes on interval and the API serves every pass live (shared snapshot
volume). SSE clients see verdict changes without any manual scan.
