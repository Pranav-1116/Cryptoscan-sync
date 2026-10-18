# 05 — Practical walkthrough: a bank payments pilot

[Guide index](README.md) · Previous: [Six BOMs](04-six-boms.md) ·
Next: [UI and exports](06-console-apis-and-exports.md)

**Every name, address, revision and outcome below is illustrative.** Requests
show implemented shapes, not a performed bank scan. Replace example targets
only after written authorization. Never execute a bank scan from an unapproved
workstation or copy illustrative observations into a real bank inventory.

## 1. Agree a small, useful estate

Consider the fictional **Example Bank** and this UAT pilot:

| Item | Approved pilot input | Question |
|---|---|---|
| Payments API | One read-only release source export | Where are signing, encryption and hashing used? |
| Partner gateway | One explicitly authorized TLS listener | What transport/certificate is actually served? |
| Payment HSM | Approved metadata observation from its owner | Which model/firmware/security posture is inventoried? |
| Payment supplier | One vendor record, supported crypto declaration and evidence | What is declared, linked and still unverified? |
| Optional cloud slice | One approved account/region and role | What permitted cloud crypto metadata can the collector actually read? |

Owners approve the scope/window and excluded systems. The network team permits
only the selected executor-to-target flow. The platform team completes HTTPS,
authentication, PostgreSQL, migrations and isolated-parser provisioning. Nothing
here requires scanning a production card switch, extracting HSM secrets, or
submitting customer records.

## 2. Prepare a restricted operator working directory and authentication

Use an approved scratch/evidence directory **outside the source checkout**.
Exported artifacts can disclose internal paths, identities and topology; do not
commit them to Git or place them in public support tickets.

Log in using the bank-approved UI/OIDC/MFA or machine-credential procedure.
Examples below assume a short-lived valid **session Bearer token** is available
in the operator shell as `BANK_TOKEN`, not a password or an unfinished MFA
challenge. Do not paste it into chat, Git or request examples. Use the approved
secret tool to supply it, keep shell tracing off and unset it afterwards.

The following optional Bash helper sends the token through a header stream
rather than a literal curl command-line argument. It does not disable TLS
validation. Install the bank trust chain normally.

```bash
set +x
: "${BANK_TOKEN:?supply an approved short-lived session via bank secret tooling}"
BANK_BASE="https://cryptoscan.bank.example"
BANK_BASE="${BANK_BASE%/}"

bank_api() {
  local method="$1" path="$2"
  shift 2
  {
    printf 'Authorization: Bearer %s\n' "$BANK_TOKEN"
    if [ -n "${BANK_TENANT_ID:-}" ]; then
      printf 'X-Tenant-ID: %s\n' "$BANK_TENANT_ID"
    fi
  } | curl --fail-with-body --silent --show-error \
      --header @- --header 'Content-Type: application/json' \
      --request "$method" "$BANK_BASE$path" "$@"
}
```

If an explicit tenant context is required, obtain the real approved tenant ID
and authorization first. A client header cannot legitimately grant access to a
different bank. Machine API keys have a separate credential/policy path; do not
put an API key into the Bearer-session example. Avoid API tokens in URL queries.

## 3. Register the business system

Save this illustrative request as `system.json` in the restricted working
directory, replacing the source path with the actual mounted, authorized input:

```json
{
  "name": "Payments API - UAT Pilot",
  "owner": "Payments Engineering",
  "technical_owner": "Payments Platform",
  "security_owner": "Application Security",
  "environment": "UAT",
  "business_unit": "Payments",
  "criticality": "HIGH",
  "scan_target": "local:///bank-input/payments-api",
  "scan_branch": "main"
}
```

```bash
bank_api POST /api/v1/systems --data-binary @system.json > system-created.json
SYSTEM_ID=$(python3 -c 'import json; print(json.load(open("system-created.json"))["id"])')
```

`/bank-input/payments-api` must be mounted and admitted on the executing
platform, with worker/runtime staging separately provisioned. It is not a
browser upload. For a Git target, use the approved internal repository URL
without embedded credentials and verify the captured revision.

A repeated create may return 409; retrieve and confirm the existing system
rather than inventing another identity. Registration records ownership, not a
successful CBOM.

## 4. Run and follow the source scan

```bash
bank_api POST "/api/v1/systems/$SYSTEM_ID/scan" > source-job.json
JOB_ID=$(python3 -c 'import json; print(json.load(open("source-job.json"))["job_id"])')
bank_api GET "/api/v1/jobs/$JOB_ID"
bank_api GET "/api/v1/jobs/$JOB_ID/logs"
```

Wait for a terminal result using approved polling/backoff, not a tight loop. The
returned `scan_id` is populated only when available; record the real value and
set `SCAN_ID` from that result. If no committed scan is linked, do not invent one
or proceed as though collection succeeded.

```bash
: "${SCAN_ID:?use the committed scan_id returned for the completed source job}"
bank_api GET "/api/v1/scans/$SCAN_ID/coverage" > source-coverage.json
bank_api GET "/api/v1/scans/$SCAN_ID/verify" > evidence-verification.json
bank_api GET "/api/v1/cbom/scan/$SCAN_ID" > source-cbom.json
bank_api GET "/api/v1/cbom/system/$SYSTEM_ID" > system-cbom.json
```

**Illustrative interpretation:** a source finding identifies an RSA signing call
and a separate hard-coded legacy digest use. The application owner checks code
origin and execution relevance. A test-only digest fixture is not automatically
a production vulnerability. An unresolved key size stays unresolved.

A job can be COMPLETED while its security decision blocks release or optional
collectors report failures. Conversely a missing parser image means the scan
fails; it is not evidence of a crypto-free application. Capture the actual job,
coverage, gate, errors and evidence-verification outcome.

### Generate the standalone software SBOM too

The preceding job and CBOM reads do not replace a package SBOM. Stage the
matching approved source revision on the SBOM executor and follow the
[exact source SBOM request and artifact retrieval example](09-sbom-deep-dive.md#5-api-example-approved-local-software-input).
Retain its distinct artifact ID, dependency-resolution coverage, input identity
and verification. Review admission/isolation differences before using that route.
If the release includes an image, reconcile a separately inspected image digest
with the source-derived software inventory and the bank deployment record.

## 5. Observe the approved gateway and populate NBOM

Use a dedicated, reviewed due-target set. Save `network-target.json`:

```json
{
  "endpoint": "partner-gateway.bank.example:443",
  "system_id": "<returned-system-id>",
  "scan_frequency": "daily",
  "enabled": true
}
```

Replace `<returned-system-id>` with `SYSTEM_ID` from step 3, never a fabricated
UUID. Then:

```bash
bank_api POST /api/v1/network/targets --data-binary @network-target.json
bank_api GET /api/v1/network/due > due-targets.json
```

**Stop and review `due-targets.json`.** `/network/run-due` scans **all currently
due enabled targets in the selected scope**, not just the one most recently
registered. Proceed only if every listed target is approved. Newly registered
targets are initially due; later schedules use the configured interval.

```bash
bank_api POST /api/v1/network/run-due > network-result.json
bank_api GET /api/v1/network/runs > network-runs.json
bank_api GET /api/v1/cbom/nbom > network-bom.json
bank_api GET /api/v1/certificates > certificates.json
```

Retain the actual `run_id` from a non-empty run and verify it through
`GET /api/v1/network/runs/{run_id}`. Confirm that the NBOM's endpoint/probe
provenance corresponds to the stored run. If no targets were due, `scanned: 0`
is a no-op, not a network assessment.

**Illustrative interpretation:** the gateway presents a certificate and
negotiates a TLS suite. The NBOM captures that observed session. It does not
prove that all legacy protocols are disabled or that another SNI/port behaves
identically. Timeouts remain unknown. Only explicitly authorized additional
probing can answer those other questions.

This path calls admission and persists a network run. Other aliases differ:
`/network-scans` has durable job telemetry but does not itself write the NBOM's
network-run ledger; `/network/scan` can write that ledger but lacks the same
explicit admission call. Do not swap endpoints blindly. See
[the route matrix](08-implementation-map-and-limits.md#2-network-route-differences).

## 6. Bring in a real hardware observation

The bank's approved collector—not a guessed spreadsheet row—obtains permitted
metadata. The following `hardware-event.json` is a **lab-only shape example**;
replace every observation with verified input before real use:

```json
{
  "event_type": "HARDWARE_DISCOVERED",
  "asset_id": "PILOT-HSM-01",
  "agent_id": "approved-pilot-collector",
  "source": "management_api",
  "manufacturer": "Illustrative Vendor",
  "model": "Training HSM",
  "device_type": "HSM",
  "firmware": {"application": "1.0.0"}
}
```

```bash
bank_api POST /api/v1/hardware/events --data-binary @hardware-event.json
bank_api GET /api/v1/hbom > estate-hbom.json
bank_api GET /api/v1/hardware/state > live-hardware-state.json
```

The session needs `hardware.ingest` permission. A successful POST means the
supplied event was processed and persistent state written; it is not independent
attestation of the collector. Check asset identity, observation time, evidence
references and source. Do not supply nonexistent PQC/FIPS claims or key material.

After process restart, compare the persisted `/hbom` output with the live-engine
view; these surfaces have deliberately different durability contracts. No
hardware-to-application dependency edge is created just by this event.

## 7. Create and substantiate the supplier relationship

Save `vendor.json`, using the actual system ID:

```json
{
  "name": "Illustrative Payments Supplier",
  "vendor_type": "software",
  "criticality": "HIGH",
  "system_id": "<returned-system-id>"
}
```

```bash
bank_api POST /api/v1/vendors --data-binary @vendor.json > vendor-created.json
VENDOR_ID=$(python3 -c 'import json; print(json.load(open("vendor-created.json"))["id"])')
bank_api GET "/api/v1/vendors/$VENDOR_ID/questionnaire" > vendor-questionnaire.json
bank_api GET "/api/v1/vendors/$VENDOR_ID/profile/schema" > vendor-profile-schema.json
```

Obtain real supplier responses and supporting evidence. Use the appropriate
questionnaire/profile or vendor CBOM-import endpoint after validation. A vendor
CBOM import expects a body containing `sbom` and replaces that vendor's crypto
inventory; review it before overwriting existing declarations. Do not use a
blanket guessed profile just to turn a completeness indicator green.

```bash
bank_api GET "/api/v1/vendors/$VENDOR_ID/vbom" > supplier-vbom.json
bank_api GET /api/v1/vendor-bom > estate-vbom.json
bank_api GET /api/v1/technology-bom/vendor > vendor-system-links.json
```

Immediately after registration, vendor crypto/profile details may be empty.
That is an evidence gap, not a healthy supplier assessment.

## 8. Optional cloud slice

Only after cloud-role, region, account and active-read approval, use a supported
queued target such as the following **request-shape example**:

```json
{
  "repo_url": "aws://111122223333",
  "sector": "banking",
  "scan_mode": "standard"
}
```

Submit through `/api/v1/scans/trigger`, follow its actual job ID and inspect
`progress.cloud`/provider telemetry. Replace the example account ID; merely
using that target string does not configure credentials. A registered account
with all describe/list calls denied must not become a successful empty estate.
IaC-only scans and queued live ingestion have different persistence paths.

## 9. Materialize and capture outputs for review

Once the approved scans/ingestion have settled:

```bash
bank_api GET /api/v1/technology-bom > technology-live.json
bank_api POST /api/v1/technology-bom/snapshot > technology-snapshot.json
bank_api POST "/api/v1/cbom/scan/$SCAN_ID/snapshot" > cbom-pin.json
bank_api POST /api/v1/hbom/snapshot > hbom-pin.json
```

Snapshot writes need the server's required permissions. A repeated identical
capture may reuse an existing snapshot. Record returned IDs/versions; none are
invented in this guide. Fetch the returned verification paths and inspect
integrity results. Independently retain network run/NBOM and vendor revision/
VBOM artifacts plus the standalone SBOM artifact because one TechBOM pin is not
an atomic freeze of every BOM.

For a historical TechBOM export, set `VERSION` from the returned snapshot:

```bash
: "${VERSION:?use the actual recorded Technology BOM version}"
bank_api GET "/api/v1/technology-bom/export?version=$VERSION&fmt=cyclonedx&layer=all" \
  > technology-export-manifest.json
```

The response is a manifest wrapping `data`, not necessarily a bare BOM. Preserve
both, plus verification metadata. View Applications → SBOM (`/dev-sec-ops`),
`/cbom`, `/nbom`, `/hbom`, `/vendor` and `/live-asset-intelligence` through the
internal HTTPS console. See
[06](06-console-apis-and-exports.md) for exact formats and interpretation.

## 10. Make one change and prove one outcome

For example, the bank owner removes a confirmed obsolete digest from the
application or replaces an expiring gateway certificate through the bank's own
change process. CryptoScan does not automatically rotate that certificate or
change the HSM because a finding exists.

Re-scan the same approved target/revision context, retain the new run, and
compare supported snapshots. A closure needs the new fact and matching coverage;
absence from a failed or excluded re-scan is not a fix. Document any remaining
vendor or network unknowns. Protect the resulting evidence bundle and clean up
short-lived credentials:

```bash
unset BANK_TOKEN BANK_TENANT_ID
```

## 11. Other practical bank examples

| Scenario | Collection combination | Expected useful output | Important limit |
|---|---|---|---|
| Online banking certificate migration | Approved TLS probes + certificate inventory + registered system dependencies | NBOM/certificate exposure and recorded migration blast radius | A frontend certificate does not expose backend TLS or every virtual host |
| Core-banking code inaccessible | Approved key/certificate/config exports + permitted network metadata + supplier evidence | Scoped CBOM/NBOM/VBOM facts and explicit unscanned source gap | No claim to have executed or fully scanned the core banking platform |
| Hardware refresh | Actual collector events before/after firmware change | Independent HBOM pin/diff and device evidence | Capability labels are not independent attestation/certification |
| Cloud key-governance review | Scoped SDK metadata + selected application source evidence | Cloud inventory and crypto references where supported ingestion maps them | Missing permissions/regions are explicit gaps; do not export secret key material |
| Air-gapped review | Approved source/artifact/metadata exports and preloaded parser/tools | Offline inventories and hashes within imported scope | No claim of current internet-visible posture or fresh external vulnerability feeds |
