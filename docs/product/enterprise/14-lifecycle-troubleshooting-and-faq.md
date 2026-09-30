# Lifecycle, troubleshooting, and FAQ

## 1. Version lifecycle

A release should have:

- immutable version/tag and source commit;
- dependency and container lock information;
- SBOM/CBOM and vulnerability review;
- migration and compatibility notes;
- security and product approval;
- deployment digest and rollback/forward plan;
- known limitations and maturity changes; and
- support and end-of-life communication.

The repository changelog, release checks, and production checklist are the
starting point. A local build or source tag does not establish that every
customer deployment is running that version.

## 2. Common installation problems

### API cannot resolve `postgres`

The hostname is valid only on the Compose network. Recreate the base and
production files together, verify network membership, and do not use the
container hostname from a process running directly on the host.

### Production refuses to start

Inspect the configuration guard. Replace demo credentials, wildcard origins,
unsafe database settings, missing production secrets, or invalid provider
configuration. Do not disable the guard to proceed.

### Dashboard is blank or shows offline

Check API origin/CORS, browser network logs, authentication/session expiry,
`/health` and `/ready`, and whether the expected scan has produced data. Empty
state is not proof of zero estate; confirm scope and job completion.

### Scan accepted but no findings appear

Follow the job ID. Check queued/running/completed state, worker liveness,
source authorization, scanner selection, unsupported-format warnings, partial
coverage, and evidence verification. A submitted job is not a completed scan.

### Scan is partial or blocked

Read the coverage and reason fields. Correct the credential, network route,
allowed scope, privacy policy, safety mode, rate limit, or unsupported-format
path. Do not retry indefinitely or broaden permissions without approval.

### Export cannot be verified

Preserve the export and manifest. Check content hash, signature/JWS key,
version, scope, and whether the underlying evidence chain is intact. Treat a
mismatch as an integrity incident until explained.

### A second tenant/customer can see a record

Stop affected access, preserve logs and identifiers, and invoke the security
incident process. Do not attempt to hide the row or repair the database before
scope and evidence are captured.

## 3. Data and migration problems

### Migration fails

Stop application writers, capture migration and database logs, check current
revision, backup integrity, supported PostgreSQL version, and partially applied
DDL. Restore or forward-migrate only under the release procedure.

### Queue jobs repeat

Check lease/visibility timeout, worker crashes, retry count, idempotency key,
and dead-letter state. Determine whether the repeated job wrote duplicate
observations or external tickets before replaying it.

### Evidence verification fails after restore

Compare backup checksum, restore command, database row counts, migration state,
artifact storage, and clock. Run the verification tool against a known scan and
record whether the problem is corruption, missing artifact, key mismatch, or a
pre-existing chain issue.

## 4. FAQ

### Does CryptoScan inspect private keys?

The intended collection model is metadata and observable use, not retrieval of
private key material. Review the collector, input contract, and customer
configuration for the exact source; never upload private keys to make a scan
work.

### Does a PASS mean the organization is compliant?

No. PASS means the selected rule passed for the declared evidence and scope.
Framework compliance requires the complete control set, operating evidence,
legal applicability, external assessment where required, and customer or
regulator decisions.

### Does an empty dashboard mean no cryptography exists?

No. It may mean no authorized scan, a failed/partial job, an empty scope,
unsupported source, or a disconnected data path. Check coverage and job state.

### Does a hash prove the finding is correct?

No. A hash proves integrity of the recorded bytes. Correctness also depends on
source authorization, parser behavior, normalization, scope, and reviewer
interpretation.

### Can the platform automatically fix a finding?

It can provide templates, workflow, or configured automation. A production
change needs owner, approval, testing, deployment, and a new scan. Do not treat
an automation record as proof of remediation.

### Can AI decide whether crypto is compliant?

No. Policy decisions are deterministic and versioned. Generated summaries, if
used, remain secondary to stored evidence and human review.

### Is this an IBM or Google service?

No. The documentation structure is enterprise-style, but CryptoScan is the
product in this repository. Its actual deployment, support, security evidence,
scale, and availability must be measured and contracted separately.

### What if a requested capability is not implemented?

Record it as unsupported or not available, identify the required adapter or
external evidence, and create a scoped plan. Do not fill the gap with a
placeholder that looks like a completed control.
