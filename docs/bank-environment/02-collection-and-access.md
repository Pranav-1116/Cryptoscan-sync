# 02 — How collection reaches bank infrastructure

[Guide index](README.md) · Previous: [Deployment](01-entry-and-deployment.md) ·
Next: [Pipeline](03-scan-to-output-pipeline.md)

## 1. Start with a signed scope register

Before adding a target, record its owner, environment, business system, allowed
collector, credential reference, exact path/address/account, permitted operation,
window, budget and exclusion list. Specify whether an entry is **declared**,
**imported**, **observed**, **unreachable** or **not yet scanned**.

For example, “Payments” is a business system, not a scan target. Its Git
repository, load-balancer listener, cloud KMS account and HSM management record
are separate collection targets. Their linkage must come from registered
relationships or evidence; identical names do not prove identity.

## 2. Collection matrix

| Target | How the tool obtains facts | Minimum access / material | Potential outputs | What it cannot establish alone |
|---|---|---|---|---|
| Application repository | Clone approved Git revision or copy an admitted local tree; parse source/configuration | Read-only repository access or a mounted export within authorized roots | CBOM, application/crypto TechBOM layers, findings/evidence | Production execution, complete dynamic crypto behavior, all deployed packages |
| Local source/config export | Read selected tree inside API/worker-visible allowed roots | Controlled file transfer and read access; provenance manifest | Crypto/config inventory and source-linked evidence | Authenticity/freshness of an unsigned operator-supplied export |
| TLS / network service | Connect to selected endpoint; observe protocol, negotiated suite and certificates | DNS/routing plus exact host:port permission; additional enumeration requires approval | Stored network runs, certificates, NBOM | Application internals, unseen virtual hosts or all supported ciphers from one handshake |
| Cloud account / subscription / project | SDK/control-plane metadata reads through supported provider collectors | Scoped read-only role/service identity and selected region/account | Cloud inventory; ingested crypto/system records on supported paths | Resources outside credentials/regions or algorithms concealed behind inaccessible APIs |
| Container or firmware artifact | Read admitted archive/filesystem or pull approved image, then inspect extracted artifacts | Approved archive, registry pull scope and tools; feed connectivity if enabled | Image/package/crypto findings, binary sidecars, applicable shared layers | A running pod's actual state or vulnerability coverage without matching feed/tool evidence |
| Hardware / HSM / TPM | Supported collector reads metadata, or operator supplies approved observations to ingestion API | Approved management metadata, agent/event integration, public capabilities | Persisted hardware estate, HBOM, firmware/security posture | Private HSM keys, every vendor command, or a full physical supply-chain inventory |
| Vendor products | Import vendor BOM/questionnaire/docs; optionally qualified endpoint checks | Vendor-supplied evidence and mapped vendor/system identity | VBOM, vendor crypto inventory, due-diligence views | Truth of an unverified supplier assertion or all unseen supplier internals |
| Runtime/log exports | Supported observations/log inputs or separately installed collectors | Reviewed metadata feed or controlled export; dedicated privileges if needed | Runtime evidence and corroborating crypto inventory where ingested | Universal endpoint monitoring or deployment of agents without bank action |
| OT / legacy restricted zones | Prefer approved passive captures and configuration/inventory exports | OT-owner review and metadata export; explicit live-probe authorization if applicable | Observed OT/config/crypto facts where supported | Permission to actively probe operational equipment or execute legacy business workloads |

Outputs are **path-dependent**: obtaining a result dict does not guarantee that
every downstream inventory table or BOM is updated. The source-to-output mapping
and specific network-path differences are documented in
[08](08-implementation-map-and-limits.md).

## 3. Source repositories: a practical access example

The bank creates a read-only identity for the `payments-api` project in its
internal Git service. The application owner pins a release commit and records
which deployed build it represents. The worker clones only that target into an
admitted staging workspace; the source parser reads that staged copy.

- Keep credentials in bank-approved secret tooling; do not embed access tokens
  in repository URLs, request bodies, findings or screenshots.
- The source parser receives neither repository credentials nor database/queue
  credentials. Clone and staging happen outside its isolated boundary.
- A `local://` target is a path on the executor's filesystem, **not** a directory
  on the operator's laptop. API validation and worker execution must resolve the
  intended mounted path; remote daemon staging has additional requirements.
- A local tree is copied, and may have no verifiable Git revision. Retain an
  export manifest/hash; do not invent a production commit for an unpacked tree.
- Source code can itself contain secrets. Isolation and safe public projections
  do not mean those files were never read, or resolve historical stored snippets.
- Default source scanning also considers test code, tagged by origin. A test
  fixture must not be represented as production cryptography simply because it
  contains an RSA key or MD5 invocation.

## 4. Network scanning is active, even when “read-only”

A TLS handshake does not change application configuration, but it generates
traffic and can trigger IDS/rate limits. Enumerating protocol versions/suites,
probing STARTTLS or sweeping a CIDR generates additional requests.

Start with one approved listener and the intended SNI hostname. A load balancer
may return a default certificate without correct SNI. A successful TLS 1.3
handshake demonstrates that negotiated session, not that TLS 1.0 is impossible.
A refused connection, handshake failure or timeout is not automatically evidence
of plaintext, no cryptography or a healthy service.

Admitted paths support emergency-stop/window/backpressure decisions. However,
**not every network alias has the same admission and persistence behavior** in
this checkout. For the worked pilot we use the reviewed due-target path that
calls admission and persists `network_scan_runs`. Do not equate this with a
fully uniform endpoint-level safety guarantee; see the route matrix in 08.

Independently enforce approved destinations and rates through the bank's
network controls. Application target validation is not a substitute for a
firewall allowlist, DNS controls or operator authorization.

## 5. Cloud: registration, authentication and collection are separate

An account registration tells the platform what exists and which identity to
use. It does not mean any cloud API call succeeded.

A practical AWS example is a bank-approved role that can describe only the
selected KMS, certificate and resource metadata in approved accounts/regions.
The specific permission policy must match the collector's actual API calls;
“read-only” is not one universal IAM policy. Use scoped roles/workload identity
rather than long-lived root credentials. Azure subscriptions and GCP projects
need the same per-collector review and positive qualification.

The queued `aws://...`, `azure://...`, `gcp://...` cloud job path invokes provider
inventory and ingestion rather than cloning a repository. IaC filesystem scans
are a distinct route and may be useful offline. Inspect returned provider
telemetry: zero resources with permission errors is not a clean account. A
partial provider response is not whole-organization coverage.

## 6. Hardware and key inventories

A bank can send an authenticated `HARDWARE_DISCOVERED` metadata event from an
approved collector, including asset identity, model, firmware and security
capability observations. The API updates persistent hardware inventory and its
journal. This enables the independent estate HBOM even if the live controller
is later restarted.

For HSMs/TPMs, collect permitted public metadata and capability/status evidence.
Do not request private key export, master-key material, PIN blocks, customer
records or cryptographic ceremony secrets. A vendor capability catalog is
useful context but is not a live attestation of installed firmware or enabled
PQC support. Unknown fields should stay absent/unknown.

The collector must actually be installed or integrated. Hardware HTTP ingestion
and edge-sync support do not automatically enroll all bank devices. Stronger
requirements such as collector mTLS/attestation, inventory reconciliation and
per-device onboarding must be designed and tested with the bank.

## 7. Vendor evidence and confidence

Procurement/security teams create a vendor record and link it to a real bank
system. They can obtain the questionnaire schema, ingest an approved supplier
BOM, attach documentation evidence and track profile revisions.

Keep three statements distinct:

1. **Supplier says:** “Product release P supports algorithm A.”
2. **Bank observes:** “This installed endpoint negotiated algorithm A at time T.”
3. **Bank concludes:** “The deployed release and observed service are mapped to
   the supplier product, so this migration dependency is actionable.”

An imported document alone supports statement 1, not automatically 2 or 3.
Do not treat a schema-valid profile or a HIGH-confidence wire fact as proof of
all claims about the vendor.

## 8. Data minimization and containment

Approve the minimum data needed: resource identifiers, algorithm metadata,
public certificate details, bounded source locations and evidence references.
Inspect actual request/response/log/export payloads before expanding the pilot.
Sensitive customer/payment data should not be supplied just to make a scan run.

Read-only collection, authenticated ingestion and metadata-only public views
are useful controls, not blanket guarantees about every historical store,
optional connector or relationship lookup. Bank privacy and tenancy acceptance
must include negative tests and a retained, sanitized evidence bundle.
