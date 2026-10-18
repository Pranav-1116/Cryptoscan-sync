# 14 — Detailed bank dependency, cascade and blast-radius examples

[Guide index](README.md) · Previous: [Mechanics](13-cascade-and-blast-radius.md) ·
Next: [API runbook](15-dependency-cascade-api-runbook.md)

**All systems, devices, counts and scenarios here are illustrative.** The exact
results in sections 2–5 are from the product's pure engine on a synthetic fixture,
not a real bank, production traffic, customer data or a deployed-device test.

## 1. Establish one consistent bank topology

Every arrow means the left-hand system depends on the right-hand system:

```text
Mobile Banking -----+
                    +--> API Gateway --> Payments API --> Signing Service
Internet Banking ---+                         |                 |
                                              |                 +--> Key Service
Settlement Batch -----------------------------+
                                              |
                                              +--> Ledger
```

Separately, the bank has substantiated and declared:

```text
Signing Service -> signing crypto asset -> served by HSM-Example
```

The graph uses these fixture IDs:

| ID | Illustrative system |
|---|---|
| `mobile` | Mobile Banking |
| `internet` | Internet Banking |
| `gateway` | API Gateway |
| `payments` | Payments API |
| `batch` | Settlement Batch |
| `signing` | Signing Service |
| `ledger` | Ledger |
| `keyservice` | Key Service |

In the fixture, the signing asset has RSA-2048 evidence. Signing Service is linked
to the process “Payment authorization”; Mobile Banking separately has a “Mobile
banking” process link. Neither assignment is inferred from a system name.

## 2. HSM unavailable: a device cascade

**Question:** “Which registered applications should be investigated if this HSM
becomes unavailable or needs an incompatible change?”

The engine starts from the matched device, reads declared crypto-to-hardware
links, resolves linked crypto assets' systems and walks their dependents.

| Stage/depth | Systems | Explanation |
|---|---|---|
| Seed | Signing Service | It owns the linked signing crypto asset |
| 1 | Payments API | Directly depends on Signing Service |
| 2 | API Gateway, Settlement Batch | Depend on Payments API |
| 3 | Mobile Banking, Internet Banking | Depend on API Gateway |

The actual engine returns **6 distinct implicated systems**, maximum propagation
depth **3**, and the linked “Payment authorization” and “Mobile banking” processes.

Partial actual fixture output:

```json
{
  "dependents_by_depth": {
    "1": ["payments"],
    "2": ["batch", "gateway"],
    "3": ["internet", "mobile"]
  },
  "affected_systems": ["batch", "gateway", "internet", "mobile", "payments", "signing"],
  "affected_system_count": 6,
  "max_propagation_depth": 3
}
```

These fields are extracted from the system layer and impact object; this is not
a complete API response.

### Why Ledger and Key Service are not in this result

They are dependencies of implicated systems, not consumers of the selected HSM
relationship in this modeled graph. The device cascade does not walk forward to
all supporting dependencies. Ledger can remain operational while payment
authorization fails. Business transactions may be interrupted without all
participating infrastructure having failed.

### What is still unknown

The result does not simulate an HA HSM pair, another signing provider, retries,
queues, cached sessions, partial transaction success or failover configuration.
A bank incident operator must verify actual health and redundancy separately.

## 3. Remove the HSM link: a critical completeness test

Keep the HSM inventory row but remove its declared crypto-to-hardware link.
The actual engine then returns:

```json
{
  "verdict": "AFFECTED",
  "affected_system_count": 0,
  "inventory_only": true
}
```

Again, this is a partial extraction, not the whole API envelope.

The verdict is possible because a concrete hardware device was found. It does
not mean applications were successfully traced. The unknowns name the absence
of declared device linkage.

Correct review statement:

> The device is known, but application consumers cannot be named from available
> relationships. Investigate and substantiate the missing link.

Incorrect statement:

> No bank applications depend on this HSM, because the system count is zero.

## 4. Payments API change: aggregate versus outage scope

Now target Payments API itself. In this fixture, unified system cascade returns:

| Category | Systems |
|---|---|
| Selected system | Payments API |
| Reverse dependents, depth 1 | API Gateway, Settlement Batch |
| Reverse dependents, depth 2 | Mobile Banking, Internet Banking |
| Supporting dependencies, depth 1 | Ledger, Signing Service |
| Supporting dependencies, depth 2 | Key Service |

The aggregate is **8 systems**, maximum propagation depth **2**.

This is a broad review set, not eight proven outages. Signing Service and Ledger
might require coordination or compatibility review without being stopped by
Payments API becoming unavailable.

For a bank presentation, split the result into:

```text
Directly implicated target
Potentially affected consumers
Supporting dependencies / change context
Confirmed operational outcomes (from independent incident evidence)
```

### Business-process closure after step 6

This fixture links processes to Signing Service and Mobile Banking, not Payments
API. The system-target result now includes both processes because it projects
support mappings over all classified review systems. Mobile Banking contributes
modeled consumer exposure; Signing Service contributes supporting context only.
The context-only process is not counted as an exposed process.

For the HSM target, Signing Service is directly implicated and Mobile Banking is
a dependent consumer, so both processes are in modeled exposure. Each process
retains its supporting system ID, scope and mapping evidence when available.
Missing mappings elsewhere remain unknown, not evidence of no business impact.
See [step 6](22-business-process-impact-and-inclusion-reasons.md) for the current
ID-based projection and its bounds.

## 5. RSA migration: a crypto-evidence cascade

Targeting RSA-2048 in the same fixture matches signing evidence/live-asset state,
resolves Signing Service and returns the same **6-system dependent set** as the
linked HSM case. It also names the fixture signing asset and its library context.

This does not mean removing or replacing RSA necessarily breaks all six systems.
An interface-compatible change could preserve behavior. A signing change also
requires bank-specific protocol, verifier, key/certificate, partner and rollback
review that simple reachability cannot establish.

Do not read a cipher-family match as proof of a particular key size or assume a
library's advertised algorithm capability is evidence of actual invocation.

## 6. Reproduce the exact local fixture

From the repository root with project Python dependencies installed, run this
snippet. It uses only a plain dictionary and the real pure cascade engine. No
bank target, API, database, source checkout acquisition or network is used.

```bash
PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)" python3 - <<'PY'
from datetime import datetime, timezone
import json
from cbom.unified_cascade import unified_cascade

names = ['mobile', 'internet', 'gateway', 'payments', 'batch', 'signing', 'ledger', 'keyservice']
snapshot = {
    'systems': [{'id': n, 'name': n} for n in names],
    'assets': [{'asset_id': 'signing-crypto', 'system_ids': ['signing'],
                'algorithms': {'RSA-2048': 1}, 'libraries': {'DemoCrypto': 'fixture'}}],
    'evidence': [{'id': 'example-evidence', 'system_id': 'signing',
                  'algorithm': 'RSA-2048', 'file_path': 'signing/sign.py'}],
    'dependencies': [{'source': a, 'target': b, 'type': 'CALLS'} for a, b in [
        ('mobile', 'gateway'), ('internet', 'gateway'), ('gateway', 'payments'),
        ('batch', 'payments'), ('payments', 'signing'), ('payments', 'ledger'),
        ('signing', 'keyservice')]],
    'hardware': [{'asset_id': 'hsm-example', 'manufacturer': 'Fictional Vendor',
                  'model': 'Fictional HSM'}],
    'crypto_hardware': {'hsm-example': ['signing-crypto']},
    'business_processes': {
        'signing': [{'id': 'process-authorize', 'name': 'Payment authorization'}],
        'mobile': [{'id': 'process-mobile', 'name': 'Mobile banking'}]},
}
now = datetime(2026, 10, 18, tzinfo=timezone.utc)
expected = {'batch', 'gateway', 'internet', 'mobile', 'payments', 'signing'}
for kind, target in [('device', 'hsm-example'), ('algorithm', 'RSA-2048'),
                     ('system', 'payments')]:
    result = unified_cascade(snapshot, target=target, kind=kind, max_depth=6, now=now)
    impact = result['impact']
    if kind in ('device', 'algorithm'):
        assert set(impact['affected_systems']) == expected
        assert impact['affected_system_count'] == 6
        assert impact['max_propagation_depth'] == 3
        assert impact['affected_processes'] == [
            {'id': 'process-authorize', 'name': 'Payment authorization'},
            {'id': 'process-mobile', 'name': 'Mobile banking'}]
        assert impact['process_impact']['counts']['exposure'] == 2
    else:
        assert set(impact['affected_systems']) == set(names)
        assert impact['affected_system_count'] == 8
        assert impact['max_propagation_depth'] == 2
        assert impact['affected_processes'] == [
            {'id': 'process-authorize', 'name': 'Payment authorization'},
            {'id': 'process-mobile', 'name': 'Mobile banking'}]
        assert impact['process_impact']['counts']['exposure'] == 1
        assert impact['process_impact']['counts']['context_only'] == 1
    print(json.dumps({'kind': kind, 'impact': impact,
                      'system': result['layers']['system']}, indent=2))

snapshot['crypto_hardware'] = {}
result = unified_cascade(snapshot, target='hsm-example', kind='device', max_depth=6, now=now)
assert result['verdict'] == 'AFFECTED'
assert result['impact']['affected_system_count'] == 0
assert result['layers']['hardware']['inventory_only'] is True
assert any('no declared crypto-to-hardware' in x for x in result['honest_unknowns'])
print('Missing hardware link remains explicitly unknown: PASS')
PY
```

The IDs above belong only to the fixture. They must not be pasted into bank API
requests as though those database objects exist.

## 7. Certificate rotation at a bank gateway

**Scenario:** the PKI team plans to replace a gateway certificate.

1. Identify the actual certificate fingerprint, intended listener/SNI and owner.
2. Inspect recorded certificate-usage links and observed listener evidence.
3. Run the certificate cascade and separate direct owners, consumers and
   supporting dependencies.
4. Check actual client trust stores, certificate pinning, mutual-TLS requirements
   and partner certification outside the simple graph calculation.
5. Perform the bank-approved rotation and re-observe the intended service.
6. Preserve before/after evidence and explain unresolved consumers.

Current caveat: even if target selection uses a fingerprint, endpoint association
can use subject matching. Renewed/different certificates sharing a subject can
be conflated. A file import also does not prove a certificate was served live.

## 8. Supplier package advisory

**Scenario:** the bank supplies an approved advisory affecting a package version
in a vendor-delivered payment image. No real CVE or affected range is invented.

```text
Approved advisory -> matched package/version -> inspected image digest
                  -> bank deployment record -> named system -> consumers
```

Use the SBOM to inspect supported package resolution/artifact evidence. Verify
that an advisory feed was actually applied and map the artifact to deployment.
Use crypto-library cascade only where its live-asset/system identity chain
exists. Do not pretend the standalone SBOM graph is automatically joined to all
business-system edges.

Package presence does not prove vulnerability reachability, exploitability or a
successful attack. A source lockfile update alone does not prove the production
image was replaced. Rebuild/deploy through bank processes and recheck the actual
release identity.

## 9. Supplier disruption and sub-tier exposure

**Scenario:** a payment-platform supplier relies on an HSM supplier that relies
on a chip vendor. Record product/release-specific system/vendor links and the
substantiated vendor-of-vendor declarations.

The vendor cascade can report linked systems, context and bounded declared
sub-tier relationships. Current sub-tier traversal is forward and bounded to
three levels. It is not a universal reverse search from a chip supplier to all
bank customers, nor proof every supplier product/version uses the same chip.

Manufacturer/library-name matches are weaker than verified product/deployment
identity. Preserve supplier declarations as declarations; do not convert them
into measured hardware or runtime claims.

## 10. How the bank should present the result

For every investigation, answer:

- What exact target and environment were selected?
- Which links are code-derived, observed, declared or imported?
- Which systems are seeds, reverse consumers or supporting context?
- What is known about freshness, omissions, caps and identity conflicts?
- Which business-process links actually exist, and which are missing?
- Which conclusions came from CryptoScan and which from operational testing?
- What changed between runs: bank deployment, source evidence, edge data, depth,
  backend, snapshot version or input coverage?

A smaller justified graph is preferable to a larger graph that hides assumptions.
