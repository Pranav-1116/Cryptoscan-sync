# Policy scopes

Baseline rules (`BASELINE-001` … `004`) always evaluate. Advanced
standards (PCI-DSS, NIST SP 800-131A, CNSA 2.0, FIPS 140-3, HIPAA)
return `NOT_APPLICABLE` unless the finding carries a matching
`compliance_scopes` tag.

## How scopes are attached

1. Create a system with `compliance_scopes: ["PCI-DSS"]`.
2. Name it after the repository (the worker auto-creates that name), or
   attach assets to it yourself.
3. The next pipeline run copies those scopes onto every evidence record
   before evaluation.

You can also put `compliance_scopes` on a finding payload when calling
the policy engine directly.

## Catalogue (Part 2)

| ID | Standard | Applies when |
| --- | --- | --- |
| PCIDSS-001 | PCI-DSS 4.2.1 | Forbidden legacy algorithms |
| PCIDSS-002 | PCI-DSS 3.5.1 | AES-256-GCM/CCM for PAN |
| PCIDSS-003 | PCI-DSS 4.2.2 / 12.3.3 | Purpose must be documented |
| PCIDSS-004 | PCI-DSS 8.3.2 | Modern KDF for passwords |
| NIST131A-001 | SP 800-131A | RSA key transport size |
| NIST131A-002 | SP 800-131A | MD5 / SHA-1 disallowed |
| NIST131A-003 | SP 800-131A | DSA disallowed |
| CNSA-001 | CNSA 2.0 | Classical PK retires after 2025 |
| CNSA-002 | CNSA 2.0 | Hybrid mode required |
| FIPS140-001 | FIPS 140-3 | Approved algorithm list |
| FIPS140-002 | FIPS 140-3 | RSA ≥ 2048 |
| HIPAA-001 | HIPAA | SHA-1 forbidden for ePHI |

Policy is never decided by a model. Every result is a deterministic YAML
rule evaluation.
