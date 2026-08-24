# Compliance standards

Baseline rules (BASELINE-001…004) always apply.

Advanced YAML is **scope-gated**. A finding is only evaluated against PCI /
NIST / CNSA / FIPS / HIPAA when the parent system’s `compliance_scopes`
intersects the rule’s `required_scopes`.

| Prefix     | Standard              | Example fail                          |
|------------|-----------------------|---------------------------------------|
| PCIDSS     | PCI-DSS 4.0           | DES, TLS 1.0, raw password hashes     |
| NIST131A   | NIST SP 800-131A      | DSA, RSA key transport / agreement    |
| CNSA       | NSA CNSA 2.0          | Classical-only after 2025, AES < 256  |
| FIPS140    | FIPS 140-3            | Non-approved algorithms, SHA-1 sign   |
| HIPAA      | 45 CFR 164.312        | Weak crypto on ePHI                   |

Attach scopes when you create a system (`PCI-DSS`, `NIST-131A`, `CNSA`,
`FIPS`, `HIPAA`). The dashboard Compliance page groups rule evaluations by
standard. Overall status is still PASS / WARN / FAIL / NOT_APPLICABLE —
never `CRITICAL_FAIL`.
