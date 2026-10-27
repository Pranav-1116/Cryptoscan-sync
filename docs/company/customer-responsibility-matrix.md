# CryptoScan customer responsibility matrix

**Status:** deployment-specific template
**Rule:** complete this matrix in every Order Form and security review

Security questionnaires often fail because the provider and customer assume
the other party owns a control. This matrix makes the boundary explicit.

## 1. Responsibility levels

- **V** — Vendor owns execution.
- **C** — Customer owns execution.
- **S** — Shared; each party has a named sub-control.
- **P** — Provider/subprocessor owns the control; Vendor manages the contract.
- **N/A** — Not applicable with a documented reason.

## 2. Matrix

| Control area | Customer-managed deployment | Vendor-managed dedicated deployment | Named owner/evidence |
|---|---|---|---|
| Contract and lawful scope | C | C | `[OWNER]` |
| Source authorization | C | C | `[OWNER]` |
| Data classification | C | S | `[OWNER]` |
| Customer legal basis | C | C | `[OWNER]` |
| Application release | V/S | V | `[OWNER]` |
| Cloud account | C | P/V | `[OWNER]` |
| Network/firewall/proxy | C | S/V | `[OWNER]` |
| Identity provider | C | S | `[OWNER]` |
| MFA policy | C | S | `[OWNER]` |
| CryptoScan roles | S | V | `[OWNER]` |
| API keys/service accounts | C/S | V/S | `[OWNER]` |
| Database | C | V/P | `[OWNER]` |
| Queue/cache/graph | C | V/P | `[OWNER]` |
| Object/evidence storage | C | V/P | `[OWNER]` |
| HSM/KMS | C/P | C/P/V as agreed | `[OWNER]` |
| Key ceremonies | C/P | C/P/V as agreed | `[OWNER]` |
| Encryption configuration | S | V/S | `[OWNER]` |
| Source connector permissions | C | C/S | `[OWNER]` |
| Scan targets/rate limits | C | S | `[OWNER]` |
| Finding validation | C | V support | `[OWNER]` |
| Remediation | C | C | `[OWNER]` |
| Risk acceptance | C | C for Vendor residual risk | `[OWNER]` |
| Audit logging | S | V/S | `[OWNER]` |
| SIEM integration | C | S | `[OWNER]` |
| Vulnerability remediation | V | V | `[OWNER]` |
| Customer-side vulnerabilities | C | C | `[OWNER]` |
| Backup | C | V | `[OWNER]` |
| Restore testing | C | V/S | `[OWNER]` |
| DR topology | C | V/S | `[OWNER]` |
| RPO/RTO decision | C | V proposes/measures | `[OWNER]` |
| Incident response | S | S | `[OWNER]` |
| Privacy rights | C | V assists | `[OWNER]` |
| Subprocessors | V | V | `[OWNER]` |
| Residency approval | C | S/V | `[OWNER]` |
| Support contacts | C | V | `[OWNER]` |
| Deletion from Customer systems | C | N/A/V as agreed | `[OWNER]` |
| Deletion from Vendor systems | N/A | V | `[OWNER]` |
| Legal hold | C | S | `[OWNER]` |

## 3. Customer must confirm

Before go-live, Customer must identify:

- system owner;
- security owner;
- privacy owner/DPO;
- platform and network owner;
- identity owner;
- database/backup owner;
- HSM/KMS owner;
- incident commander;
- procurement/legal owner;
- risk acceptance authority; and
- deletion/exit owner.

## 4. Review events

Review this matrix when:

- deployment model changes;
- a new source or integration is added;
- a new region/subprocessor is used;
- support access changes;
- a security incident occurs;
- an SLA or DPA changes;
- a DR exercise identifies a responsibility gap; or
- the Order Form renews.
