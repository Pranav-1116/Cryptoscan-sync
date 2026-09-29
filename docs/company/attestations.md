# Attestation and certification register

**Status:** controlled register template  
**Owner:** `[COMPLIANCE OWNER]`  
**Rule:** an attestation is valid only when issued by the named issuer, within
scope and period, and verified through an approved channel.

## 1. Register

| Artifact | Issuer | Scope | Period/expiry | Evidence tier | Location | Status |
|---|---|---|---|---|---|---|
| SOC 2 Type I/II | `[CPA FIRM]` | `[SYSTEM/SERVICE]` | `[PERIOD]` | External certification | `[DATA ROOM]` | Not currently evidenced / available |
| ISO/IEC 27001 | `[CERTIFICATION BODY]` | `[ISMS SCOPE]` | `[EXPIRY]` | External certification | `[DATA ROOM]` | Not currently evidenced / available |
| Pen-test report | `[INDEPENDENT ASSESSOR]` | `[RELEASE/SCOPE]` | `[DATE]` | Operational record/external assessment | `[DATA ROOM]` | Not currently evidenced / available |
| HSM provider evidence | `[PROVIDER/CUSTOMER]` | `[KEY/REGION/MODULE]` | `[DATE]` | Provider/customer attestation | `[CONTROLLED PATH]` | Customer-specific |
| DR qualification | `[OPERATOR/CUSTOMER]` | `[TOPOLOGY]` | `[DATE]` | Operational record | `[CONTROLLED PATH]` | Customer-specific |
| Customer pilot sign-off | `[CUSTOMER]` | `[ESTATE/SCOPE]` | `[DATE]` | Customer attestation | `[CONTROLLED PATH]` | Customer-specific |
| Regulatory decision | `[REGULATOR/CUSTOMER]` | `[ENTITY/SCOPE]` | `[DATE]` | Customer/regulatory | `[CONTROLLED PATH]` | Customer-specific |

## 2. Verification checklist

Before releasing an artifact, confirm:

- issuer legal identity;
- issuer authority and independence;
- exact service/system scope;
- period, effective date, and expiry;
- release, region, environment, and deployment;
- exceptions and complementary customer controls;
- signature or verification method;
- source and chain of custody;
- confidentiality and redaction;
- customer-specific limitation; and
- owner, reviewer, and next review.

## 3. Missing evidence response

If the requested artifact is not available, use:

> This artifact is not currently available for the requested service and scope.
> The company can provide the available internal control descriptions and
> readiness evidence, but those materials are not the requested independent
> certification/attestation. The item remains an external or customer-specific
> requirement.

## 4. No self-certification

Do not create a Vendor document titled SOC 2 report, ISO certificate,
regulator approval, customer attestation, or independent penetration test.
Internal checklists and policy documents must retain their actual title and
evidence tier.
