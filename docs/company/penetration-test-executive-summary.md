# Independent penetration-test executive summary template

**Status:** template only; not a penetration-test report  
**Assessor:** `[INDEPENDENT ASSESSOR]`  
**Assessment dates:** `[DATES]`  
**Release/environment:** `[RELEASE AND ENVIRONMENT]`  
**Confidentiality:** `[RESTRICTED / NDA / DATA ROOM]`

This template must be completed by the independent assessor or based on the
assessor's approved report. Internal security tests must not be rewritten as
independent testing.

## 1. Scope

| Area | Included? | Details |
|---|---|---|
| Web console/API | `[YES/NO]` | `[HOSTS/ROUTES]` |
| Authentication/SSO/MFA | `[YES/NO]` | `[PROTOCOLS]` |
| Authorization/tenant isolation | `[YES/NO]` | `[SURFACES]` |
| Worker/queue/background jobs | `[YES/NO]` | `[BOUNDARY]` |
| Database/evidence/audit | `[YES/NO]` | `[BOUNDARY]` |
| Connectors/SSRF/parser paths | `[YES/NO]` | `[BOUNDARY]` |
| Kubernetes/Compose/cloud | `[YES/NO]` | `[BOUNDARY]` |
| Release/update path | `[YES/NO]` | `[BOUNDARY]` |
| HSM/KMS integration | `[YES/NO]` | `[BOUNDARY]` |
| Denial of service/load | `[YES/NO]` | `[LIMITS]` |

## 2. Methodology

Record standards and methods actually used:

- threat-model review;
- authenticated and unauthenticated web testing;
- API authorization matrix;
- tenant and object access tests;
- injection, SSRF, parser, archive, and command-injection tests;
- dependency and container review;
- cloud and infrastructure review;
- cryptographic and key-boundary review;
- race, retry, queue, and failure testing;
- evidence/audit integrity testing; and
- retest.

## 3. Executive result

```text
Overall conclusion: [ASSESSOR CONCLUSION]
Critical findings: [COUNT]
High findings: [COUNT]
Medium findings: [COUNT]
Low findings: [COUNT]
Informational findings: [COUNT]
Retest completed: [DATE / NO]
Open critical/high findings: [COUNT AND ACCEPTANCE]
```

## 4. Findings summary

| ID | Severity | Area | Summary | Release | Remediation | Retest |
|---|---|---|---|---|---|---|
| `[ID]` | `[SEVERITY]` | `[AREA]` | `[SUMMARY]` | `[DIGEST]` | `[STATUS]` | `[RESULT]` |

Do not omit accepted findings. Attach the residual-risk approval and expiry.

## 5. Limitations

The summary must disclose:

- excluded assets, regions, connectors, and source systems;
- test account and privilege limits;
- rate limits and denied test methods;
- untested customer configurations;
- testing dates and release digest;
- dependency on customer-provided access or data; and
- any result that cannot be generalized to another deployment.

## 6. Vendor response

Vendor may provide a response matrix, but must not edit the assessor's result:

| Finding | Vendor response | Fix/retest evidence | Residual risk owner |
|---|---|---|---|
| `[ID]` | `[RESPONSE]` | `[EVIDENCE]` | `[OWNER/EXPIRY]` |

## 7. Distribution

Provide the full report only through an approved secure channel. A customer may
receive a redacted summary, but the summary must identify that it is redacted
and must not imply that omitted scope was clean.
