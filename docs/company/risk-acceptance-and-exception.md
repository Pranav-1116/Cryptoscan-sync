# Risk acceptance and exception form

**Status:** controlled template; not an approval until signed by accountable
risk owner
**Use:** security, privacy, availability, compliance, pilot, and contract
exceptions

A risk acceptance records a deliberate decision to operate with a known gap. It
does not convert a failed control into a passing control or transfer legal
responsibility silently.

## 1. Exception record

| Field | Value |
|---|---|
| Exception ID | `[ID]` |
| Customer/entity | `[ENTITY]` |
| Service/environment | `[SCOPE]` |
| Control/gap | `[CONTROL/P0/P1/QUESTION ID]` |
| Description | `[WHAT IS NOT MET]` |
| Discovered | `[DATE]` |
| Requested by | `[NAME]` |
| Business reason | `[REASON]` |
| Risk owner | `[ACCOUNTABLE PERSON]` |
| Severity | `[CRITICAL/HIGH/MEDIUM/LOW]` |
| Expiry | `[DATE]` |

## 2. Risk analysis

```text
Threat/event: ______________________________
Affected asset/data/process: _______________
Likelihood: low / medium / high
Impact: low / medium / high
Inherent risk: _____________________________
Existing controls: _________________________
Residual risk: _____________________________
Customer/regulator impact: _________________
```

## 3. Compensating controls

| Control | Owner | Due | Evidence |
|---|---|---:|---|
| `[CONTROL]` | `[OWNER]` | `[DATE]` | `[ARTIFACT]` |

## 4. Decision

Choose one:

- approved temporarily;
- approved with compensating control;
- rejected;
- requires customer/regulator approval;
- requires product fix before operation; or
- accepted only for pilot/pre-production.

The approval must state whether it permits production processing. A Vendor
employee must not accept a customer's regulatory or business risk on behalf of
the customer.

## 5. Approval and closure

```text
Security reviewer: _________________________
Privacy/legal reviewer: ____________________
Operations reviewer: _______________________
Customer risk owner: _______________________
Decision/date: _____________________________
Review cadence: ____________________________
Closure evidence: __________________________
Closed by/date: ____________________________
```

Expired exceptions automatically return to open status until renewed by the
accountable owner.
