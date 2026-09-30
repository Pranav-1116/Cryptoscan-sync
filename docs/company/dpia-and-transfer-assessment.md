# Data Protection Impact Assessment and transfer assessment template

**Status:** privacy/legal review required; customer-specific
**Customer:** `[CUSTOMER]`
**Processing:** CryptoScan `[DEPLOYMENT/SOURCE]`
**Assessment ID:** `[ID]`

A DPA allocates responsibilities. A DPIA assesses whether the processing is
likely to create high risk and what measures reduce it. A transfer assessment
examines cross-border access and provider law. Complete both where applicable.

## 1. Processing description

| Field | Value |
|---|---|
| Purpose | `[PURPOSE]` |
| Controller/processor roles | `[ROLES]` |
| Data subjects | `[CATEGORIES]` |
| Data types | `[CATEGORIES]` |
| Sensitive data | `[NONE/DETAIL]` |
| Source systems | `[SOURCES]` |
| Processing operations | `[COLLECT/ANALYZE/STORE/EXPORT/DELETE]` |
| Regions | `[PRIMARY/BACKUP/SUPPORT/SUBPROCESSOR]` |
| Duration | `[TERM/RETENTION]` |
| Recipients | `[VENDOR/CUSTOMER/SUBPROCESSORS]` |
| Automated decision | `[YES/NO; EXPLANATION]` |
| Individual impact | `[ASSESSMENT]` |

## 2. Necessity and proportionality

Explain:

- why each data category is needed;
- why a less intrusive source is insufficient;
- how data is minimized or masked;
- how accuracy and human review are handled;
- how retention is limited;
- how access is restricted; and
- how individuals can exercise rights.

CryptoScan findings must not be used as an unreviewed automated decision about
employment, credit, eligibility, or an individual.

## 3. Risk assessment

| Risk | Likelihood | Impact | Control | Residual risk | Owner |
|---|---|---|---|---|---|
| Unauthorized source access | `[L/M/H]` | `[L/M/H]` | Read-only scope, authorization, RBAC | `[RATING]` | `[OWNER]` |
| Sensitive data ingestion | `[L/M/H]` | `[L/M/H]` | Minimize, prohibit, mask, DPA | `[RATING]` | `[OWNER]` |
| Cross-region access | `[L/M/H]` | `[L/M/H]` | Region/transfer controls | `[RATING]` | `[OWNER]` |
| Insider/admin access | `[L/M/H]` | `[L/M/H]` | Least privilege, log, review | `[RATING]` | `[OWNER]` |
| Backup/deletion failure | `[L/M/H]` | `[L/M/H]` | Retention, encryption, verification | `[RATING]` | `[OWNER]` |
| Misleading finding | `[L/M/H]` | `[L/M/H]` | Human review, unknown state | `[RATING]` | `[OWNER]` |
| Security incident | `[L/M/H]` | `[L/M/H]` | IR, monitoring, notification | `[RATING]` | `[OWNER]` |

## 4. Transfer assessment

| Transfer | Destination | Provider/law | Data | Mechanism | Risk | Supplementary measure |
|---|---|---|---|---|---|---|
| `[TRANSFER]` | `[REGION]` | `[PROVIDER]` | `[DATA]` | `[SCC/ADEQUACY/OTHER]` | `[RISK]` | `[MEASURE]` |

Consider government access, provider support, encryption, key control,
subprocessor access, legal remedies, and deletion.

## 5. Consultation and approval

Record customer privacy, security, legal, business, and regulator consultation
where required. The assessment should state whether residual risk is:

- accepted;
- reduced with a required action;
- prohibited pending change; or
- referred to a regulator or counsel.

```text
Customer privacy owner: __________________
Customer security owner: _________________
Legal reviewer: __________________________
Regulator consultation: ___________________
Decision: _________________________________
Approval date: ____________________________
Next review: ______________________________
```
