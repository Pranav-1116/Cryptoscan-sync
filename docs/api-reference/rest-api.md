# REST API reference

Generated from the live OpenAPI schema (`GET /api/openapi.json`) on 2026-09-13:
**595 paths, 655 operations** across 79 tagged groups.
Re-generate after API changes; this file is a mirror of the schema, not a hand-maintained list.

## Conventions

- Base path: `/api/v1`. Interactive docs: `/api/docs` (Swagger UI).
- Auth: `POST /auth/login` `{username, password}` → cookie `cryptoscan_session` + `token`.
  Send `Authorization: Bearer <token>` or rely on the cookie.
- Development login: `admin` / `cryptoscan` (refused in production).
- RBAC: 9 roles (superadmin, ciso, security_analyst, developer, auditor, business_owner,
  scanner, readonly, supervisor); most read endpoints allow readonly+, exports/mutations are role-gated.
- Multi-tenant SaaS: tenant-scoped requests resolve the organization from the session's
  memberships or `X-Tenant-ID`; API keys minted inside a tenant are bound to it. See
  [architecture/multi-tenancy.md](../architecture/multi-tenancy.md).
- Every list endpoint is paginated and every export carries SHA-256 verification
  (`/verify` siblings) — see [user-guide/evidence-pack.md](../user-guide/evidence-pack.md).

## agility

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/agility` | List Agility |
| `GET` | `/api/v1/agility/pqc` | Agility Pqc |
| `GET` | `/api/v1/agility/roadmap` | Agility Roadmap |
| `GET` | `/api/v1/readiness` | List Readiness |
| `GET` | `/api/v1/systems/{system_id}/agility` | Get System Agility |
| `GET` | `/api/v1/systems/{system_id}/agility/history` | Agility History |
| `POST` | `/api/v1/systems/{system_id}/agility/recalculate` | Recalculate |
| `POST` | `/api/v1/systems/{system_id}/agility/simulate` | Agility Simulate |

## algorithms

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/algorithms` | List Algorithms |
| `GET` | `/api/v1/algorithms/` | List Algorithms |
| `GET` | `/api/v1/algorithms/parse` | Parse |
| `GET` | `/api/v1/algorithms/parse-many` | Parse Many |

## analytics

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/analytics` | Overview |
| `GET` | `/api/v1/analytics/executive` | Executive |
| `GET` | `/api/v1/analytics/forecast` | Forecast |
| `GET` | `/api/v1/analytics/heatmap` | Heatmap |
| `GET` | `/api/v1/analytics/recommendations` | Recs |
| `GET` | `/api/v1/analytics/trends` | Trends |

## anomaly

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/anomaly/analyze` | Analyze |
| `POST` | `/api/v1/anomaly/baseline` | Seal Baseline |
| `POST` | `/api/v1/anomaly/baseline/drift` | Baseline Drift |
| `GET` | `/api/v1/anomaly/flags` | List Flags |
| `POST` | `/api/v1/anomaly/flags/{flag_pk}/ack` | Ack Flag |
| `POST` | `/api/v1/anomaly/scan` | Scan Telemetry |

## api-keys

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/api-keys` | List Api Keys |
| `POST` | `/api/v1/api-keys` | Create Api Key |
| `GET` | `/api/v1/api-keys/rotation/report` | Rotation Report |
| `PATCH` | `/api/v1/api-keys/{key_id}` | Update Api Key Policy |
| `DELETE` | `/api/v1/api-keys/{key_id}` | Revoke Api Key |

## assets

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/assets` | List Assets |
| `GET` | `/api/v1/assets/{asset_id}` | Get Asset |

## audit-export

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/audit-export/engagement-archive` | Engagement Archive |
| `GET` | `/api/v1/audit-export/exit-report` | Exit Report |
| `GET` | `/api/v1/audit-export/pack` | Export Pack |

## authentication

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/auth/audit` | List Audit |
| `GET` | `/api/v1/auth/audit/export` | Export Audit |
| `GET` | `/api/v1/auth/audit/verify` | Verify Audit |
| `POST` | `/api/v1/auth/login` | Login |
| `POST` | `/api/v1/auth/login/mfa` | Login Mfa |
| `POST` | `/api/v1/auth/logout` | Logout |
| `GET` | `/api/v1/auth/me` | Me |
| `PATCH` | `/api/v1/auth/me` | Update Me |
| `POST` | `/api/v1/auth/me/password` | Change My Password |
| `GET` | `/api/v1/auth/me/sessions` | List My Sessions |
| `POST` | `/api/v1/auth/me/sessions/revoke` | Revoke My Sessions |
| `POST` | `/api/v1/auth/mfa/disable` | Mfa Disable |
| `POST` | `/api/v1/auth/mfa/enable` | Mfa Enable |
| `POST` | `/api/v1/auth/mfa/enroll` | Mfa Enroll |
| `POST` | `/api/v1/auth/oidc` | Oidc Login |
| `GET` | `/api/v1/auth/oidc/authorize` | Oidc Authorize |
| `GET` | `/api/v1/auth/oidc/callback` | Oidc Callback |
| `POST` | `/api/v1/auth/register` | Register |
| `GET` | `/api/v1/auth/roles` | List Roles |
| `GET` | `/api/v1/auth/users` | List Users |
| `POST` | `/api/v1/auth/users` | Create User |
| `PATCH` | `/api/v1/auth/users/{username}` | Update User |
| `DELETE` | `/api/v1/auth/users/{username}` | Delete User |
| `POST` | `/api/v1/auth/users/{username}/restore` | Restore User |

## automation

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/automation/blast-radius` | Blast Radius |
| `GET` | `/api/v1/automation/capabilities` | Capabilities |
| `GET` | `/api/v1/automation/cbom/versions` | Cbom History |
| `POST` | `/api/v1/automation/cbom/versions` | Cbom Update |
| `POST` | `/api/v1/automation/cert-watch` | Cert Watch |
| `GET` | `/api/v1/automation/connectors` | List Connectors |
| `POST` | `/api/v1/automation/connectors/dispatch` | Connector Dispatch |
| `POST` | `/api/v1/automation/connectors/preview` | Connector Preview |
| `POST` | `/api/v1/automation/health/platform` | Platform Health |
| `POST` | `/api/v1/automation/health/sweep` | Health Sweep |
| `POST` | `/api/v1/automation/post-migration/validate` | Post Migration Validate |
| `POST` | `/api/v1/automation/process-event` | Process Event |
| `POST` | `/api/v1/automation/risk/recalculate` | Risk Recalculate |
| `GET` | `/api/v1/automation/rules` | List Rules |
| `POST` | `/api/v1/automation/rules` | Upsert Rule |
| `DELETE` | `/api/v1/automation/rules/{rule_id}` | Delete Rule |
| `GET` | `/api/v1/automation/runs` | List Runs |
| `POST` | `/api/v1/automation/schedule` | Schedule Preview |
| `GET` | `/api/v1/automation/sectors` | List Sectors |
| `POST` | `/api/v1/automation/sectors/{sector}/activate` | Activate Sector Endpoint |
| `POST` | `/api/v1/automation/select-scanners` | Select Scanners Preview |
| `POST` | `/api/v1/automation/telecom-guardrails` | Install Telecom Guardrails |

## banking-regulatory

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/banking/action-plan` | Banking Action Plan |
| `GET` | `/api/v1/banking/action-plan/export` | Banking Action Plan Export |
| `GET` | `/api/v1/banking/compliance-crosswalk` | Banking Compliance Crosswalk |
| `GET` | `/api/v1/banking/fips` | Banking Fips Lookup |
| `GET` | `/api/v1/banking/fips/registry` | Banking Fips Registry |
| `POST` | `/api/v1/banking/fips/registry` | Banking Fips Registry Add |
| `GET` | `/api/v1/banking/group` | Banking Group Rollup |
| `GET` | `/api/v1/banking/group/dora-register` | Banking Group Dora Register |
| `GET` | `/api/v1/banking/group/entities` | Banking Group Entities |
| `POST` | `/api/v1/banking/group/entities` | Banking Group Entity Add |
| `DELETE` | `/api/v1/banking/group/entities/{code}` | Banking Group Entity Delete |
| `GET` | `/api/v1/banking/group/roadmap` | Banking Group Roadmap |
| `GET` | `/api/v1/banking/group/supervisor-pack` | Banking Group Supervisor Pack |
| `PUT` | `/api/v1/banking/group/systems/{system_id}/entity` | Banking Group Assign System |
| `GET` | `/api/v1/banking/hndl` | Banking Hndl |
| `GET` | `/api/v1/banking/hsm` | Banking Hsm Fleet |
| `GET` | `/api/v1/banking/hsm/deep` | Banking Hsm Deep |
| `POST` | `/api/v1/banking/hsm/parse` | Banking Hsm Parse |
| `GET` | `/api/v1/banking/integrations/qualys` | Banking Integrations Qualys |
| `GET` | `/api/v1/banking/integrations/servicenow` | Banking Integrations Servicenow |
| `GET` | `/api/v1/banking/jurisdiction/{code}` | Banking Jurisdiction |
| `GET` | `/api/v1/banking/jurisdictions` | Banking Jurisdictions |
| `GET` | `/api/v1/banking/keys` | Banking Key Lifecycle |
| `GET` | `/api/v1/banking/mainframe` | Banking Mainframe Inventory |
| `POST` | `/api/v1/banking/mainframe/analyze` | Banking Mainframe Analyze |
| `GET` | `/api/v1/banking/mainframe/assessment` | Banking Mainframe Assessment |
| `POST` | `/api/v1/banking/mainframe/ingest` | Banking Mainframe Ingest |
| `GET` | `/api/v1/banking/overview` | Banking Overview Endpoint |
| `GET` | `/api/v1/banking/roadmap` | Banking Roadmap |
| `GET` | `/api/v1/banking/swift-csp` | Banking Swift Csp |

## baselines

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/baselines` | List Baselines |
| `POST` | `/api/v1/baselines/approve` | Approve |

## business

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/business/owners` | List Owners |
| `POST` | `/api/v1/business/owners` | Create Owner |
| `GET` | `/api/v1/business/processes` | List Processes |
| `POST` | `/api/v1/business/processes` | Create Process |
| `POST` | `/api/v1/business/processes/{process_id}/systems` | Link Process |
| `GET` | `/api/v1/migrations` | List Migrations |
| `POST` | `/api/v1/migrations` | Create Migration |
| `POST` | `/api/v1/migrations/from-scan` | Create Migration From Scan |
| `PATCH` | `/api/v1/migrations/tasks/{task_id}` | Update Migration Task |
| `PATCH` | `/api/v1/migrations/{project_id}` | Update Migration |
| `GET` | `/api/v1/migrations/{project_id}/export/github-issues` | Export Github Issues |
| `GET` | `/api/v1/migrations/{project_id}/forecast` | Migration Forecast |
| `GET` | `/api/v1/migrations/{project_id}/milestones` | List Milestones |
| `POST` | `/api/v1/migrations/{project_id}/milestones` | Add Milestone |
| `GET` | `/api/v1/migrations/{project_id}/progress` | Migration Progress |
| `POST` | `/api/v1/migrations/{project_id}/sync` | Sync Migration |
| `GET` | `/api/v1/migrations/{project_id}/tasks` | List Migration Tasks |
| `POST` | `/api/v1/migrations/{project_id}/tasks` | Add Migration Task |
| `GET` | `/api/v1/vendor-risks` | Vendor Risks |
| `GET` | `/api/v1/vendors` | List Vendors |
| `POST` | `/api/v1/vendors` | Create Vendor |
| `POST` | `/api/v1/vendors/{vendor_id}/api-scan` | Vendor Api Scan |
| `POST` | `/api/v1/vendors/{vendor_id}/cbom` | Post Vendor Cbom |
| `POST` | `/api/v1/vendors/{vendor_id}/docs` | Post Vendor Docs |
| `GET` | `/api/v1/vendors/{vendor_id}/questionnaire` | Get Questionnaire |
| `POST` | `/api/v1/vendors/{vendor_id}/questionnaire` | Post Questionnaire |
| `GET` | `/api/v1/vendors/{vendor_id}/risk` | Vendor Risk |

## business-context

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/business-context` | Summary |
| `GET` | `/api/v1/business-context/` | Summary |
| `GET` | `/api/v1/business-context/impact` | Impact |
| `GET` | `/api/v1/business-context/priorities` | Priorities |

## cbom

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/cbom` | Cbom Catalog |
| `GET` | `/api/v1/cbom/` | Cbom Catalog |
| `POST` | `/api/v1/cbom/assess` | Cbom Assess |
| `GET` | `/api/v1/cbom/assess/portfolio` | Cbom Assess Portfolio |
| `GET` | `/api/v1/cbom/coverage` | Cbom Coverage |
| `POST` | `/api/v1/cbom/custom` | Cbom Custom |
| `POST` | `/api/v1/cbom/diff` | Cbom Diff |
| `POST` | `/api/v1/cbom/ingest` | Cbom Ingest |
| `GET` | `/api/v1/cbom/portfolio` | Cbom Portfolio |
| `POST` | `/api/v1/cbom/scan-uncovered` | Cbom Scan Uncovered |
| `GET` | `/api/v1/cbom/scan/{scan_id}` | Cbom For Scan |
| `GET` | `/api/v1/cbom/search` | Cbom Search |
| `GET` | `/api/v1/cbom/system/{system_id}` | Cbom For System |
| `POST` | `/api/v1/cbom/validate` | Cbom Validate |
| `POST` | `/api/v1/cbom/verify` | Cbom Verify |

## certificates

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/certificates/lifecycle/csr` | Lifecycle Csr |
| `POST` | `/api/v1/certificates/lifecycle/issue` | Lifecycle Issue |
| `GET` | `/api/v1/certificates/lifecycle/renewal-queue` | Renewal Queue |
| `POST` | `/api/v1/certificates/{fingerprint}/renew` | Lifecycle Renew |
| `POST` | `/api/v1/certificates/{fingerprint}/revoke` | Lifecycle Revoke |

## cloud

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/cloud/accounts` | List Accounts |
| `POST` | `/api/v1/cloud/accounts` | Create Account |
| `POST` | `/api/v1/cloud/accounts/{account_id}/inventory` | Inventory Account |
| `GET` | `/api/v1/cloud/credentials/status` | Cloud Credentials Status |
| `POST` | `/api/v1/cloud/inventory` | Inventory Cloud |
| `POST` | `/api/v1/cloud/orgs/discover` | Discover Org |
| `POST` | `/api/v1/cloud/orgs/scan` | Scan Org Endpoint |
| `POST` | `/api/v1/cloud/scan` | Scan Cloud |

## cloud-scans

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/cloud-scans` | List Cloud Scans |
| `POST` | `/api/v1/cloud-scans` | Trigger Cloud Scan |
| `GET` | `/api/v1/cloud-scans/` | List Cloud Scans |
| `POST` | `/api/v1/cloud-scans/` | Trigger Cloud Scan |

## connectors

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/connectors/sdk` | Sdk Catalog |
| `POST` | `/api/v1/connectors/sdk/validate` | Validate Connector |

## container

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/container/sbom` | Render Sbom |
| `POST` | `/api/v1/container/scan` | Scan Container |
| `GET` | `/api/v1/container/scans` | List Container Scans |
| `GET` | `/api/v1/container/scans/{scan_id}` | Get Container Scan |
| `GET` | `/api/v1/container/scans/{scan_id}/drift` | Container Scan Drift |
| `GET` | `/api/v1/container/scans/{scan_id}/metrics` | Container Scan Metrics |
| `GET` | `/api/v1/container/scans/{scan_id}/sbom` | Container Scan Sbom |
| `GET` | `/api/v1/container/scans/{scan_id}/spdx` | Container Scan Spdx |

## container-scans

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/container-scans` | List Container Scans |
| `POST` | `/api/v1/container-scans` | Trigger Container Scan |
| `GET` | `/api/v1/container-scans/` | List Container Scans |
| `POST` | `/api/v1/container-scans/` | Trigger Container Scan |
| `POST` | `/api/v1/container-scans/scan` | Trigger Container Scan |

## control-plane

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/control/agents` | List Agents |
| `POST` | `/api/v1/control/agents/enroll` | Enroll Agent |
| `POST` | `/api/v1/control/agents/heartbeat` | Agent Heartbeat |
| `POST` | `/api/v1/control/agents/{agent_id}/cert` | Rotate Agent Cert |
| `POST` | `/api/v1/control/agents/{agent_id}/config` | Configure Agent |
| `POST` | `/api/v1/control/agents/{agent_id}/upgrade` | Upgrade Agent |
| `GET` | `/api/v1/control/assets` | List Assets |
| `POST` | `/api/v1/control/assets/resolve` | Resolve Assets |
| `POST` | `/api/v1/control/authorize` | Authorize |
| `POST` | `/api/v1/control/benchmark/cases` | Add Cases |
| `POST` | `/api/v1/control/benchmark/datasets` | Create Dataset |
| `POST` | `/api/v1/control/benchmark/run-real` | Run Real Benchmark |
| `GET` | `/api/v1/control/benchmark/runs` | Benchmark Runs |
| `POST` | `/api/v1/control/benchmark/score` | Score Benchmark |
| `GET` | `/api/v1/control/credential-leases` | List Credential Leases |
| `POST` | `/api/v1/control/credential-leases/{handle}/release` | Release Credential Lease |
| `GET` | `/api/v1/control/credentials` | List Credentials |
| `POST` | `/api/v1/control/credentials` | Create Credential |
| `POST` | `/api/v1/control/credentials/{credential_id}/lease` | Lease Credential Endpoint |
| `POST` | `/api/v1/control/credentials/{credential_id}/rotate` | Rotate Credential |
| `GET` | `/api/v1/control/deliveries` | List Deliveries |
| `POST` | `/api/v1/control/deliveries/flush` | Flush Deliveries |
| `POST` | `/api/v1/control/events/enqueue` | Enqueue Event |
| `GET` | `/api/v1/control/events/queue` | Event Queue |
| `POST` | `/api/v1/control/grants` | Create Grant |
| `GET` | `/api/v1/control/health` | Control Health |
| `GET` | `/api/v1/control/me/grants` | My Grants |
| `POST` | `/api/v1/control/orchestrator/dispatch` | Dispatch |
| `POST` | `/api/v1/control/orchestrator/events/{event_id}/cancel` | Cancel Event |
| `POST` | `/api/v1/control/orchestrator/events/{event_id}/complete` | Complete Event |
| `POST` | `/api/v1/control/orchestrator/events/{event_id}/fail` | Fail Event Endpoint |
| `POST` | `/api/v1/control/orchestrator/tick` | Worker Tick Endpoint |
| `POST` | `/api/v1/control/safe-scan/emergency-stop` | Emergency Stop |
| `POST` | `/api/v1/control/safe-scan/evaluate` | Evaluate Scan Check |
| `GET` | `/api/v1/control/safe-scan/policy` | Get Safe Scan Policy |
| `PUT` | `/api/v1/control/safe-scan/policy` | Put Safe Scan Policy |
| `GET` | `/api/v1/control/tenants` | List Tenants |
| `POST` | `/api/v1/control/tenants` | Create Tenant |

## crypto

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/crypto/accuracy` | Accuracy Overview |
| `POST` | `/api/v1/crypto/live/events` | Ingest Event |
| `GET` | `/api/v1/crypto/live/risk-summary` | Risk Summary |
| `GET` | `/api/v1/crypto/live/state` | Live State |
| `GET` | `/api/v1/crypto/live/state/{asset_id}` | Asset State |
| `GET` | `/api/v1/crypto/live/timeline` | Event Timeline |
| `GET` | `/api/v1/crypto/live/{asset_id}/cbom` | Live Cbom |
| `POST` | `/api/v1/crypto/scan` | Run Scan |
| `POST` | `/api/v1/crypto/simulate` | Simulate Migration |

## crypto-assurance

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/crypto-assurance/code-rules/scan` | Code Scan |
| `POST` | `/api/v1/crypto-assurance/ct-monitor` | Ct Monitor |
| `POST` | `/api/v1/crypto-assurance/expiry-alerts` | Expiry Alerts |
| `POST` | `/api/v1/crypto-assurance/hsm-check` | Hsm Check |
| `POST` | `/api/v1/crypto-assurance/pqc-downgrade-audit` | Pqc Downgrade |
| `POST` | `/api/v1/crypto-assurance/tls-audit` | Tls Audit |
| `POST` | `/api/v1/crypto-assurance/trust-store` | Trust Store |

## data-lake

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/datalake/batches` | List Batches |
| `POST` | `/api/v1/datalake/export` | Export Batch |
| `POST` | `/api/v1/datalake/export/live` | Export Live Findings |
| `POST` | `/api/v1/datalake/verify/{batch_pk}` | Verify Stored Batch |

## devsecops

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/devsecops/chat/action` | Chat Action |
| `POST` | `/api/v1/devsecops/cloud-posture` | Cloud Posture |
| `POST` | `/api/v1/devsecops/connectors/preview` | Connector Preview |
| `POST` | `/api/v1/devsecops/container-scan` | Container Scan |
| `POST` | `/api/v1/devsecops/k8s-manifest-scan` | K8S Scan |
| `POST` | `/api/v1/devsecops/sbom/export` | Sbom Export |
| `POST` | `/api/v1/devsecops/sbom/import` | Sbom Import |
| `POST` | `/api/v1/devsecops/tickets/sync-pull` | Ticket Sync Pull |

## drift

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/drift` | List Drift |
| `GET` | `/api/v1/drift/digest` | Drift Digest |
| `POST` | `/api/v1/drift/{drift_id}/acknowledge` | Acknowledge |
| `POST` | `/api/v1/drift/{drift_id}/false-positive` | False Positive |
| `POST` | `/api/v1/drift/{drift_id}/resolve` | Resolve Drift |

## enterprise

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/enterprise/airgap/bundle` | Airgap Bundle |
| `POST` | `/api/v1/enterprise/airgap/export` | Airgap Export |
| `POST` | `/api/v1/enterprise/airgap/import` | Airgap Import |
| `POST` | `/api/v1/enterprise/compliance/controls` | Add Control |
| `POST` | `/api/v1/enterprise/compliance/evaluate` | Compliance Evaluate |
| `GET` | `/api/v1/enterprise/crypto-kb` | Crypto Kb |
| `PUT` | `/api/v1/enterprise/crypto-kb` | Put Kb Entry |
| `GET` | `/api/v1/enterprise/integrations` | List Integrations |
| `POST` | `/api/v1/enterprise/integrations` | Register Integration |
| `POST` | `/api/v1/enterprise/integrations/cmdb/resolve` | Cmdb Resolve |
| `GET` | `/api/v1/enterprise/integrations/deliveries` | Integration Deliveries |
| `POST` | `/api/v1/enterprise/integrations/siem/export` | Siem Export |
| `POST` | `/api/v1/enterprise/integrations/{integration_id}/test` | Test Integration |
| `GET` | `/api/v1/enterprise/itsm/tickets` | List Tickets |
| `POST` | `/api/v1/enterprise/itsm/tickets` | Create Ticket |
| `POST` | `/api/v1/enterprise/itsm/tickets/{ticket_id}/transition` | Transition Ticket |
| `POST` | `/api/v1/enterprise/pipeline/evaluate` | Run Findings Pipeline |
| `GET` | `/api/v1/enterprise/policies` | List Policies |
| `PUT` | `/api/v1/enterprise/policies` | Put Policy |
| `POST` | `/api/v1/enterprise/policies/evaluate` | Evaluate |
| `PUT` | `/api/v1/enterprise/regions` | Put Region |
| `GET` | `/api/v1/enterprise/regions/health` | Regions Health |

## estate

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/estate/campaigns` | Preview Campaign |
| `POST` | `/api/v1/estate/campaigns` | Start Campaign |
| `GET` | `/api/v1/estate/scans/due` | Preview Due Scans |
| `POST` | `/api/v1/estate/scans/run-due` | Run Due Scans |

## events

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/events/recent` | Recent Events |
| `GET` | `/api/v1/events/stats` | Event Stats |
| `GET` | `/api/v1/events/stream` | Stream Events |

## exceptions

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/exceptions` | List Exceptions |
| `POST` | `/api/v1/exceptions` | Create Exception |
| `POST` | `/api/v1/exceptions/expire-due` | Expire Due |
| `GET` | `/api/v1/exceptions/{exception_id}` | Get Exception |
| `POST` | `/api/v1/exceptions/{exception_id}/approve` | Approve Exception |
| `POST` | `/api/v1/exceptions/{exception_id}/reject` | Reject Exception |
| `POST` | `/api/v1/exceptions/{exception_id}/review` | Review Exception |
| `POST` | `/api/v1/exceptions/{exception_id}/revoke` | Revoke Exception |

## export

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/export/findings.csv` | Export Findings Csv |
| `GET` | `/api/v1/scans/{scan_id}/cbom` | Export Cbom |
| `GET` | `/api/v1/scans/{scan_id}/export` | Export Scan |
| `GET` | `/api/v1/scans/{scan_id}/export.csv` | Export Scan Csv |
| `GET` | `/api/v1/scans/{scan_id}/verification-script` | Export Verification Script |
| `GET` | `/api/v1/scans/{scan_id}/verify` | Verify Scan |

## findings

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/findings` | List All Findings |
| `GET` | `/api/v1/findings/{evidence_id}` | Get Finding |
| `GET` | `/api/v1/scans/{scan_id}/findings` | List Findings |

## governance

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/governance/migration` | List Validations |
| `POST` | `/api/v1/governance/migration/validate` | Validate Migration Endpoint |
| `GET` | `/api/v1/governance/requests` | List Requests |
| `POST` | `/api/v1/governance/requests` | Submit Request |
| `POST` | `/api/v1/governance/requests/{request_pk}/decide` | Decide Request |

## graph

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/graph` | Get Graph |
| `GET` | `/api/v1/graph/blast-radius` | Blast Radius |
| `GET` | `/api/v1/graph/certificates/exposure` | Graph Certificate Exposure |
| `GET` | `/api/v1/graph/compare` | Graph Compare |
| `GET` | `/api/v1/graph/compliance` | Compliance Inheritance |
| `GET` | `/api/v1/graph/crypto` | Crypto Inventory |
| `GET` | `/api/v1/graph/cycles` | Graph Cycles |
| `GET` | `/api/v1/graph/dependents` | Graph Dependents |
| `GET` | `/api/v1/graph/drift` | Get Graph Drift |
| `GET` | `/api/v1/graph/explain` | Graph Explain |
| `GET` | `/api/v1/graph/health` | Get Graph Health |
| `GET` | `/api/v1/graph/hotspots` | Graph Hotspots |
| `GET` | `/api/v1/graph/impact` | Business Impact |
| `POST` | `/api/v1/graph/migration-plan` | Graph Migration Plan |
| `GET` | `/api/v1/graph/migration-waves` | Graph Migration Waves |
| `GET` | `/api/v1/graph/path` | Graph Path |
| `POST` | `/api/v1/graph/simulate` | Graph Simulate |
| `POST` | `/api/v1/graph/snapshot` | Graph Snapshot Endpoint |
| `GET` | `/api/v1/graph/stats` | Graph Stats |
| `POST` | `/api/v1/graph/sync` | Post Graph Sync |
| `GET` | `/api/v1/graph/timeline` | Graph Timeline |
| `GET` | `/api/v1/graph/vendor-chain` | Vendor Chain |
| `GET` | `/api/v1/graph/vendor-chains` | Vendor Chains |
| `GET` | `/api/v1/graph/vendor-path` | Vendor Path |
| `GET` | `/api/v1/priorities` | Priorities |

## hardware

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/hardware/agents` | Agent Health |
| `GET` | `/api/v1/hardware/catalog` | Hardware Catalog |
| `POST` | `/api/v1/hardware/classify` | Classify Hardware Device |
| `POST` | `/api/v1/hardware/edge/sync` | Edge Sync |
| `POST` | `/api/v1/hardware/events` | Ingest Event |
| `POST` | `/api/v1/hardware/events/batch` | Ingest Events Batch |
| `GET` | `/api/v1/hardware/hbom/versions` | Hbom Versions |
| `POST` | `/api/v1/hardware/heartbeats` | Ingest Heartbeat |
| `GET` | `/api/v1/hardware/incidents` | Incidents |
| `POST` | `/api/v1/hardware/reaction-plan` | Reaction Plan |
| `GET` | `/api/v1/hardware/risk` | Risk Scores |
| `GET` | `/api/v1/hardware/state` | Live State |
| `GET` | `/api/v1/hardware/state/{asset_id}` | Asset State |
| `GET` | `/api/v1/hardware/timeline` | Event Timeline |
| `GET` | `/api/v1/hardware/timeline/state-at` | State At |

## health

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/discovery/plugins` | Discovery Plugins |
| `GET` | `/api/v1/healthz` | Healthz |
| `GET` | `/api/v1/healthz/dependencies` | Healthz Dependencies |
| `GET` | `/api/v1/healthz/schema` | Healthz Schema |
| `GET` | `/api/v1/meta` | Meta |
| `GET` | `/api/v1/readyz` | Readyz |

## intelligence

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/ci/gate` | Ci Gate |
| `GET` | `/api/v1/ci/gate-evaluations` | Ci Gate Evaluations |
| `POST` | `/api/v1/evidence-pack/verify` | Verify Pack |
| `GET` | `/api/v1/report-templates` | List Report Templates |
| `POST` | `/api/v1/report/verify` | Verify Report Signature |
| `POST` | `/api/v1/scans/import` | Import Scan Transfer |
| `GET` | `/api/v1/scans/{scan_id}/agility` | Get Agility |
| `GET` | `/api/v1/scans/{scan_id}/audit-pack` | Get Audit Pack |
| `GET` | `/api/v1/scans/{scan_id}/evidence-pack` | Get Evidence Pack |
| `GET` | `/api/v1/scans/{scan_id}/gate` | Get Gate |
| `GET` | `/api/v1/scans/{scan_id}/gate.sarif` | Get Gate Sarif |
| `GET` | `/api/v1/scans/{scan_id}/materials` | Get Materials |
| `GET` | `/api/v1/scans/{scan_id}/quantum` | Get Quantum |
| `GET` | `/api/v1/scans/{scan_id}/remediation` | Get Remediation |
| `GET` | `/api/v1/scans/{scan_id}/report` | Get Report |
| `GET` | `/api/v1/scans/{scan_id}/report.html` | Get Report Html |
| `GET` | `/api/v1/scans/{scan_id}/report.pdf` | Get Report Pdf |
| `GET` | `/api/v1/scans/{scan_id}/transfer` | Export Scan Transfer |
| `GET` | `/api/v1/scans/{scan_id}/work-orders` | Get Work Orders |

## inventory

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/inventory/assets` | List Inventory |
| `GET` | `/api/v1/inventory/summary` | Inventory Summary |

## inventory-cloud

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/inventory/cloud/assets` | List Cloud Assets |
| `POST` | `/api/v1/inventory/cloud/collect` | Collect |

## jobs

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/jobs` | List Jobs |
| `GET` | `/api/v1/jobs/{job_id}` | Get Job |
| `GET` | `/api/v1/jobs/{job_id}/logs` | Get Job Logs |
| `POST` | `/api/v1/jobs/{job_id}/retry` | Retry Job |

## live

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/live/environment` | Live Environment |
| `GET` | `/api/v1/live/orchestrator/history` | Orchestrator History |
| `POST` | `/api/v1/live/orchestrator/start` | Orchestrator Start |
| `GET` | `/api/v1/live/orchestrator/status` | Orchestrator Status |

## live-scan

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/live-scan/alerts` | Alerts |
| `GET` | `/api/v1/live-scan/bom` | Bom |
| `GET` | `/api/v1/live-scan/drift` | Drift |
| `GET` | `/api/v1/live-scan/inventory` | Inventory |
| `POST` | `/api/v1/live-scan/run` | Run Scan |
| `POST` | `/api/v1/live-scan/start` | Start Periodic |
| `GET` | `/api/v1/live-scan/status` | Status |
| `POST` | `/api/v1/live-scan/stop` | Stop Periodic |

## marketplace

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/marketplace/active/{plugin_id}` | Active Plugin |
| `GET` | `/api/v1/marketplace/plugins` | List Plugins |
| `POST` | `/api/v1/marketplace/plugins` | Upload Plugin |
| `POST` | `/api/v1/marketplace/plugins/{plugin_pk}/disable` | Disable Plugin |
| `POST` | `/api/v1/marketplace/plugins/{plugin_pk}/enable` | Enable Plugin |
| `POST` | `/api/v1/marketplace/plugins/{plugin_pk}/evaluate` | Evaluate Ruleset |
| `GET` | `/api/v1/marketplace/trusted-keys` | List Trusted Keys |
| `POST` | `/api/v1/marketplace/trusted-keys` | Add Trusted Key |
| `DELETE` | `/api/v1/marketplace/trusted-keys/{key_id}` | Remove Trusted Key |

## metrics

| Method | Path | Summary |
|---|---|---|
| `GET` | `/metrics` | Metrics |

## monitor

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/monitor/events` | Monitor Events |
| `GET` | `/api/v1/monitor/status` | Monitor Status |
| `GET` | `/api/v1/monitor/targets` | List Targets |
| `POST` | `/api/v1/monitor/targets` | Create Target |
| `PATCH` | `/api/v1/monitor/targets/{target_id}` | Update Target |
| `DELETE` | `/api/v1/monitor/targets/{target_id}` | Delete Target |
| `POST` | `/api/v1/monitor/targets/{target_id}/scan-now` | Scan Now |

## network

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/certificates` | List Certificates |
| `GET` | `/api/v1/certificates/expiry-calendar` | Certificate Expiry Calendar |
| `GET` | `/api/v1/certificates/{cert_id}` | Get Certificate |
| `POST` | `/api/v1/certificates/{cert_id}/revocation` | Check Revocation |
| `GET` | `/api/v1/certificates/{cert_id}/usages` | Certificate Usages |
| `PATCH` | `/api/v1/certificates/{fingerprint}/renewal` | Update Certificate Renewal |
| `POST` | `/api/v1/network/alerts/dispatch` | Dispatch Expiry Alerts |
| `POST` | `/api/v1/network/discover` | Discover Subnet Endpoints |
| `GET` | `/api/v1/network/drift/latest` | Latest Scan Drift |
| `GET` | `/api/v1/network/due` | List Due |
| `POST` | `/api/v1/network/metrics` | Render Metrics |
| `GET` | `/api/v1/network/protocols` | List Protocols |
| `POST` | `/api/v1/network/run-due` | Run Due |
| `GET` | `/api/v1/network/runs` | List Scan Runs |
| `GET` | `/api/v1/network/runs/{run_id}` | Get Scan Run |
| `GET` | `/api/v1/network/runs/{run_id}/metrics` | Scan Run Metrics |
| `POST` | `/api/v1/network/scan` | Scan Network |
| `POST` | `/api/v1/network/scan-path` | Scan Path |
| `POST` | `/api/v1/network/scan/drift` | Scan Drift |
| `POST` | `/api/v1/network/ssh-scan` | Scan Ssh Hosts |
| `GET` | `/api/v1/network/targets` | List Targets |
| `POST` | `/api/v1/network/targets` | Create Target |

## network-scans

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/network-scans` | List Network Scans |
| `POST` | `/api/v1/network-scans` | Trigger Network Scan |
| `GET` | `/api/v1/network-scans/` | List Network Scans |
| `POST` | `/api/v1/network-scans/` | Trigger Network Scan |

## notifications

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/notifications/catalog` | Get Catalog |
| `GET` | `/api/v1/notifications/routing` | Get Routing |
| `PUT` | `/api/v1/notifications/routing` | Put Routing |

## onboarding

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/onboarding/agent/heartbeat` | Agent Heartbeat |
| `GET` | `/api/v1/onboarding/connections` | List Connections |
| `POST` | `/api/v1/onboarding/connections` | Add Connection |
| `DELETE` | `/api/v1/onboarding/connections/{connector_id}` | Delete Connection |
| `POST` | `/api/v1/onboarding/connections/{connector_id}/test` | Test Connection |
| `GET` | `/api/v1/onboarding/discovery/runs` | List Discovery Runs |
| `POST` | `/api/v1/onboarding/discovery/start` | Start Discovery |
| `GET` | `/api/v1/onboarding/discovery/{run_id}` | Get Discovery Run |
| `POST` | `/api/v1/onboarding/environments` | Add Environment |
| `PATCH` | `/api/v1/onboarding/environments/{env_id}` | Update Environment |
| `POST` | `/api/v1/onboarding/organization` | Create Organization |
| `GET` | `/api/v1/onboarding/scope` | Get Scope |
| `POST` | `/api/v1/onboarding/scope` | Add Scope |
| `DELETE` | `/api/v1/onboarding/scope/{entry_id}` | Delete Scope |
| `GET` | `/api/v1/onboarding/state` | Onboarding State |

## ot

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/ot/devices` | List Devices |
| `GET` | `/api/v1/ot/findings` | List Findings |
| `POST` | `/api/v1/ot/metrics` | Render Ot Metrics |
| `POST` | `/api/v1/ot/scan` | Scan Ot |

## ot-safety

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/ot/maintenance-windows` | List Windows |
| `POST` | `/api/v1/ot/maintenance-windows` | Create Window |
| `POST` | `/api/v1/ot/maintenance-windows/{window_ref}/cancel` | Cancel Window |
| `POST` | `/api/v1/ot/safety/authorize` | Authorize |
| `GET` | `/api/v1/ot/safety/operations` | List Operation Classes |

## other

| Method | Path | Summary |
|---|---|---|
| `GET` | `/` | Home |
| `GET` | `/health` | Health Check |
| `GET` | `/healthz` | Healthz Root Alias |
| `GET` | `/ready` | Ready Check |
| `GET` | `/readyz` | Readyz Root Alias |

## payment-crypto

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/payment-crypto/ceremonies` | List Ceremonies |
| `POST` | `/api/v1/payment-crypto/ceremonies` | Upsert Ceremony |
| `PATCH` | `/api/v1/payment-crypto/ceremonies/{ceremony_id}` | Update Ceremony |
| `POST` | `/api/v1/payment-crypto/evaluate` | Evaluate |
| `GET` | `/api/v1/payment-crypto/findings` | List Findings |
| `POST` | `/api/v1/payment-crypto/findings/{finding_id}/status` | Set Finding Status |
| `GET` | `/api/v1/payment-crypto/forecast` | Forecast |
| `GET` | `/api/v1/payment-crypto/hsm-events` | List Hsm Events |
| `POST` | `/api/v1/payment-crypto/hsm-events` | Ingest Hsm Events |
| `GET` | `/api/v1/payment-crypto/keys` | List Keys |
| `POST` | `/api/v1/payment-crypto/keys` | Upsert Key |
| `DELETE` | `/api/v1/payment-crypto/keys/{key_id}` | Delete Key |
| `GET` | `/api/v1/payment-crypto/summary` | Summary |
| `POST` | `/api/v1/payment-crypto/transactions` | Record Transactions |
| `POST` | `/api/v1/payment-crypto/transactions/bulk` | Record Transactions Bulk |
| `GET` | `/api/v1/payment-crypto/usage` | Usage |

## platform

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/platform/blast` | Platform Blast |
| `GET` | `/api/v1/platform/bom` | Platform Bom |
| `POST` | `/api/v1/platform/discover` | Platform Discover |
| `POST` | `/api/v1/platform/drift` | Platform Drift |
| `GET` | `/api/v1/platform/evidence` | Platform Evidence |
| `POST` | `/api/v1/platform/risk` | Platform Risk |
| `GET` | `/api/v1/platform/scope` | Platform Scope |
| `POST` | `/api/v1/platform/security` | Platform Security |
| `POST` | `/api/v1/platform/whatif` | Platform Whatif |

## policy

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/policy/rules` | List Rules |

## quantum

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/quantum/mosca` | Quantum Mosca |
| `GET` | `/api/v1/quantum/plan` | Quantum Plan |

## reachability

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/reachability/blast-radius` | Blast Radius |
| `GET` | `/api/v1/reachability/compliance` | Compliance Inheritance |
| `GET` | `/api/v1/reachability/impact` | Business Impact |
| `GET` | `/api/v1/reachability/vendor-path` | Vendor Path |

## remediation

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/remediation/fix-branch` | Fix Branch |
| `GET` | `/api/v1/remediation/scans/{scan_id}/suggestions` | Scan Suggestions |
| `GET` | `/api/v1/remediation/templates` | List Templates |
| `GET` | `/api/v1/remediation/templates/{rule_id}` | Template Detail |

## report-schedules

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/report-schedules` | List Schedules |
| `POST` | `/api/v1/report-schedules` | Create Schedule |
| `GET` | `/api/v1/report-schedules/due` | Due Schedules |
| `POST` | `/api/v1/report-schedules/run-due` | Run Due Schedules |
| `PATCH` | `/api/v1/report-schedules/{schedule_id}` | Update Schedule |
| `DELETE` | `/api/v1/report-schedules/{schedule_id}` | Delete Schedule |
| `POST` | `/api/v1/report-schedules/{schedule_id}/run` | Run Schedule |
| `GET` | `/api/v1/report-snapshots` | List Snapshots |
| `GET` | `/api/v1/report-snapshots/{snapshot_id}` | Get Snapshot |
| `GET` | `/api/v1/report-snapshots/{snapshot_id}/pdf` | Get Snapshot Pdf |

## repos

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/repos` | List Repos |
| `POST` | `/api/v1/repos` | Create Repo |

## resilience

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/resilience/airgap/build-bundle` | Airgap Build |
| `POST` | `/api/v1/resilience/airgap/import-feed` | Airgap Import |
| `POST` | `/api/v1/resilience/airgap/network-decision` | Airgap Decision |
| `GET` | `/api/v1/resilience/airgap/status` | Airgap Status |
| `GET` | `/api/v1/resilience/audit/attestation` | Audit Attestation |
| `POST` | `/api/v1/resilience/audit/attestation/verify` | Audit Attestation Verify |
| `POST` | `/api/v1/resilience/backup/config` | Backup Config |
| `POST` | `/api/v1/resilience/backup/create` | Backup Create |
| `GET` | `/api/v1/resilience/backup/encryption-key-info` | Backup Key Info |
| `GET` | `/api/v1/resilience/backup/list` | Backup List |
| `POST` | `/api/v1/resilience/backup/restore` | Backup Restore |
| `POST` | `/api/v1/resilience/backup/retention-plan` | Retention Plan |
| `POST` | `/api/v1/resilience/backup/run-scheduled` | Backup Run Scheduled |
| `POST` | `/api/v1/resilience/backup/sweep` | Backup Sweep |
| `POST` | `/api/v1/resilience/compliance-report` | Compliance Report |
| `POST` | `/api/v1/resilience/ot/decode` | Ot Decode |
| `POST` | `/api/v1/resilience/ot/ingest-pcap` | Ot Ingest Pcap |

## risk

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/risk/unified` | Unified Inventory Risk |

## runtime

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/scans/runtime-findings` | List Runtime Findings |
| `POST` | `/api/v1/scans/runtime-findings` | Ingest Runtime Findings |

## saas

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/saas/admin/tenants` | Admin List Tenants |
| `POST` | `/api/v1/saas/admin/tenants/{tenant_id}/plan` | Admin Set Plan |
| `POST` | `/api/v1/saas/admin/tenants/{tenant_id}/restore` | Admin Restore |
| `POST` | `/api/v1/saas/admin/tenants/{tenant_id}/suspend` | Admin Suspend |
| `GET` | `/api/v1/saas/members` | List Members |
| `POST` | `/api/v1/saas/members` | Add Member |
| `DELETE` | `/api/v1/saas/members/{username}` | Remove Member |
| `POST` | `/api/v1/saas/signup` | Signup |
| `GET` | `/api/v1/saas/usage` | Usage |
| `GET` | `/api/v1/saas/whoami` | Whoami |

## scans

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/scans` | List Scans |
| `GET` | `/api/v1/scans/{scan_id}` | Get Scan |
| `POST` | `/api/v1/scans/{scan_id}/retry` | Retry Scan |

## scim

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/scim/v2/ServiceProviderConfig` | Service Provider Config |
| `GET` | `/api/v1/scim/v2/Users` | List Users |
| `POST` | `/api/v1/scim/v2/Users` | Create User |
| `GET` | `/api/v1/scim/v2/Users/{username}` | Get User |
| `PATCH` | `/api/v1/scim/v2/Users/{username}` | Patch User |
| `DELETE` | `/api/v1/scim/v2/Users/{username}` | Delete User |

## scope

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/scope/authorize` | Authorize |
| `GET` | `/api/v1/scope/authorize-batch` | Authorize Batch |
| `GET` | `/api/v1/scope/envelope` | Scope Envelope |
| `GET` | `/api/v1/scope/tenant/isolation` | Tenant Isolation |

## sectors

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/sectors` | List Sectors |
| `POST` | `/api/v1/sectors/compliance-map` | Compliance Map |
| `POST` | `/api/v1/sectors/context` | Sector Context |
| `POST` | `/api/v1/sectors/criticality` | Score Criticality |
| `GET` | `/api/v1/sectors/organization/active` | Get Active Sector |
| `PUT` | `/api/v1/sectors/organization/active` | Set Active Sector |
| `GET` | `/api/v1/sectors/quantum-risk` | Sector Quantum Risk |
| `GET` | `/api/v1/sectors/scan-modes` | List Scan Modes |
| `GET` | `/api/v1/sectors/{sector_id}` | Get Sector |

## security

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/security/alerts` | Security Alerts |
| `POST` | `/api/v1/security/gate` | Evaluate Gate |
| `POST` | `/api/v1/security/intelligence/chain` | Build Risk Chain |
| `POST` | `/api/v1/security/intelligence/correlate` | Correlate Findings |
| `POST` | `/api/v1/security/intelligence/identity/resolve` | Resolve Asset Identity |
| `POST` | `/api/v1/security/intelligence/schedule` | Resolve Schedule |
| `POST` | `/api/v1/security/intelligence/state` | Asset State |
| `GET` | `/api/v1/security/policy` | Get Scan Policy |
| `PUT` | `/api/v1/security/policy` | Put Scan Policy |
| `GET` | `/api/v1/security/posture` | Get Security Posture |
| `GET` | `/api/v1/security/posture/history` | List Security Posture History |
| `GET` | `/api/v1/security/posture/stream` | Posture Stream |
| `GET` | `/api/v1/security/posture/trend` | Posture Trend |
| `GET` | `/api/v1/security/profiles` | List Scan Profiles |
| `POST` | `/api/v1/security/profiles/resolve` | Resolve Scan Profile |

## sla

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/sla/evaluate` | Evaluate |
| `GET` | `/api/v1/sla/policy` | Sla Policy |

## sso

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/auth/ldap/login` | Ldap Login |
| `POST` | `/api/v1/auth/saml/acs` | Saml Acs |
| `GET` | `/api/v1/auth/saml/login` | Saml Login |
| `GET` | `/api/v1/auth/saml/metadata` | Saml Metadata |
| `GET` | `/api/v1/auth/saml/status` | Saml Status |
| `GET` | `/api/v1/auth/sso/status` | Sso Status |

## stats

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/stats/summary` | Summary |

## systems

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/systems` | List Systems |
| `POST` | `/api/v1/systems` | Create System |
| `POST` | `/api/v1/systems/import` | Import Systems |
| `GET` | `/api/v1/systems/{system_id}` | Get System |
| `PATCH` | `/api/v1/systems/{system_id}` | Update System |
| `POST` | `/api/v1/systems/{system_id}/assets` | Attach Asset |
| `POST` | `/api/v1/systems/{system_id}/dependencies` | Add Dependency |
| `POST` | `/api/v1/systems/{system_id}/scan` | Scan System |

## technology-bom

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/technology-bom` | Technology Bom Live |
| `GET` | `/api/v1/technology-bom/` | Technology Bom Live |
| `GET` | `/api/v1/technology-bom/admission` | Technology Bom Admission |
| `GET` | `/api/v1/technology-bom/assurance` | Technology Bom Assurance |
| `GET` | `/api/v1/technology-bom/compare` | Technology Bom Compare |
| `GET` | `/api/v1/technology-bom/evidence-package` | Evidence Package |
| `GET` | `/api/v1/technology-bom/export` | Technology Bom Export |
| `GET` | `/api/v1/technology-bom/export-runs` | List Export Runs |
| `GET` | `/api/v1/technology-bom/export-schedules` | List Export Schedules |
| `POST` | `/api/v1/technology-bom/export-schedules` | Create Export Schedule |
| `POST` | `/api/v1/technology-bom/export-schedules/run-due` | Run Due Export Schedules |
| `GET` | `/api/v1/technology-bom/export-schedules/{schedule_id}` | Get Export Schedule |
| `PUT` | `/api/v1/technology-bom/export-schedules/{schedule_id}` | Update Export Schedule |
| `DELETE` | `/api/v1/technology-bom/export-schedules/{schedule_id}` | Delete Export Schedule |
| `POST` | `/api/v1/technology-bom/export-schedules/{schedule_id}/run` | Run Export Schedule |
| `GET` | `/api/v1/technology-bom/history` | Technology Bom History |
| `GET` | `/api/v1/technology-bom/history/versions` | Technology Bom Versions |
| `GET` | `/api/v1/technology-bom/runtime-verify` | Technology Bom Runtime Verify |
| `POST` | `/api/v1/technology-bom/snapshot` | Technology Bom Snapshot |
| `GET` | `/api/v1/technology-bom/vendor` | Vendor Inventory |
| `GET` | `/api/v1/technology-bom/vex` | Technology Bom Vex |
| `GET` | `/api/v1/technology-bom/xbom` | Technology Bom Xbom |

## telecom

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/telecom/carriers` | Telecom Carrier Add |
| `DELETE` | `/api/v1/telecom/carriers/{code}` | Telecom Carrier Delete |
| `GET` | `/api/v1/telecom/events` | Telecom Events |
| `POST` | `/api/v1/telecom/ingest` | Telecom Ingest |
| `GET` | `/api/v1/telecom/journey` | Telecom Journey |
| `GET` | `/api/v1/telecom/pack` | Telecom Carrier Pack |
| `GET` | `/api/v1/telecom/posture` | Telecom Posture |
| `GET` | `/api/v1/telecom/registry` | Telecom Registry |
| `GET` | `/api/v1/telecom/roadmap` | Telecom Roadmap View |
| `GET` | `/api/v1/telecom/roaming` | Telecom Roaming |
| `POST` | `/api/v1/telecom/roaming-partners` | Telecom Roaming Partner Add |
| `DELETE` | `/api/v1/telecom/roaming-partners/{pid}` | Telecom Roaming Partner Delete |
| `POST` | `/api/v1/telecom/scan` | Telecom Scan |
| `POST` | `/api/v1/telecom/targets` | Telecom Target Add |
| `DELETE` | `/api/v1/telecom/targets/{nf_id}` | Telecom Target Delete |

## trigger

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/scans/trigger` | Trigger Manual Scan |

## vulnerabilities

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | List Vulnerabilities |
| `GET` | `/api/v1/vulnerabilities/` | List Vulnerabilities |
| `GET` | `/api/v1/vulns` | List Vulns |

## webhooks

| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/webhooks/acr` | Container Registry Webhook |
| `POST` | `/api/v1/webhooks/container` | Container Registry Webhook |
| `POST` | `/api/v1/webhooks/dockerhub` | Container Registry Webhook |
| `POST` | `/api/v1/webhooks/ecr` | Container Registry Webhook |
| `POST` | `/api/v1/webhooks/gcr` | Container Registry Webhook |
| `POST` | `/api/v1/webhooks/github` | Github Webhook |
| `POST` | `/api/v1/webhooks/harbor` | Container Registry Webhook |

## workload-identity

| Method | Path | Summary |
|---|---|---|
| `GET` | `/api/v1/workload/ca` | Ca Bundle |
| `POST` | `/api/v1/workload/svid` | Issue Svid |
| `POST` | `/api/v1/workload/verify` | Verify Svid |
