# Business context setup

1. Create owners (`POST /api/v1/business/owners`).
2. Create processes with `revenue_daily`, `customer_count`, and `sla_uptime`.
3. Map systems to processes.
4. After a scan the worker enrichment stage writes `business_context` onto each crypto asset (revenue at risk, owners, priority P0/P1/P2).

P0 findings render the owner email template; findings with ≥ $1M/day also render the executive template.
