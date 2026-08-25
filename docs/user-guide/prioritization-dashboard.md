# Prioritization dashboard

`/business` ranks assets by `priority_score`:

`score = revenue_daily * 0.4 + customers * 0.0001 + compliance_fail * 80 + severity * 0.3`

P0 is anything with a compliance FAIL on a revenue-generating process, or a very large raw score. Sort the table by revenue or customer impact before opening a migration.
