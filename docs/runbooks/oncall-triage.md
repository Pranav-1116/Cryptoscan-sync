# On-call triage

The paging rules are in [`infra/monitoring/prometheus/alerts.yml`](../../infra/monitoring/prometheus/alerts.yml).
Every alert below names a first question and a first command. If you are reading
this during an incident, start with the alert's name; if the API is not being
scraped at all, skip to **CryptoscanApiDown**.

Two things are true of this platform and change how you triage:

- **The API's own alert feed is not the pager.** `/ops/alerts` evaluates rules
  inside the API process, which is exactly the thing that fails first. Prometheus
  owns paging; treat `/ops/alerts` as detail once you are already awake.
- **Readiness is dependency-aware, liveness is not.** `/readyz` returns 503 when
  the database or Redis is unreachable, and that removes pods from rotation.
  `/healthz` only says the process is alive, so a pod that answers `/healthz`
  and fails `/readyz` is *not* serving — do not restart it, look at the
  dependency.

## First five minutes

```bash
kubectl -n cryptoscan get pods -o wide                 # who is not ready, and since when
kubectl -n cryptoscan rollout history deploy/cryptoscan-api
curl -sS -o /dev/null -w '%{http_code}\n' https://<console>/readyz
curl -sS -H "Authorization: Bearer $METRICS_TOKEN" https://<console>/metrics | head -40
```

Record the timeline as you go: alert time, first action, evidence. The drill and
the post-incident review both depend on those timestamps, not on memory.

## CryptoscanApiDown / CryptoscanScrapeTargetMissing

1. `kubectl -n cryptoscan get pods` — are the API pods `Running` but not
   `Ready`? Readiness failing is a dependency problem, not an API problem.
2. `kubectl -n cryptoscan logs deploy/cryptoscan-api --tail=200` — a boot
   refusal is deliberate and verbose (the production gate names the setting it
   rejected). Do not "fix" it by loosening `ENVIRONMENT`.
3. Check the scrape path itself: does Prometheus reach `api:8010`? A changed
   `METRICS_TOKEN` looks identical to an outage from the outside.
4. If the whole tier is gone: check node pressure, the PodDisruptionBudget
   blocking a drain, and image pull errors.

Never restart pods to "clear" an alert that says readiness is failing: the
replacement pod inherits the same broken dependency and you lose the logs.

## CryptoscanAvailabilityBudgetBurnHigh / CryptoscanServerErrorRate

1. Which class of request? `sum by (status) (rate(http_requests_total[5m]))`
   and `sum by (method) (rate(http_server_errors_total[5m]))`.
2. `curl /readyz` and check the database: connection exhaustion and long-running
   migrations both surface as 5xx, and their fixes are opposite.
3. Correlate with the last deployment and the last migration
   (`scripts/operator_release.py` records the migration head). A 5xx spike
   starting within minutes of a rollout is a rollback decision, not a debugging
   decision — the rollback plan is in `docs/ops/production-checklist.md`.
4. For an error budget: the alert fires at 14.4× burn, meaning the hourly budget
   is gone in about five minutes. Decide early between rollback and fix-forward;
   do not let the budget drain while you read code.

## CryptoscanLatencyP99High

1. Is the database the bottleneck? Look at query time and at the number of
   running scan jobs (`MAX_CONCURRENT_JOBS`, worker replicas).
2. A p99 increase with a flat error rate and flat throughput is usually a slow
   dependency; an increase with *rising* throughput is capacity.
3. Do not raise the 500 ms SLO to silence the alert. If the target was wrong,
   that is a reviewed change to `DEFAULT_SLOS` plus this file, not a hotfix.

## CryptoscanNoTraffic

The API is up and answering nothing. Check, in order: ingress (`kubectl -n
cryptoscan describe ingress cryptoscan`), DNS, the TLS secret expiry
(`openssl s_client -connect <host>:443 | openssl x509 -noout -dates`), and
whether a `whitelist-source-range` annotation is rejecting your callers. This
alert exists because an outage with zero traffic produces a perfect error rate.

## CryptoscanRateLimitStorm

429s mean the limiter is working, not that it is broken. Identify the identity:
the bucket key is an API-key digest, a session user, or the resolved client IP
(see `api/security/client_ip.py`). A storm from one key is a runaway integration
— rotate or revoke the key. A storm from *many* IPs is either real load or an
attack; check whether `TRUSTED_PROXY_CIDRS` matches the real ingress network,
because a misconfigured proxy boundary collapses every caller into one bucket.

## Escalation boundaries

This runbook restores service. It does not authorise: data restoration (see
[backup-restore](../admin-guide/backup-restore.md)), secret rotation (see
`scripts/rotate_secrets.py`), or anything that changes evidence. Those need the
approvals in `docs/ops/production-checklist.md`, and a restore needs the
measured numbers from `scripts/pitr_drill.py`, not an estimate.
