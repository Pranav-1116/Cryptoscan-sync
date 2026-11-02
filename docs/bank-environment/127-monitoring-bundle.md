# The monitoring bundle — do the parts connect?

`cryptoscan.monitoring-bundle/1` · generated 2026-11-02T10:49:46.198303+00:00 · **3 pass · 0 partial · 0 fail**

Guide 117 proved the delivery half of alerting by hand: a real rule, a real webhook-v4 notification, a counted series. What it left open is whether a deployed stack contains anything that posts. `infra/monitoring` had a Prometheus config with an `alerting:` stanza and an `alerts.yml` full of rules, and no compose file ran either process.

| Question | Verdict | What was measured |
|---|---|---|
| **does the stack that ships start the processes its configs describe?** | **PASS** | 22 probe(s), all passing |
| **does Prometheus reach Alertmanager, and Alertmanager reach a route the API serves?** | **PASS** | 8 probe(s), all passing |
| **is the token Alertmanager sends the token the API validates?** | **PASS** | 8 probe(s), all passing |

### `compose_wiring` — PASS

*does the stack that ships start the processes its configs describe?*

- **PASS** `service-prometheus-exists` — the overlay defines `prometheus`
- **PASS** `prometheus-image-pinned` — image is ${PROMETHEUS_IMAGE:-prometheus/prometheus:v2.53.2}
- **PASS** `prometheus-no-host-port` — publishes no host port; reach it through the bank's proxy
- **PASS** `prometheus-no-new-privileges` — security_opt=['no-new-privileges:true']
- **PASS** `prometheus-has-healthcheck` — healthcheck present
- **PASS** `prometheus-restart-policy` — restart='unless-stopped'
- **PASS** `service-alertmanager-exists` — the overlay defines `alertmanager`
- **PASS** `alertmanager-image-pinned` — image is ${ALERTMANAGER_IMAGE:-prometheus/alertmanager:v0.27.0}
- **PASS** `alertmanager-no-host-port` — publishes no host port; reach it through the bank's proxy
- **PASS** `alertmanager-no-new-privileges` — security_opt=['no-new-privileges:true']
- **PASS** `alertmanager-has-healthcheck` — healthcheck present
- **PASS** `alertmanager-restart-policy` — restart='unless-stopped'
- **PASS** `prometheus-config-mounted` — mounted at /etc/prometheus/prometheus.yml
- **PASS** `prometheus-config-read-only` — mount mode is ro
- **PASS** `rules-mounted` — mounted at /etc/prometheus/rules/alerts.yml
- **PASS** `rules-read-only` — mount mode is ro
- **PASS** `alertmanager-config-mounted` — mounted at /etc/alertmanager/alertmanager.yml
- **PASS** `alertmanager-config-read-only` — mount mode is ro
- **PASS** `rule_files-match-the-mount` — every rule_files entry is a mounted path
- **PASS** `receiver-credential-file-mounted` — credentials_file ['/etc/alertmanager/secrets/webhook_token'] is mounted
- **PASS** `metrics-token-file-mounted` — bearer_token_file ['/etc/prometheus/secrets/metrics_token'] is mounted
- **PASS** `secrets-from-one-directory` — both services read their token from ${MONITORING_SECRETS_DIR}, one source

### `config_chain` — PASS

*does Prometheus reach Alertmanager, and Alertmanager reach a route the API serves?*

- **PASS** `alertmanager-listens-on-a-known-port` — --web.listen-address=0.0.0.0:9093
- **PASS** `prometheus-alerting-target` — Prometheus sends to ['alertmanager:9093']
- **PASS** `prometheus-depends-on-alertmanager` — depends_on={'api': {'condition': 'service_started'}, 'alertmanager': {'condition': 'service_started'}}
- **PASS** `receiver-url-is-a-served-route` — receiver URL(s) resolve: ['/api/v1/ops/alerts/alertmanager']
- **PASS** `every-route-names-a-real-receiver` — every route receiver is defined
- **PASS** `every-rule-severity-resolves-to-a-receiver` — each rule severity resolves: critical->cryptoscan-platform, high->cryptoscan-platform, medium->cryptoscan-platform
- **PASS** `no-paging-severity-is-silenced` — informational alerts are routed to the null receiver; nothing that should page is
- **PASS** `rules-file-has-rules` — 15 rule(s) in alerts.yml

### `secret_wiring` — PASS

*is the token Alertmanager sends the token the API validates?*

- **PASS** `token-file-is-rendered` — webhook_token exists with 64 character(s)
- **PASS** `token-length-meets-the-api-floor` — 64 character(s); the API requires 32
- **PASS** `token-is-documented-in-the-production-template` — ALERTMANAGER_WEBHOOK_TOKEN is in .env.production.example
- **PASS** `production-template-keeps-the-two-tokens-apart` — the template leaves both blank; one read-only scrape credential and one inbound write credential must never be the same value
- **PASS** `right-token-is-accepted` — a notification carrying the rendered token answers 200
- **PASS** `wrong-token-is-refused` — a token one character off answers 401
- **PASS** `missing-token-is-refused` — no Authorization header answers 401
- **PASS** `unset-token-fails-closed` — a production process with no token configured answers 503 rather than accepting the notification

## The negative control

The same checks run against a copy of the bundle with exactly one defect injected. Each defect must make the row that watches for it stop passing:

| Injected defect | Row | Result |
|---|---|---|
| prometheus.yml points at localhost instead of the Alertmanager service | config_chain | config_chain=FAIL (caught) |
| alertmanager.yml posts to a path the API does not serve | config_chain | config_chain=FAIL (caught) |
| the overlay stops mounting alertmanager.yml | compose_wiring | compose_wiring=FAIL (caught) |
| the rendered token is below the API's 32-character floor | secret_wiring | secret_wiring=FAIL (caught) |
| the critical sub-route sends paging alerts to the null receiver | config_chain | config_chain=FAIL (caught) |

Every injection was caught.

## How to run it

```sh
# one env var per token, both at least 32 characters
python3 scripts/render_monitoring_secrets.py
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
               -f docker-compose.monitoring.yml up -d
```

## What this does not prove

- no Prometheus or Alertmanager process is started here: the bundle is read, cross-checked and its token path executed through the API's own dependency, but container start-up, scrape timing, rule evaluation and Alertmanager grouping are the bank's to observe
- image tags are pinned but their contents were not audited; a bank that requires signed images substitutes its own registry
- the healthcheck command was not executed inside the upstream images

**The verdict this bundle supports:** the stack that ships actually contains the processes the configs describe, Prometheus is pointed at the Alertmanager this overlay starts, Alertmanager posts to a route the API serves, and the token it sends is the token the API validates — proven by calling the API's own dependency with it. What is not proven is that a bank's Alertmanager evaluates, groups and retries correctly: that is the layer the bank configures and observes.
