# 05 — How to deploy CryptoScan on premises

[FAQ index](README.md) · Questions Q049–Q060.

## Q049. What is the current on-premises reference architecture?

The controlled reference is **`kubernetes-external-services/local-source-v1`**:

```text
Bank workstation → internal HTTPS ingress → frontend → private API
                                                      │
                       regional PostgreSQL + TLS Redis + worker
                                                            │
                                                isolated source parser
                                                no network / no secrets
```

The bank also supplies approved source storage/transfer, a private registry, DNS/PKI, secret custody, restricted operations and recovery facilities. API, worker and parser are distinct trust roles. This is a reference engineering profile requiring actual site qualification—not a pre-approved turnkey bank deployment.

## Q050. Can the bank deploy using Docker Compose or one VM?

Compose/SQLite/inline-parser examples are for development, not a shortcut to the controlled bank profile. Bank-owned VMs may host the approved Kubernetes and worker infrastructure, but a VM alone is not the complete supported topology.

Do not claim that a single container or host automatically supplies isolation, shared durable authority, backup, HA or tenant separation. Follow the reviewed runtime/worker/daemon assumptions and record site deviations for explicit engineering/security review.

## Q051. Why are PostgreSQL and Redis called “external” services?

External means outside the application workloads, **not outside the bank**. They may be bank-managed services inside the same approved data centre/region.

PostgreSQL holds durable application/evidence/authority state; Redis is used by relevant queue/shared limiting and other consumers. Each needs the correct approved endpoint, TLS/CA verification, least-privilege roles, persistence, backup/recovery and capacity. Do not configure an internet database or unencrypted Redis simply to satisfy a template, and do not assume one healthy consumer proves every consumer is configured correctly.

## Q052. What infrastructure and data must be ready before installation?

Have approved values for cluster/context/namespace, dedicated reviewed worker/runtime, storage/staging paths, registry and exact image digests, internal DNS/HTTPS origin, database/Redis endpoints and CAs, source root/PVC permissions, configuration/secrets, monitoring and backup destination.

Also assign actual owners, scope, residency, retention, release/change authority and acceptance tests. Templates contain placeholders; never invent image digests, public keys, customer IDs or approval records to make validation pass. Do first-use/fault/migration experiments in disposable pre-production infrastructure, not the live bank database.

## Q053. What are the recommended deployment steps?

1. Agree the supported profile, exact release, site architecture and exclusions.
2. Provision reviewed infrastructure, dependency roles, storage, network policy and secrets.
3. Transfer verified compatible artifacts to the bank's private registry/storage.
4. Render/review site configuration using the operator profile/runbook; validate required explicit pins.
5. Take the required consistent backup/checkpoint and perform the approved coordinated migration/install.
6. Verify HTTPS/authentication, dependency TLS, admission refusals and correct tenant/region.
7. Run an authorized bounded source journey and negative/cleanup/recovery tests.
8. Obtain separate site/security/customer acceptance and hand over to named operators.

This is a sequence, not a copy-paste production command set. Use the current operator runbook for exact version-compatible commands and evidence; a documentation update does not execute these steps.

## Q054. Can CryptoScan run in an air-gapped bank?

Offline acquisition and bank-controlled transfer are useful options. An air-gap installation still needs all compatible images/packages, certificates, approved feeds and dependencies available inside the boundary, with reviewed media/import/export procedures.

Treat `AIRGAP_MODE` and legacy bundle tooling as application mechanisms, not proof of zero egress from every process/library/runtime. Enforce isolation at the bank network/host boundary, test the exact release, and verify that any offline feed/export route is admitted by the selected profile. No public registry, update service or AI service should be contacted merely because a development example does so.

## Q055. What CPU, memory and storage does the bank need?

There is no qualified universal “bank size” number. Size against source/artifact count and bytes, parser cost, concurrency, history/evidence growth, database I/O, queue behavior, staging expansion, logs and recovery targets.

Reference CPU/memory/PID settings are starting examples, not throughput guarantees. Include node/daemon child workloads, system overhead and safety margin—not only pod requests. Agree representative workloads and operating limits before measuring; test maximum-admitted and refused inputs. Do not turn synthetic/local regression timings into a customer capacity or latency SLA.

## Q056. How are certificates, secrets and encryption handled?

Separate nonsecret configuration from bank-managed secret custody. Use approved ingress certificates and dependency CAs with hostname verification; restrict access to runtime and migration credentials. Protect application/evidence storage, backups, keys and cluster secret handling under the bank's policy.

A Kubernetes Secret object, `rediss://` string or encryption checkbox alone does not prove correct custody, rotation, encryption at rest or restore ability. Verify mounts, trust chains, expiry, ACLs and fail-closed negatives at the actual site. Never put live secrets into Git, support chat or public readiness artifacts.

## Q057. Does on-premises deployment mean no data can leave the bank?

Physical location alone is not an egress guarantee. Review browser assets, telemetry, vulnerability-feed updates, registry access, integrations, logs, exports, backups and support access. Restrict and test the actual flows; minimize sensitive content and define transfer/retention rules.

No external AI processing or vendor upload should be assumed authorized. A development integration's existence does not enable it in production. A valid hash/signature does not grant permission to export data or override residency restrictions.

## Q058. How are upgrades, migrations and rollback managed?

Use a bank-approved change with exact compatible images/configuration/schema, backups, migration checks, release verification and post-change evidence. Coordinate API/worker/dependency compatibility; do not run an arbitrary `latest` image or blind schema downgrade.

Some state cannot be safely reversed by relabeling jobs or deleting uncertainty. Preserve UNKNOWN work/evidence and follow the current reconciliation/recovery runbook. Test restore and rollback limits on a representative copy before go-live; retaining a backup file is not proof of recovery.

## Q059. Is high availability provided automatically by Kubernetes?

No. The reference API/worker deployments use one replica; restart behavior is not witnessed HA. More replicas can change worker authority, shared budgets, queues, rate windows, database load and recovery behavior.

HA, automatic failover, multi-region active/active and zero-downtime upgrades need a reviewed topology, actual failure exercises and accepted recovery objectives. Never increase replica counts or market those properties solely because a manifest can be edited.

## Q060. What must be checked before the bank calls the installation live?

Verify the exact profile/release, authorized happy path and refusal paths; current identity/estate/region; dependency TLS/roles; parser network/secret/socket isolation; resource/cancellation/cleanup behavior; evidence integrity/export permissions; backup/restore/reconciliation; monitoring; and named escalation/operating owners.

Record unresolved gaps and scope them out or block acceptance. Software running, a green health endpoint or passing local tests is not a substitute for independent security and bank acceptance of the actual site.

### References

[On-premises architecture and worksheet](../BANK-ON-PREMISES-DEPLOYMENT.md) · [exact operator runbook](../runbooks/operator-install-upgrade-recover.md) · [site template](../../deploy/operator-profile/site.example.yaml) · [controlled upgrade/admission](../runbooks/controlled-execution-upgrade.md) · [measured workloads](../bank-environment/55-measured-workloads-and-capacity-limits.md)
