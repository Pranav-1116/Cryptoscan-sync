# Runbook — Measure traffic/storage, then review a control draft

[Guide](../bank-environment/86-network-traffic-storage-and-control.md) · [API](../api-reference/resource-monitoring.md) · [Engineering evidence](../readiness-evidence/resource-monitoring-2026-10-26.md).

## 1. Agree exactly what to measure

Identify the existing estate/system/environment and intended Linux operator host. Decide which interfaces and directory filesystems are in scope. Do not infer these from the API server's machine, scan a subnet or collect every mount automatically. Use local filesystem paths where possible; unhealthy remote filesystem calls can stall.

The collector supports ordinary-user Linux, not native Windows/router/cloud resources. It measures namespace interface totals and filesystem capacity, not per-app/IP flows, RAM or physical storage pools. It never captures packets or changes configuration.

## 2. Register and approve in the UI

1. Open **Network → Traffic & storage**.
2. Expand **Register an explicit collection scope**; enter system ID/environment, operator host label, exact comma-separated interfaces and one absolute directory path per line. Choose 1–30 seconds. The UI requests a 30-minute window.
3. Register the scope: this is only a draft.
4. A current authorized reviewer selects the scope, records a change reference/reason and approves. The server checks `assurance.trust`; a button is not authority.
5. Download the approved scope JSON and retain its displayed `plan_record_sha256` separately through the approved channel. Do not edit the file or assume the public nonce proves source identity.

Use the API for explicit revocation, alternative windows and further list pages. Scope/system changes require a newly registered/approved scope; existing evidence is immutable.

## 3. Run the collector on the intended host

Use a trusted checkout/release and Python dependencies. **No sudo**, no credentials/private keys in chat, no caller-supplied commands. Save the downloaded authorization on the intended Linux host and choose a new absolute output filename whose parent already exists:

```bash
python scripts/collect_resources.py collect \
  --authorization /absolute/approved-scope.json \
  --approved-record-sha256 APPROVED_RECORD_SHA256 \
  --output /absolute/new-resource-capture.json
```

Replace placeholders with the actual scope file/hash. The file hash parameter is the original approval revision hash in that authorization, not a pretty-file checksum. The collector checks exact commitment, time window, Linux/non-root execution, fixed proc sources and stable boot/namespace context.

- Exit **0**: every selected input measured; still not whole-host completeness/authenticity.
- Exit **2**: a retained capture contains gaps/reset/identity-change dispositions; inspect it, do not treat them as zeros.
- Exit **64**: refused/invalid capture; no successful receipt. Output never overwrites an existing file and is created mode 0600.

The CLI prints `RESOURCE_CAPTURE_SHA256=…`: retain that canonical typed digest for import. Counter rates use monotonic sampling, not a caller's bandwidth estimate. Root/capability escalation, filesystem cleanup and network configuration are not remedies for a gap.

## 4. Inspect offline if needed

```bash
python scripts/collect_resources.py report \
  --capture /absolute/new-resource-capture.json \
  --expected-capture-sha256 CAPTURE_SHA256 \
  --output /absolute/new-resource-report.json
```

This reconstructs a report without re-reading targets. It does not authenticate original collection, approve a policy or apply a rule. Use a new output name; existing files and symlinks are refused.

## 5. Import and review

In the Network panel, expand **Import the operator capture**, select the capture JSON and paste its CLI digest. Import does not run collection. Alternatively POST the exact model/digest to `/api/v1/resource-monitoring/captures`.

Inspect capture time, host label, namespace context and dispositions. UI refresh shows retained samples, not an active live feed. Samples older than five minutes are marked stale for drafting. Switching estate/auth clears private values and pending responses; stale data must not carry into another estate.

- Measured `0 Mbps`: idle valid counter pair, not a failed probe.
- Reset/missing/denied: unknown rate; investigate authorized interface/source access.
- Storage total/free/available: filesystem values, not separate physical disks. Do not add multiple paths. Reservations are not used bytes. No quota/RAID/SAN capacity claim follows.
- Error/drop delta: driver/interface counter, not proven end-to-end loss.

GET the retained record to revalidate the source/report. A mismatch is an integrity refusal, not a reason to edit/reseal stored JSON. Scope revocation blocks new intake/proposals but does not erase historical evidence.

## 6. Draft a traffic limit — never mistake it for enforcement

Select a measured interface, explicit egress Mbps and reason, then **Save draft limit (not apply)**. The server requires a fresh capture/current scope and retains the original evidence hashes. The response explicitly says NOT APPLIED.

Before implementing enforcement, identify **Linux server/gateway, router/firewall model, or cloud provider**. Agree management/control-plane exclusions, owner, approval, intended duration, existing-policy conflict handling, rollback and a disposable validation target. Do not apply a blanket bandwidth limit to the management interface or turn a firewall allow/deny rule into a claimed rate cap.

This release has no apply endpoint, privileged agent, `tc` command, firewall modification, ingress shaper or cloud-policy writer. There is no automatic traffic blocking or 24/7 resource scheduler. Those are distinct next steps, not hidden behavior behind the draft button.

## Engineering tests

Use a disposable checkout/copy before reproducing retained logs. With repository/service/shared roots and `services/api/tests/unit` on `PYTHONPATH`:

```bash
python -m pytest shared/shared_models/tests/test_resource_monitoring.py \
  services/inventory/tests/test_resource_monitoring.py \
  services/api/tests/unit/test_resource_monitoring_api.py -q
python docs/readiness-evidence/resource-monitoring-2026-10-26/run-owned-postgres.py
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
npm test -- src/components/ResourceMonitoring.test.tsx src/lib/api.test.ts
```

The optional test-only `CRYPTOSCAN_RESOURCE_WITNESS_DIR` retains actual read-only **sandbox** capture/record/scope artifacts from the native case; it is not customer capture authorization. The PostgreSQL helper creates/stops/removes its own disposable server/databases and never uses an existing customer DB URL. No actual router/customer rule or bank traffic limit is applied by these tests.
