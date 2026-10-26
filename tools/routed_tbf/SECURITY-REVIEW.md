# Build/update and external-review gate

**Status: pending independent review; not production/security-qualified.**
This repository supplies review tooling, not a staffed security/SLA service.
An accountable release/security owner and independent reviewer must be appointed;
neither identity nor completion is invented here.

## Before any binary distribution or real adapter promotion

1. Reconcile every source/binary/runtime with its upstream origin and authenticity
   evidence. Hash pinning alone is not upstream provenance verification. QEMU is
   a prebuilt npm artifact; the package lacks a discovered license file in this
   inventory. Treat its licensing/transitive-library obligations as **UNKNOWN**
   until documented, even if registry metadata supplies a license label.
2. Review discovered license text, bundled libraries and copied Debian runtime
   components. Resolve source-offer/redistribution/notice obligations, including
   custom GNU compatibility and musl signal changes. The current archive inventory
   is not a complete transitive SBOM or legal approval. No binaries are published
   by this increment.
3. Review the fixed kernel/QEMU/musl/bootstrap/runtime versions against trusted
   advisory feeds and vendor notices. Unknown advisory coverage blocks release;
   “no known issues” must not be substituted for an unperformed review.
4. Independently review `sandbox.c`, private musl four-site tgkill patch, launcher
   resource bounds, guest namespace guard, policy ownership and watchdog behavior.
   This is not a complete host-metadata confidentiality or VM-escape certification.
5. Rebuild/test/run on a second supported engineering environment. Use the `trust`
   record/compare tooling, a separately governed reviewer key and actual artifacts.
   Identical hashes are not presumed; document environment/runtime/binary differences.
6. Review authority custody: all current local roles share a trusted store owner.
   Production needs separate principals/custody, authenticated transport, clock and
   ledger rollback resistance, durable audit and independent change authorization.
   Do not reuse these generated fixture keys for production.

## Update workflow

Before each engineering release, and on relevant new vendor advisories, record
review date, owner, affected assets, advisory coverage and unresolved UNKNOWNs.
A desired periodic review cadence (for example weekly) is a proposed operational
policy—not an implemented scheduled service, agreed staffing commitment or SLA.
For each approved update:

- retain old locks/evidence; replace exact URLs/commits/sizes/hashes explicitly;
- record patch/ABI/runtime changes and inspect license/provenance differences;
- rebuild from fresh work directories and rerun source/schema/static/regression,
  sandbox denial, routed workload, management, failure and authorization tests;
- keep acceptance thresholds unchanged unless separately agreed before measurement;
- retain failures and comparison records; never promote historical passing runs to
  qualification of new binary bytes;
- obtain independent review before promoting the release gate. Production and
  independent-review flags remain false until the corresponding external evidence
  and separate governance actually exist.

## Operational limits still requiring further work

The authority is a local fixture, not a hardened multi-tenant service. Its SQLite
store/clock/filesystem owner are trusted. Authority-store I/O failures can terminate
execution without a complete final receipt; do not treat missing evidence as success.
Crash/lease/connection withdrawal is qualified only for the fixed guest policy.
Replacement policy/identity cases deliberately refuse recovery. There is no durable
real-device rollback agent, out-of-band bank access or real-host actuator.

The workload lasts minutes, not days. Echo tails are conditional on received probes;
missed schedules and delivery denominators remain visible. No application-latency,
losslessness, fairness, ingress, IPv6, tunnel, firewall, physical-NIC or bank SLA is
qualified. Thresholds on the simulated management link do not establish complete
management exclusions in a real estate.
