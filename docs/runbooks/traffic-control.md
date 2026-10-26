# Runbook — Read-only Linux preflight, then isolated validation

[Guide 87](../bank-environment/87-linux-traffic-preflight-and-isolated-control.md) · [API contract](../api-reference/traffic-control.md) · [Evidence](../readiness-evidence/traffic-control-2026-10-26.md)

## 1. Select and measure first

Follow Guide 86 on the intended operator host, with explicit interface/path scope and human approval. Import measurements and save a draft traffic proposal. Agree declared management IPs with the owner; their routes do **not** establish complete management safety. Do not use the application server/sandbox as the customer's network truth.

The next sequence must finish before the original sample is five minutes old. If it expires, collect a new scoped sample and create new immutable requests; do not edit timestamps. Existing policies must remain untouched.

## 2. Register and download a read-only specification

Open **Network → Linux traffic control: preflight & isolated validation**. Use the operation selector and fields relevant to each step:

1. **Register preflight request**: record UUID = original traffic proposal ID; hash = its record `payload_sha256`; management IPs = agreed canonical IP literals. The returned record includes `subject_id`, `spec` and `spec_sha256`.
2. **Download specification**: record UUID = the new request ID. Save original JSON. Retain its `spec_sha256` from step 1 separately.

No credentials/private keys or elevated shell are needed. Use a trusted checkout and ordinary-user Linux. Fixed expected executable paths are `/usr/bin/ip`, `/usr/sbin/tc`, and (only for the optional namespace drill) `/usr/bin/unshare`. Parent tools must be root-owned, not group/world writable, regular no-follow files without setuid/setgid bits or file capabilities. Missing tools are a refusal, never a fallback to caller commands.

## 3. Run preflight locally

```bash
python scripts/traffic_control.py preflight \
  --input /absolute/preflight-spec.json \
  --expected-sha256 SPEC_CANONICAL_SHA256 \
  --output /absolute/new-preflight.json
```

Replace uppercase placeholders with actual commitments. Output is exclusive/no-follow mode 0600 and never overwrites a file. Per-command stdout+stderr is limited to 64 KiB and two seconds; fixed argv only. An unavailable tool refuses capture; failed command/parsing yields an explicit gap where possible. Stable context/tool hashes are checked before accepting the packet.

Exit **0** = declared read-only checks resolved, **not** permission to change a host. Exit **2** = retained gaps. Exit **64** = refusal/invalid request/no usable receipt. Keep the printed `OUTPUT_SHA256`, the canonical typed packet hash.

Optional offline report:

```bash
python scripts/traffic_control.py report \
  --input /absolute/new-preflight.json \
  --expected-sha256 PREFLIGHT_CANONICAL_SHA256 \
  --output /absolute/new-preflight-report.json
```

## 4. Import and inspect

**Import preflight**: UUID = request ID; hash = printed capture `OUTPUT_SHA256`; paste original preflight JSON into the text field. It is not parsed/re-encoded in JavaScript. Use **Inspect preflight blockers** with the same ID. Keep the returned capture record's `payload_sha256` for the next step.

Host blockers always remain. Existing root policy and management-path overlap do not get waived by isolated validation; the isolated drill never touches this source interface. Incomplete declared checks prevent validation review. Historical records remain inspectable after revocation/expiry, but cannot support a new export.

## 5. Separate-human review

**Propose isolated validation**: UUID = preflight ID; hash = retained preflight record `payload_sha256`; provide a different eligible reviewer user UUID, 1–5 seconds, and explicit reason. Retain the resulting validation ID.

The assigned reviewer inspects preflight, host blockers and validation history in their own current session/selected estate. **Assigned reviewer approval**: UUID = validation ID; provide evidence reference and reason. Self-review and duplicate approval are refused. Then use **Download namespace-only packet** with that validation ID and save original JSON. Determine `digest(DrillAuthorization)` using the trusted Python contract; the local CLI requires this canonical hash, not the review record hash:

```python
from shared_models.host_collection import digest
from shared_models.linux_traffic_control import DrillAuthorization
print(digest(DrillAuthorization.model_validate_json(open("packet.json", "rb").read())))
```

Run this with the repository import bootstrap/environment. Human review is authenticated at the API, but the downloaded unsigned file is not independently authenticated on the operator host. It is not an enrolled-device or production authorization.

## 6. Optional local namespace-only drill

```bash
python scripts/traffic_control.py isolated-drill \
  --input /absolute/namespace-only-packet.json \
  --expected-sha256 PACKET_CANONICAL_SHA256 \
  --acknowledge-disposable-namespace-only \
  --output /absolute/new-isolated-result.json
```

The parent must be ordinary-user, capability-free and match the pinned boot/network/mount context. The wrapper alone launches fresh user/network namespaces. Inherited namespace handles prove distinct parent/child user and network namespaces; the child must initially contain only loopback, ifindex 1. It activates **child** `lo`, verifies default noqueue, and uses **add**, never replace, for owned TBF handle `7e01:`. Executable hashes are carried from the root-owned parent checks because host-root ownership is unmapped inside the new user namespace.

Readback must match TBF/handle/rate. After the bounded hold, deletion requires the owned matching policy and unchanged child context; default-policy digest/readback must match the baseline. On unexpected policy ownership, do not delete it; fail and destroy the namespace. Child tools stay in the wrapper's process group so the outer `duration + 20s` deadline can terminate/reap the namespace processes. No native success is asserted merely because the namespace exits; explicit rollback readback is required.

- Exit **0** and `APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE`: namespace mechanism/readback succeeded, not throughput enforcement.
- Exit **2** and `REFUSED_OR_FAILED`: retain the gap; do not substitute a physical interface, use sudo, load modules or bypass namespace checks.
- Exit **64**: packet/context/parent privilege/precondition refusal.

The result remains a local artifact, not uploaded/certified automatically. No packet traffic generator, bandwidth benchmark, throughput target, real-host lease/revocation enforcement or production executor is included. Local offline packets may be replayed within their window; production use would require authenticated device execution with an online authorization/lease design.

## Engineering validation

Focused commands use the existing Python import bootstrap and frontend toolchain. The readiness note records exact tested tree/results. Owned PostgreSQL tests separately cover duplicate review, review/revocation ordering and audit rollback; neither those synthetic tests nor SQLite HTTP fixtures qualify a real device or production deployment. On the current sandbox, the actual kernel does not support TBF: its retained native witness is blocked, despite successful namespace creation and child-loopback activation.
