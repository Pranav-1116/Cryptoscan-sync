# Operator runbook — routed disposable Linux TBF laboratory

[Profile and limits](../../tools/routed_tbf/README.md) · [Detailed gates](../bank-environment/89-routed-tbf-application-and-recovery.md) · [Actual evidence](../readiness-evidence/routed-tbf-2026-10-26.md)

## Preconditions

Use a dedicated ordinary-user x86_64 Linux engineering environment, not a customer
host. Required: Landlock ABI ≥2, seccomp, GCC/static libc, make, system BusyBox with
bc, Debian-layout Python 3.11, iproute2 `ip`/`tc`, libelf 0.188 runtime and development
Python with Pydantic 2/cryptography. See v1's [bootstrap constraints](../../tools/disposable_tbf/README.md).
The launcher fails closed if its sandbox cannot be installed; do not add sudo,
capabilities, modules, container-host networking or an unsandboxed fallback.

No credentials/private keys belong in chat, Git, guest images or retained evidence.
Only disposable locally generated test keys are needed. These model separate roles,
not independently approved bank changes. Keep cache/authority directories private.

## 1. Rebuild locked sources

From the repository root, with its Python environment ready:

```bash
LAB="$HOME/.cache/cryptoscan-routed"
mkdir -p "$LAB"
chmod 700 "$LAB"
.venv/bin/python scripts/qualify_routed_tbf.py build \
  --cache "$LAB/assets" --work "$LAB/fresh-build-01" --output "$LAB/bundle-01"
```

Record the printed `BUNDLE_SHA256` as `BUNDLE`; never substitute the source-tree
hash for the actual bundle-manifest byte hash. Work/output directories must not
already exist. Large binaries and complete build trees remain outside Git.
`assemble` supports explicitly provided matching prebuilt kernel/config/QEMU/private
musl inputs but is not evidence that the full locked pipeline ran.

## 2. Initialize local lab roles

```bash
.venv/bin/python scripts/qualify_routed_tbf.py init-authority \
  --authority "$LAB/authority" --tenant lab --device diskless-routed-v1 \
  > "$LAB/public-keys.json"
```

Pin the public enrollment output separately. The authority directory is 0700 and
private keys/database are 0600. Do not copy that directory into evidence. Public
keys, signatures, lease IDs and nonces are not secrets. The database serializes
redemption/revocation; its local owner and clock remain trusted. No network service
or physical-device enrollment is created.

## 3. Issue, explicitly approve, and execute

Set `BUNDLE` to the actual printed hash before running:

```bash
.venv/bin/python scripts/qualify_routed_tbf.py issue \
  --authority "$LAB/authority" --bundle-sha256 "$BUNDLE" --output "$LAB/lease-01.json"
.venv/bin/python scripts/qualify_routed_tbf.py approve \
  --authority "$LAB/authority" --input "$LAB/lease-01.json" \
  --output "$LAB/grant-01.json" --ack-simulated-reviewer
.venv/bin/python scripts/qualify_routed_tbf.py run \
  --authority "$LAB/authority" --bundle "$LAB/bundle-01" --bundle-sha256 "$BUNDLE" \
  --input "$LAB/grant-01.json" --output "$LAB/run-01" --ack-disposable-vm-only
```

Each grant is once-only and valid for at most ten minutes. Execution requires at
least 305 seconds remaining; issue/approve immediately before launch. Every new
run needs a fresh grant and new output directory. Do not replay an old packet or
reuse a failure directory. Only fixed guest-internal addresses/interfaces exist;
there is no command for selecting a customer target or passing emulator flags.

The workload runs eleven longer application phases, five injected failures and
three additional post-withdrawal traffic phases. Allow up to 300 seconds wall time;
the outer supervisor bounds serial output to 512 KiB and kills/reaps a stuck VM.
The sandbox CPU limit is 300 seconds, RAM 256 MiB guest/3 GiB address-space cap,
FD limit 128 and core dumps disabled. Key material is never forwarded to the VM.

Exit 0 means the bounded lab gates passed, **including two explicit not-recovered
refusal cases**. Exit 2 retains an inconclusive/failed run. Exit 64 refuses invalid
operations; argparse usage errors also use its standard exit code 2. A failed or
missing measurement cannot be promoted to success by changing acceptance.json.
Changing runtime source/profile requires a new bundle and new measurements.

## 4. Verify and inspect the actual application results

The run prints the byte SHA-256 of `result.json`. Obtain the enrolled adapter public
key from the separately pinned public-key output, not an untrusted receipt alone:

```bash
.venv/bin/python scripts/qualify_routed_tbf.py verify \
  --input "$LAB/run-01/result.json" --expected-sha256 "$RESULT" \
  --trusted-adapter-public-key "$ADAPTER_PUBLIC_KEY"
```

The receipt is signed by the enrolled **local lab adapter**; verification binds its
payload to the serial capture, exact source/profile, recomputed gates and unchanged
recorded parent policy/context. It is not physical device/guest attestation or
independent issuer/reviewer custody. Inspect `payload.report.blockers`, every phase's
received payload Mbps, UDP loss denominator, TCP retransmissions and both RTT tails.
Review refused recovery cases separately. `all_failure_modes_recovered` stays false.

Raw serial and failed results are retained even when the guest fails or gates fail;
partial phase progress can be inspected but is never a successful final capture.
The management path must meet delivery/latency gates and its policy hash remain
unchanged; this does not establish zero latency impact or complete bank-management
coverage. No data-path latency/losslessness SLA was agreed.

## 5. Revocation and recovery drills

From another local shell, use the public ID in the lease payload:

```bash
.venv/bin/python scripts/qualify_routed_tbf.py revoke \
  --authority "$LAB/authority" --lease-id "$LEASE_ID"
```

The supervisor polls active state roughly every 100 ms (plus OS/SQLite scheduling),
terminates/reaps the VM on revocation/expiry and reports that termination—not a
fabricated guest rollback. No parent policy was installed. Native guest watchdog
drills independently test crash, lost heartbeat and lease expiry with ≤5-second
withdrawal/readback and post-recovery traffic. A lost heartbeat models a control
connection failure; no real customer management transport exists.

On interface recreation or policy takeover, deletion must be refused. The new/foreign
policy must remain intact. Harness cleanup afterward is separately marked and is
not recovery. Unexpected failures, unknown identity or missing watchdog evidence
remain inconclusive/failed. Never add a blind root-qdisc replacement as a fallback.

## 6. Build trust and independent validation

```bash
.venv/bin/python -m tools.routed_tbf.trust inventory \
  --cache "$LAB/assets" --output "$LAB/dependency-review.json"
.venv/bin/python -m tools.routed_tbf.trust record \
  --bundle "$LAB/bundle-01" --receipt "$LAB/run-01/result.json" \
  --receipt-sha256 "$RESULT" --trusted-adapter-public-key "$ADAPTER_PUBLIC_KEY" \
  --output "$LAB/local-validation.json"
```

License-file hashes/excerpts are discovery evidence, **not legal approval**. Missing
license files are UNKNOWN; vulnerability review and upstream authenticity are not
invented. Review prebuilt emulator/transitive libraries, copied system runtime
licenses, old GNU bootstrap sources, kernel pin and custom private-musl signal patch.
Do not describe this fixed engineering kernel as a current security baseline.

A separate operator must repeat the complete build/tests/native measurements on a
second supported environment and review launcher/runtime changes. Their signed
peer payload uses the validation-record fields, adds their genuine reviewer ID and
`reviewed_launcher_and_runtime=true`, and is signed with their separately governed
Ed25519 key over canonical sorted compact JSON. Supply that public key through an
independently trusted channel—never send their private key here.

```bash
.venv/bin/python -m tools.routed_tbf.trust compare \
  --local "$LAB/local-validation.json" --peer "$LAB/signed-peer-review.json" \
  --trusted-reviewer-public-key "$REVIEWER_PUBLIC_KEY"
```

The comparator rejects the same recorded environment, wrong profile/acceptance or
missing review assertions and lists changed binary hashes. It authenticates a
supplied review assertion, not physical environment/competence; it does not grant
production authority. General bit-for-bit reproducibility remains unestablished
unless the independent result actually demonstrates it. No separate review or
second environment is claimed merely because these tools exist.
