# Disposable Linux TBF target

This is an **operator-run engineering fixture**, not a new service, collector, production device adapter or extension of Guide 87's offline namespace authorization.

- Build a pinned Linux **6.12.58** x86_64 kernel with **`CONFIG_NET_SCH_TBF=y`**, no modules and no network device drivers.
- Boot a diskless, 256 MiB, one-vCPU **TCG** VM. No KVM, NIC, TAP, forwarded port, disk, monitor, host-directory sharing or interactive guest shell is exposed.
- A mandatory unprivileged **Landlock ABI ≥2 + seccomp** launcher restricts filesystem content reads/execution to the bundle plus read-only random/null devices; denies path writes/truncation, ownership/mode/timestamp/xattr mutation, sockets, mounts, namespace changes, ptrace, kernel module operations, System V IPC and subprocess creation. Emulator threads are allowed. Process signals are limited to the emulator's own TGID. CPU/address-space/FD/core limits and a 180-second outer deadline apply.
- Generate bounded synthetic UDP on **guest `127.0.0.1` / `lo` only**. Measure uncapped baseline, **10 Mbps**, **5 Mbps**, then restored baseline. Each phase has one warmup second and four receive-measurement seconds.
- Require exact TBF handle/rate readback, advancing kernel bytes/packets/overlimits, matching default-policy rollback, enough unshaped headroom and actual received payload within predeclared bands. Low traffic or policy presence alone cannot qualify.

The launcher fails closed if the sandbox cannot be established. It does not rely on the downloaded QEMU's optional built-in sandbox. Metadata queries are not a general host confidentiality boundary, and this small launcher/emulator/profile has **not** received independent security certification. Use a dedicated engineering environment, not a machine with customer workloads/secrets. A successful run is qualified only for this generated UDP guest-loopback workload, never a production/physical interface.

## Operator entry point

See [Guide 88](../../docs/bank-environment/88-disposable-linux-tbf-qualification.md), the [runbook](../../docs/runbooks/disposable-tbf.md) and [retained engineering evidence](../../docs/readiness-evidence/disposable-tbf-2026-10-26.md).

```bash
.venv/bin/python scripts/qualify_tbf.py build \
  --cache "$HOME/.cache/cryptoscan-tbf-assets" \
  --work "$HOME/.cache/cryptoscan-tbf-build-UNIQUE" \
  --output "$HOME/.cache/cryptoscan-tbf-bundle-UNIQUE"
```

`build` prints `BUNDLE_SHA256`. `scope` pins it to a ten-minute local engineering window. `run` requires the separately displayed scope hash and `--acknowledge-disposable-vm-only`. `verify` recomputes archived receipt/report/serial closure; it is not device authentication. Use new work/output names: the tool never cleans/reuses an existing output directory.

## Build inputs and limits

[assets.lock.json](assets.lock.json) pins source commits, archive lengths and SHA-256 hashes. It includes Linux, GNU m4/bison/flex bootstrap tools, musl 1.2.5, elfutils 0.188 headers and the npm `qemu-portable-linux-x64-musl` 0.2.1 package (whose binary reports QEMU 11.0.2). Sources come only from fixed GitHub codeload/npm registry URLs. Downloads are bounded and checked before extraction. No install scripts, sudo, system package installation or host module loading occurs.

`build.py` explicitly patches old bootstrap gnulib for modern glibc and changes the **private** musl runtime's four `tkill` sites to `tgkill(getpid(), tid, signal)`. This preserves thread signaling while allowing cross-process signals/legacy `tkill` to stay denied. These are disclosed local modifications, not claims of unmodified upstream binaries. The downloaded archives' hashes establish integrity, **not** upstream signature verification or reproducible-build attestation.

The initial supported builder is ordinary-user **Debian-style x86_64 Linux with system Python 3.11**, GCC/static libc development files, make/binutils, BusyBox (`bc` applet), a runtime libelf 0.188-compatible library, and fixed root-owned `ip`/`tc`/Python tools. The isolated guest receives only those explicit runtimes and non-symlink Python standard-library sources; no site packages, host configuration, application data or credentials are copied. Other host layouts are unqualified and may refuse/fail. Use several GiB of free cache/work space. Compiler/system runtime inputs vary by host: bit-for-bit reproducibility is not claimed.

`assemble` is an advanced operator path for already built matching components; it records/pins resulting bytes, not proof that a supplied kernel matches its configuration. The normal `build` path compiles the locked source. Do not redistribute a bundle without meeting every component's license/source/notice obligations; large generated binaries/rootfs/build trees are intentionally not committed to Git. The runtime file-hash inventory is not a schema-validated SBOM or device attestation.
