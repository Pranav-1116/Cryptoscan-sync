# Phase 2 — Linux collection increment and remaining Linux work

**2026-10-24 · Phase 1 first, then Linux metadata extension**

[Foundation/data/API guide](62-universal-collection-foundation.md) ·
[Execution report](../readiness-evidence/collection-foundation-2026-10-24.md).

## Implemented Linux profile

The first universal runtime adapter is `OfflineLinuxCollector`. It validates the
method/platform and authorized time window before invoking the existing bounded,
unprivileged, no-shell/no-network host collector. The CLI now accepts
`--target-spec` as an alternative to legacy `--manifest`; they are mutually
exclusive. Output remains the same bounded metadata snapshot, exclusive-create
0600, with no automatic upload and no overwrite.

| Input kind | Result | Qualification boundary |
|---|---|---|
| `LINUX_OS_RELEASE` **new** | Literal `ID`/optional `VERSION_ID` → `OS_RELEASE`, local basis DECLARED, TechBOM | File declaration, not attested running OS/kernel |
| `DPKG_STATUS` | Installed-package database name/version → SBOM/TechBOM metadata | Approved Debian-style database only; not all distributions, loaded packages or release binding |
| `BINARY_METADATA` | ELF/PE header presence → SBOM/TechBOM metadata | Does not load/execute/disassemble a binary, identify all libraries or prove algorithm use |
| `PUBLIC_CERTIFICATE` | Public key/certificate metadata → CBOM/TechBOM | Not a served certificate or actual signing/key-exchange operation |
| `NGINX_TLS_CONFIG` | Allowlisted literal TLS configuration → CBOM/TechBOM declarations | No includes/variable expansion or effective negotiated-session claim |

One collection session can contain all supported inputs. They are imported once;
central normalization projects shared observation references, not six scans.

## Safe OS-release handling

- Read **only** the explicitly approved regular file through the existing
  descriptor-relative no-follow traversal and byte/mutation budgets.
- Never `source`, execute, interpolate or expand os-release text. Only small,
  literal alphanumeric/dot/underscore/hyphen values for `ID` and `VERSION_ID` are
  accepted; duplicate/ambiguous/executable values fail with an INVALID receipt.
- Other fields/commands/passwords/display labels are not exported. Original input
  bytes are committed by hash, not copied into the evidence envelope.
- Missing version is null/unknown, never guessed from the distribution name.
- On many Linux systems `/etc/os-release` is a **symlink**. This collector refuses
  it. An operator must explicitly approve an appropriate regular file such as
  `/usr/lib/os-release` after independent scope review; the collector does not
  automatically follow or expand scope.
- Existing host-v1 metadata gains only an additive input/fact/purpose vocabulary;
  existing serialized fact defaults are unchanged. Pinned schemas are refreshed;
  existing native CBOM golden/schema tests remain gates. OS metadata does not get
  projected into the crypto CBOM as an algorithm.

Example addition to an actual reviewed manifest (path must be approved for that
host, not copied blindly):

```json
{"input_id":"os-release","kind":"LINUX_OS_RELEASE","path":"/usr/lib/os-release"}
```

Local file content is DECLARED OS metadata. Server provenance remains IMPORTED.
It cannot be promoted to observed RSA, effective TLS, complete software inventory
or a secure host grade. Root/capability/elevated accounts, symlinks/hardlinks/special
files, denied paths, changing files, private-key material and oversize input retain
the existing conservative refusal behavior.

## Not yet complete in Phase 2

This increment **does not finish the entire requested Linux phase**. Remaining:

- Approved, bounded service/process/listening-socket interfaces and actual running
  service/endpoint evidence, with permission/failure receipts. Static TLS config
  is not substituted for a listener or handshake.
- Native hardware/TPM/HSM identity and mechanism/operation evidence. Inventory
  co-existence or supplier capability declarations cannot manufacture these links.
- Additional package ecosystems, qualified library/runtime attribution and full
  expected-truth coverage for supported Linux distributions.
- Signed collector releases/identity, independent bank fixture review and the
  isolated admission→queue→worker→read-only stage production execution path.

No Windows, container, cloud, HSM, vendor or OT adapter is secretly enabled as a
fallback. Those remain later phases. No Linux whole-host percentage, p95/p99
qualification or bank acceptance is inferred from passing synthetic tests.
