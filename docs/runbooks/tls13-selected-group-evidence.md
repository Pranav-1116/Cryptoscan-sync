# Operator packet — TLS 1.3 final selected group

[Guide 80](../bank-environment/80-tls13-selected-group-evidence.md) · [Base approved single-session packet](approved-single-tls-session-candidate.md).

This is an **active operator-run candidate**, not permission to contact a customer or evidence of production/native qualification. Do not send credentials, private keys or TLS session secrets.

## Before measuring

Use the existing approval/reviewer process. Agree one numeric endpoint/port, canonical SNI, exact TLS 1.3, independently trusted peer DER SHA-256 and bounded UTC window. Obtain explicit consent both to the active handshake and to retaining the public ServerHello (random, compatibility session ID and public key share). Keep real endpoint/organization identifiers in the approved secure channel.

Reviewer must specify expected **selected group**, separately from the certificate key and cipher name. A server with an RSA certificate may select X25519. For broader capability/PQC acceptance, separately agree every permitted attempt and denominator; this command does **one** session, not a survey or proof of unsupported groups.

## Change the reviewed target, not the old snapshot

Start with the base packet's public `TargetSpec`, preserving numeric `address`, network method, sole `OBSERVE_APPROVED_TLS_SESSION` operation, no credential reference, Linux ordinary-user scope, matching environment and start/expiry.

Replace only the explicitly reviewed input/profile as appropriate:

```json
{
  "input_id": "session",
  "kind": "NETWORK_TLS13_KEY_SHARE",
  "path": "tls-key-share://<numeric-IP>:<port>/sni/<canonical-ASCII-name>/version/TLSv1.3/peer/sha256/<independently-reviewed-peer-SHA256>"
}
```

IPv6 uses canonical brackets. Keep exactly one input, explicit 128 KiB or smaller budget and no exclusions. Recompute and independently review the **whole-target canonical SHA-256** with the base packet's bounded reader. New kind/resource changes the digest; the previous reviewed hash is not reusable. Host intake must approve the exact new manifest before acquisition; complete external target/consent originals remain separate artifacts.

## Explicit acquisition

```bash
python scripts/collect_tls_session.py \
  --target reviewed-tls13-group-target.json \
  --approved-target-sha256 '<reviewed-whole-target-digest>' \
  --acknowledge-active-tls --include-key-share \
  --output tls13-group-snapshot.json
```

Without `--include-key-share`, the old wrapper refuses before any connection. Existing output/symlink, wrong hash, credential reference, wrong window/platform and excluded/mismatched scope still refuse. There is no API job execution, DNS, reconnect, version/group fallback, application request or HSM query. Existing 0/2/64 exit semantics and exclusive mode-0600 output apply; preserve partial/failed output and investigate, never automatically retry.

The real TLS handshake and exact peer pin must succeed. A HelloRetryRequest alone is not positive negotiation. Unsupported/truncated/oversized/duplicate/mismatched public records and missing final hello produce gaps, not absence or a quantum-safety verdict. Total charged bytes include final ServerHello copy and canonical selected metadata, in addition to wire/DER. Deadlines bound I/O, not native-library CPU/memory isolation.

## Return and independently compare

Retain the original target/digest, snapshot, source/release identity, independent expected truth and actual operator/reviewer records. Validate exact selected group ID/name, raw final ServerHello/hash, suite/version and certificate separately. Hybrid codepoint mapping is **registry interpretation**, not functional KEM verification or overall PQC readiness. Our hybrid unit vectors are not an operator's real hybrid run.

Import through existing approved host intake. Inspect via existing panel or stored-only route:

```text
GET /api/v1/host-evidence/approvals/{approval_id}/snapshot
GET /api/v1/host-evidence/approvals/{approval_id}/tls-session/cyclonedx-1.6
```

No read/export reconnects. Imported measurements are not authenticated merely by a content hash. CA/hostname/revocation remain unvalidated; application/HSM operation use, complete software coverage, other group/version capability and PQC implementation/readiness remain unproven. Genuine Windows/container qualification still needs the existing independent operator-return workflow; this Linux TLS packet cannot close it.
