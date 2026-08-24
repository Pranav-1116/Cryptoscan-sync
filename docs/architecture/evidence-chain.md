# Evidence chain

Each finding is canonicalized (sorted JSON, UTF-8, no whitespace) and hashed
with SHA-256 (`content_hash`). Records in a scan are then chain-hashed:

```
chain_0 = SHA256(scan_id || content_0)
chain_n = SHA256(chain_{n-1} || content_n)
```

`GET /scans/{id}/verify` recomputes both layers. `IntegrityProof` is the
in-memory model of that pair. Tampering any finding or reordering the chain
fails verification.

The dashboard "Verify chain" button and the downloadable verifier script use
the same algorithm.
