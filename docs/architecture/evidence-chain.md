# Evidence chain

Each finding is canonicalized (sorted JSON, UTF-8) and hashed with SHA-256 (`content_hash`).

`chain_hash[i] = SHA256(content_hash[i] || previous_chain_hash)` seeded with the scan id.

The scan manifest hashes the sorted evidence IDs. Auditors recompute both layers; CryptoScan never asks a model to attest integrity.
