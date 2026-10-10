
## Round 29 update (2026-10-10) — library identity normalization built

* **Library identity normalization — the open item from round 26 — NOW
  BUILT (this round).** `normalization/library_identity.py` maps
  free-form library names onto the platform's library registry (the
  same `LIBRARIES` identities the artifact fingerprinter confirms
  against evidence, so the two surfaces cannot disagree): sonames
  (``libssl.so.1.1``), module paths (``Crypto.Cipher`` → PyCryptodome,
  ``crypto.subtle`` → WebCrypto — internal dots are identity, not
  noise), packaging prefixes (``py-openssl``, ``libmbedtls``), version
  tails (``openssl 1.1.1k``), and an alias table for spellings cleaning
  cannot reach (``bcprov`` → BouncyCastle, ``node:crypto`` → Node
  crypto). Versions normalize too (``1.1.1k`` → base ``1.1.1`` + patch
  letter ``k``, epochs, ``v``-prefixes). Domain words that name no
  particular library (``ssl``, ``crypto``) and unknown names stay
  **unmatched** — never forced onto the nearest registry entry.
  Surfaced at `GET /assets/libraries/identity`: the estate-wide dedup
  view that folds every asset's raw library entries into canonical
  identities with their alias sets and versions. Tests: 10 unit
  (`services/normalization/tests/unit/test_library_identity.py`) + 1
  API test (three assets, six raw spellings → two canonical identities
  + one honest unmatched).
