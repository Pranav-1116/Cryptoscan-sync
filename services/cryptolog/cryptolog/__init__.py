"""CryptoLog collection domain (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 4):
multi-source cryptographic event collection. Adapters translate SOURCE
observations into canonical events; they never invent evidence, never copy
secret material, and an unparseable observation is a recorded refusal, not
a fabricated event."""
