# Scanner design

Part 1 uses a deterministic regex Java parser (`JavaParser`) covering:

- `Cipher.getInstance`
- `MessageDigest.getInstance`
- `KeyGenerator.getInstance`
- `Signature.getInstance`
- `new SecretKeySpec(...)` hardcoded keys

Eclipse JDT sources live under `services/scanner/jdt/` for a later production parser. The public API is `Scanner.scan(...) → ScanResult`.
