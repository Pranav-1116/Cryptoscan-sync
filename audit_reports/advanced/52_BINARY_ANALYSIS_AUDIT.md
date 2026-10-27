# 52_BINARY_ANALYSIS_AUDIT.md
## ZELNX CryptoScan — Binary Analysis Audit (52)

**Created:** 2026-10-12 (round 38)
**Scope:** binary-level crypto analysis. Progress to date is tracked
in `audit_reports/00_ROUND_STATUS.md` rows citing 52: whole-file
binary table fingerprints with offset-carrying evidence (round 36) and
the labeled-detector calibration surface (round 34). This file was
created in round 38 to carry the angr/Ghidra CFA addendum below.

---


## Round 38 addendum (2026-10-12) — angr/Ghidra CFA adapters BUILT

The last open row of round 36's table fingerprints is closed:
`universal_crypto/binary_cfa.py` attributes crypto constants to
FUNCTIONS using real program analysis. `angr_analysis` recovers the
CFG (`Project(auto_load_libs=False)` → `CFGFast()` →
`cfg.kb.functions`), reads each function's blocks, and byte-scans the
exact function bodies with the shared `binary_tables.scan_tables`
registry — a hit becomes "AES implementation in function X (address,
size)". `ghidra_analysis` runs Ghidra headless with the shipped
`deploy/ghidra/ExportCryptoFunctions.py` post-script (Jython, embeds
the AES S-box / inverse / T-table / DES IP leading bytes, matches the
Python-side registry byte-for-byte — pinned by test) and parses its
JSON output; the runner reports analyzeHeadless failures with rc and
stderr, never silence. `analyze()` orchestrates and records every
attempt. Honest classification: angr is guarded-import and
deliberately NOT a requirement (hundreds of MB; absence → recorded
reason, nothing inferred — 8 tests cover degradation, the angr
plumbing via a stub module, and the Ghidra runner via a fake headless
executable); the Ghidra script's execution needs an external Ghidra
installation (deployment half). Tests:
`services/universal_crypto/tests/test_binary_cfa.py`.
