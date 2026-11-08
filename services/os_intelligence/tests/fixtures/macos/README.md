# macOS fixture provenance

These files are **RECONSTRUCTED from documented Apple command output
formats** — they were NOT captured from a live macOS host.

Per docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §12: a successful
parse of these fixtures is NOT macOS fleet qualification. The adapter
status is "validated against documented output formats"; live-macOS
validation and enterprise fleet qualification are both NOT DONE and
never claimed.

Reconstructed formats:
- sw_vers.txt     — `sw_vers` key/value layout
- uname.txt       — `uname -r` / `uname -m` output lines
- csrutil.txt     — `csrutil status` output
- spctl.txt       — `spctl --status` output
- fdesetup.txt    — `fdesetup status` output
- kmutil.txt      — `kextstat`-style loaded-kext rows

Collection boundary (§5/§7): Security framework / Keychain command
OUTPUTS only — protected storage files and keychain databases are
never scraped.
