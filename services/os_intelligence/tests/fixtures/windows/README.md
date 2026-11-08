# Windows fixture provenance

These files are **RECONSTRUCTED from documented Microsoft command
output formats** — they were NOT captured from a live Windows host.

Per docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §12: a successful
parse of these fixtures is NOT Windows fleet qualification. The
adapter status is "validated against documented output formats"; a
live-Windows-host validation and an enterprise Windows fleet
qualification are both NOT DONE and are never claimed.

Reconstructed formats:
- systeminfo.txt        — `systeminfo` key/value layout
- certutil_csplist.txt  — `certutil -csplist` provider blocks
- reg_schannel.txt      — `reg query` output for SCHANNEL\Protocols
- manage_bde.txt        — `manage-bde -status` volume blocks
- get_tpm.txt           — `Get-Tpm` PowerShell property lines
- confirm_secureboot.txt — `Confirm-SecureBootUEFI` output
- driverquery.txt       — `driverquery /fo list` blocks
