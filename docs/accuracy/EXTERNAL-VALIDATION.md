# External validation — real third-party code

The corpus in `REPORT.md` is hand-labelled by us. To check the scanner against code nobody here
wrote, we point it at the Python packages installed in the project's own virtualenv and review
every finding by hand (`python scripts/scan_third_party.py <pkg> v`).

Date: 2026-09-24 · scanner at the commit that adds this file.

## Packages with no cryptography (precision check)

| Package | Files scanned | Findings | Verdict |
|---|---|---|---|
| click | 17 | 0 | correct (only `random.randrange` for a temp-file suffix, not key material) |
| structlog | 21 | 0 | correct |
| pyyaml | 17 | 0 | correct |
| pytest + _pytest + pluggy + iniconfig | 92 | 0 | correct |
| packaging | 22 | 0 | correct |
| pygments | 343 | 0 | correct |
| pydantic | 105 | 0 | correct (`SecretStr` types are not crypto) |
| gitpython (git) | 37 | 0 | correct |
| smmap | 10 | 0 | correct |
| pkg_resources | 51 | 0 | correct |

**715 files, 0 false positives.**

## Packages with cryptography (recall check, every `hashlib`/`hmac`/`ssl` call site grepped and compared)

| Package | Files | Findings | Missed before this round | Status |
|---|---|---|---|---|
| gitdb | 25 | 1 (`hashlib.sha1`) | — | complete |
| setuptools | 179 | 5 | `getattr(hashlib, "md5", None)` table in `_distutils/command/upload.py`; dynamic `hashlib.new(hash_name)` | fixed: 3 digests + UNKNOWN now reported |
| pip (+ vendored urllib3/requests/distlib/cachecontrol) | 491 | 41 | `operations/build/build_tracker.py` skipped because the directory is named `build` | fixed: output-dir exclusion no longer applies to Python packages |
| cryptography | 78 | 60 → 96 | algorithm *implementations* (`class MD5(HashAlgorithm)`, `class TripleDES(BlockCipherAlgorithm)`, curve classes) were invisible | fixed: reported with purpose `ALGORITHM_IMPLEMENTATION` when the base class is a crypto ABC |

Every remaining finding in these packages was reviewed and is a genuine cryptographic call, constant or
implementation (digest auth MD5/SHA in `requests/auth.py`, `PROTOCOL_SSLv3`/`CERT_NONE` in urllib3
contrib backends, `os.urandom`, `ssl.create_default_context`, etc.).

## Two discovery bugs this exercise exposed (both fixed, both regression-tested)

1. **Config files were never scanned in a repository scan** — `FileDiscovery` only yielded source
   extensions, so nginx/sshd/Docker/Kubernetes/Terraform/`.env` files were skipped entirely.
2. **Any source directory named `build`, `out`, `target`, `dist` or `bin` was skipped**, even when it
   was a Python package.
