#!/bin/sh
# macOS live-host capture (docs/os-kernel-intelligence/
# 01_PRODUCT_SPEC.md §15 step 9 + §5.2). Run ONLY on an authorised
# macOS host under an agreed scope.
#
# Command OUTPUTS only — Security framework / Keychain command-line
# results; protected storage files and keychain databases are NEVER
# scraped. Denied commands are recorded as unavailable/permission-
# denied — never as absence (§2.1).
set -eu
OUT="${1:-macos-capture-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"

capture() {
  name="$1"; file="$2"; shift 2
  if "$@" > "$OUT/$file" 2>&1; then
    echo "captured $name"
  else
    echo "permission_denied or unavailable (exit $?)" > "$OUT/$file"
    echo "unavailable $name (recorded, never as absence)"
  fi
}

capture "sw_vers" sw_vers.txt sw_vers
capture "uname" uname.txt uname -r
capture "csrutil" csrutil.txt csrutil status
capture "spctl" spctl.txt spctl --status
capture "fdesetup" fdesetup.txt fdesetup status
capture "kmutil" kmutil.txt kmutil showloaded
# Certificate METADATA only (public attributes) — never private keys.
if command -v openssl >/dev/null 2>&1; then
  : > "$OUT/certificate_metadata.txt"
  for cert in /etc/ssl/cert.pem /etc/ssl/certs/*.pem; do
    [ -f "$cert" ] || continue
    openssl x509 -in "$cert" -noout -subject -issuer -dates \
      -fingerprint -sha256 >> "$OUT/certificate_metadata.txt" 2>/dev/null || true
    openssl x509 -in "$cert" -noout -text 2>/dev/null |
      grep -m1 "Public-Key:" >> "$OUT/certificate_metadata.txt" || true
    echo "---" >> "$OUT/certificate_metadata.txt"
  done
else
  echo "permission_denied or unavailable (openssl not present)" \
    > "$OUT/certificate_metadata.txt"
fi

cat > "$OUT/manifest.json" <<MANIFEST
{
  "schema": "cryptoscan.live-capture/1",
  "platform": "macos",
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname 2>/dev/null || echo unknown)",
  "note": "command outputs only — protected storage files and keychain databases are never scraped; private keys are never collected"
}
MANIFEST
echo "wrote $OUT (validate with: validate_capture.py --platform macos $OUT)"
