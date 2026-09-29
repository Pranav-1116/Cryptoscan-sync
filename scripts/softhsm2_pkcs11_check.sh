#!/usr/bin/env bash
# Exercise the real PKCS#11 path against SoftHSM2.
#
# This is intentionally not a fake-HSM unit test. CI installs softhsm2 and
# opensc, creates an ephemeral token, generates a key pair through
# pkcs11-tool, and reads the object back through the PKCS#11 module. A local
# developer without those binaries gets an explicit SKIP; CI sets
# REQUIRE_SOFTHSM2=1 so missing coverage fails the gate. Real CloudHSM/HSM
# validation remains an external evidence item.
set -euo pipefail

if ! command -v softhsm2-util >/dev/null 2>&1 || ! command -v pkcs11-tool >/dev/null 2>&1; then
  if [[ "${REQUIRE_SOFTHSM2:-0}" == "1" ]]; then
    echo "SoftHSM2 PKCS#11 coverage required but softhsm2-util/pkcs11-tool is unavailable" >&2
    exit 2
  fi
  echo "SKIP: SoftHSM2 and OpenSC are not installed; set REQUIRE_SOFTHSM2=1 in CI" >&2
  exit 0
fi

module="${SOFTHSM2_MODULE:-}"
if [[ -z "$module" ]]; then
  for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/*/softhsm/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then module="$candidate"; break; fi
  done
fi
if [[ -z "$module" || ! -f "$module" ]]; then
  echo "SoftHSM2 tools exist but libsofthsm2.so was not found" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tokens"
cat > "$tmp/softhsm2.conf" <<EOF
directories.tokendir = $tmp/tokens
objectstore.backend = file
EOF
export SOFTHSM2_CONF="$tmp/softhsm2.conf"

softhsm2-util --init-token --free --label cryptoscan-ci --so-pin 12345678 --pin 123456
slot="$(softhsm2-util --show-slots | awk '/Slot [0-9]+/{slot=$2} /Label: *cryptoscan-ci/{print slot; exit}')"
if [[ -z "$slot" ]]; then
  echo "could not locate the ephemeral SoftHSM2 token" >&2
  exit 2
fi

common=(--module "$module" --slot "$slot" --login --pin 123456)
pkcs11-tool "${common[@]}" --keypairgen --key-type rsa:2048 --id 01 --label cryptoscan-ci-key >/dev/null
objects="$(pkcs11-tool "${common[@]}" --list-objects)"
grep -q 'cryptoscan-ci-key' <<<"$objects"
grep -qi 'RSA' <<<"$objects"
echo "PASS: SoftHSM2 PKCS#11 token initialized; RSA-2048 object generated and read back"
