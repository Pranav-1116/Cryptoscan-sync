#!/bin/sh
# One-shot certificate factory for the sandbox estate. Each endpoint gets a
# cert whose *posture* matches its role: strong modern certs for internet-
# facing channels, a deliberately weak 1024-bit one for the legacy branch
# concentrator, and a soon-expiring cert so renewal workflows have something
# real to chew on. All throwaway — sandbox only.
#
# Every cert carries BOTH its DNS name and its sandbox-net IP as SANs, so a
# scan aimed at the IP (the way a bank's scanner sweeps a subnet) sees a
# well-formed cert instead of an artificial name-mismatch.
set -e
mkdir -p /certs
cd /certs

gen() { # name cn ip days keyspec
  name="$1"; cn="$2"; ip="$3"; days="$4"; shift 4
  openssl req -x509 -newkey "$@" -keyout "$name.key" -out "$name.crt" \
    -days "$days" -nodes -subj "/C=IN/ST=Tamil Nadu/L=Chennai/O=Meridian Bank (Sandbox)/CN=$cn" \
    -addext "subjectAltName=DNS:$cn,IP:$ip" 2>/dev/null
  echo "generated $name -> $cn / $ip ($days days)"
}

gen internet-banking internet-banking.bank.sandbox 10.210.0.10 398 rsa:2048
gen mobile-api       mobile-api.bank.sandbox       10.210.0.11 398 rsa:2048
gen swift-gateway    swift-gateway.bank.sandbox    10.210.0.12 365 rsa:3072
gen hsm-sim          hsm-sim.bank.sandbox          10.210.0.14 730 rsa:2048
gen core-db          core-banking-db.bank.sandbox  10.210.0.15 398 rsa:2048
# Weak on purpose: 1024-bit key, 30 days left after backdating via -days 31.
gen legacy-branch    legacy-branch.bank.sandbox    10.210.0.13  31 rsa:1024

chmod 0644 /certs/*.key /certs/*.crt
echo "sandbox certificates ready"
