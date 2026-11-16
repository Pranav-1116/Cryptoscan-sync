# mTLS Certificate Rotation — without an outage

The gateways DEMAND client certificates (`deploy/ha/nginx.conf`
`ssl_verify_client on`; `deploy/stack/envoy/envoy.yaml`
`require_client_certificate: true`). That makes rotation the one
maintenance action that can lock every client out at once if it is done
wrong. This runbook is the no-outage path.

## What is mounted where

| File | Consumers | Meaning |
|---|---|---|
| `/etc/nginx/certs/fullchain.pem` + `privkey.pem` | HA nginx pair | the gateway's own server certificate |
| `/etc/nginx/certs/ca.pem` | HA nginx pair | the bank CA that signs **client** certificates |
| `/run/secrets/gateway/tls.crt` + `tls.key` | Envoy gateway | server cert AND its client cert to the API |
| `/run/secrets/gateway/client-ca.crt` | Envoy gateway | the bank CA for client + upstream validation |

All of them come from the bank's PKI. CryptoScan never generates them.

## The rotation order (server first, clients second)

1. **Issue the new server certificate** (same CN/SANs, new key) from the
   bank CA. Keep the old one active in parallel — both stacks support a
   certificate PAIR during transition; stage the new files beside the old.
2. **Roll the server side one instance at a time** (nginx pair: drain one
   node, swap `fullchain.pem`/`privkey.pem`, `nginx -t && nginx -s
   reload`, verify, then the other node. Envoy: swap the mounted secret,
   hot-restart). The old CA still validates existing client certs the
   whole time — no client is locked out.
3. **Re-issue client certificates** to the SOC/automation clients whose
   lifetime has elapsed (`/security/secrets/status` `stale_references`
   flags the credentials side; client certs are tracked by the bank PKI).
   New clients can connect as soon as the new CA is trusted.
4. **Rotate the CA itself last, and overlap**: mount the NEW CA as an
   additional trusted root (both stacks accept a CA bundle), distribute
   client certs signed by it, watch `ssl_client_verify`/envoy access logs
   until no old-CA client remains, then remove the old root.

## What must never happen

* Swapping the CA first — every client is rejected at once. Server first,
  CA last, always overlapped.
* Rotating both nginx nodes together — the pair is the availability
  unit; one node at a time.
* A verification step that does not end in a live request: after every
  swap, one real mTLS request must succeed before moving on.

## Verification (the contract)

* `openssl s_client -connect <gw>:443 -cert client.pem -key client.key
  -CAfile ca.pem` completes the handshake.
* The app sees the identity: `X-Client-Cert-CN` reaches the API
  (`deploy/ha/nginx.conf` forwards it).
* `deploy/stack/envoy/envoy.yaml`'s `require_client_certificate: true`
  stays set through every transition — the temporary relaxation
  (`ssl_verify_client optional`) is only for the initial client rollout
  and is itself a change to close.

## Rotation drill (rehearse before the incident)

`scripts/mtls_rotation_drill.py` executes this runbook's ordering
against a real TLS stack that demands client certificates — throwaway
PKI in a temp directory, real handshakes, one report:

```bash
python3 scripts/mtls_rotation_drill.py --out drill-report.json
```

It proves, live: the gate **demands** certificates (a bare client gets
`TLSV13_ALERT_CERTIFICATE_REQUIRED`), a re-issued server cert locks
nobody out, client re-issue keeps old certs working, the CA **overlap**
keeps both generations connected, retiring the old root rejects old-CA
clients as intended — and it OBSERVES the failure mode the ordering
prevents (swap the CA first → every client locked out) so the drill can
detect it. The drill runs in the test suite on every certify
(`test_mtls_rotation_drill.py`); run it manually before any real
rotation window. It never touches production material — the bank's PKI
issues those ("CryptoScan never generates them").
