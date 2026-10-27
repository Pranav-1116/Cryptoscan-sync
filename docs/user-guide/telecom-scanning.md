# Telecom network scanning (5GC / roaming / EPC / IMS)

CryptoScan classifies the cryptographic posture of 3GPP network functions —
5G SBA, EPC, IMS, signaling and NDS/IP — against 3GPP TS 33.210 / TS 33.501
and NIST SP 800-52r2 / IR 8547, per carrier, with a dedicated roaming view
for SEPP PQC readiness. Operator-run: you register your own estate, the
scanner probes it, every verdict is evidence-linked. Dashboard:
**Telecom** page.

## Concepts

| Object | Meaning |
|---|---|
| **Carrier** | One operator network: `code`, name, ISO country, PLMN (`MCC-MNC`), optional `legal_entity` for group views |
| **NF target** | One network-function endpoint: `nf_id`, `nf_type` (amf, smf, sepp, ipsecgw, …), `endpoint` host:port, `environment`, `plane` |
| **Roaming partner** | An inter-PLMN agreement (`partner_plmn`), optionally mapped to the SEPP that protects it |
| **Verdict** | One NF's classification from the latest pass: status, severity, findings, `crypto_inventory`, fingerprint |

## Registering the estate (read-only probes, never intrusive)

```bash
# mutations are telecom.manage-gated (superadmin / ciso / security_analyst)
curl -X POST $API/api/v1/telecom/carriers -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"code":"de-telekom","name":"Deutsche Telekom","country":"de","plmn":"262-01","legal_entity":"dt-group"}'
curl -X POST $API/api/v1/telecom/targets -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"nf_id":"amf-lab-01","nf_type":"amf","endpoint":"10.0.0.5:8080","carrier_code":"de-telekom","environment":"lab","plane":"5gc"}'
curl -X POST $API/api/v1/telecom/roaming-partners -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"id":"orange-fr:208-01","carrier_code":"de-telekom","partner_name":"Orange France","partner_plmn":"208-01","country":"fr","sepp_nf_id":"gw-za-01"}'
```

Registry path resolution: `CRYPTOSCAN_TELECOM_REGISTRY` env var →
`<CRYPTOSCAN_ROOT>/config/telecom_registry.json` → writable fallback under
`CRYPTOSCAN_HOME`. `GET /telecom/registry` shows what is registered.

## Scanning and reading the posture

```bash
curl -X POST $API/api/v1/telecom/scan -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{"timeout": 3.0}'
curl -s $API/api/v1/telecom/posture -H "Authorization: Bearer $T"     # per-NF verdicts
curl -s $API/api/v1/telecom/roaming -H "Authorization: Bearer $T"     # roaming + SEPP readiness
curl -s $API/api/v1/telecom/roadmap -H "Authorization: Bearer $T"     # migration view
curl -s $API/api/v1/telecom/events -H "Authorization: Bearer $T"      # event feed
```

Probes are TLS/certificate handshakes (starttls-aware, SNI-aware, optional
HTTP check) — no exploitation, no agents on the network functions.

**Honesty rule:** a roaming row's `pqc_ready` is `False` unless hybrid
ML-KEM was actually observed in the probe. Configured-but-not-probed is
reported as such, never inferred.

## PQC adoption journey

`GET /telecom/journey` turns per-pass drift detection into the trend answer:
per-NF readiness **eras** (consecutive passes with the same verdict coalesce
into one era; a flip opens a new era), transitions, and adoption % over
tracked NFs. Fed by every writer — API scans, operator ingest, monitor-daemon
TELECOM passes — and file-backed, so an API restart keeps the history. The
roaming view (`GET /telecom/roaming`) joins each partner row with its
protecting SEPP's journey (`pqc`: ready / since / flips / passes). Honest
empties: nothing probed yet reports `nf_tracked: 0` with `adoption_pct:
null` — never a fabricated percent. Dashboard: **Telecom** page, "PQC
adoption journey" panel.

## Operator ingest and carrier packs

Network functions that cannot be probed directly can **push** observations
via `POST /telecom/ingest` (operator-authenticated), so closed networks are
still inventoried. Export a per-carrier pack for audit:

```bash
curl -s "$API/api/v1/telecom/pack?carrier=de-telekom&format=json" -H "Authorization: Bearer $T"
```

## Where it feeds the engagement

Telecom rows appear in the estate CBOM, in the examiner audit pack
(`GET /audit-export/pack`) and in the PoC exit report — registered-but-empty
passes report honest zeros; a never-scanned telecom estate is **absent**
from the exit report, not zeroed. Operations (monitoring, troubleshooting,
restart behavior): [runbooks/telecom-operations.md](../runbooks/telecom-operations.md).
