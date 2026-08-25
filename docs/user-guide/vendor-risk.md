# Vendor crypto discovery

Four discovery methods feed `vendor_crypto_inventory`:

1. Questionnaire (`GET/POST /vendors/{id}/questionnaire`)
2. CycloneDX CBOM import (`POST /vendors/{id}/cbom`)
3. Documentation extraction (`POST /vendors/{id}/docs`)
4. TLS/API observations already stored from the network scanner

`GET /vendor-risks` rolls those observations into a 0–100 score
(crypto strength + PQC posture + data sensitivity + transparency).
