# Real HSM/provider qualification

`python scripts/hsm_qualification.py` is a fail-closed evidence harness. It
never exports, prints or stores private-key material, PINs, credentials or raw
provider secrets.

## Provider run

Run from a controlled host with one customer-owned test key and the provider's
normal credential mechanism:

```bash
HSM_PROVIDER=aws \
HSM_KEY_ID='arn:aws:kms:region:account:key/id' \
python scripts/hsm_qualification.py --strict --out docs/hsm-evidence/aws.json

HSM_PROVIDER=azure HSM_AZURE_VAULT_URL='https://vault.managedhsm.azure.net/' \
HSM_KEY_ID='qualification-key' \
python scripts/hsm_qualification.py --strict --out docs/hsm-evidence/azure.json

HSM_PROVIDER=gcp HSM_KEY_ID='projects/.../cryptoKeyVersions/1' \
python scripts/hsm_qualification.py --strict --out docs/hsm-evidence/gcp.json

PKCS11_LIB=/customer/vendor/libcryptoki.so PKCS11_SLOT=0 \
HSM_PROVIDER=pkcs11 HSM_KEY_ID='customer-key-label' \
python scripts/hsm_qualification.py --strict --out docs/hsm-evidence/pkcs11.json
```

The adapter performs provider metadata and an in-boundary sign challenge.
Strict qualification also requires operator wrappers for real rotation,
revocation and provider audit-log correlation:

```bash
HSM_ROTATION_COMMAND='/secure/provider-tests/rotate-key.sh' \
HSM_REVOCATION_COMMAND='/secure/provider-tests/revoke-key.sh' \
HSM_AUDIT_LOG_COMMAND='/secure/provider-tests/export-audit-correlation.sh' \
python scripts/hsm_qualification.py --strict ...
```

The lifecycle evidence bundle supplied with `--evidence` must separately
contain the non-secret results. Its schema requires a `key_id_digest`,
FIPS/provider metadata and PASS statuses for rotation, revocation and audit
logging; it must not contain PEM/private-key material. A local SoftHSM2 result
is a development gate only, not customer HSM, CloudHSM or Managed HSM evidence.

An outage probe is intentionally bounded. It accepts an operator-supplied
endpoint and recovery command; it does not kill a provider or infer that a
network refusal proves application failover. Attach provider audit logs and
application recovery logs to the report in the controlled evidence store.
