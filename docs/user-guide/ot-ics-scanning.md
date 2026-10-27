# OT / ICS scanning

CryptoScan observes operational-technology crypto **passively**. It reads
span-port logs, JSON captures, and vendor-exported session dumps. It never
opens a socket toward a PLC, HMI, or RTU.

Supported observations:

- OPC-UA security mode / policy (`None`, `Sign`, `SignAndEncrypt`, Basic256Sha256, …)
- Modbus TCP (no native crypto — flagged unless marked as TLS-tunneled)
- DNP3 Secure Authentication
- IEC 61850 MMS

`send_packet()` is hard-wired to raise `OtSafetyError`. The dashboard OT page
and `POST /api/v1/ot/scan` both report `packets_sent: 0`.

```bash
python scripts/run_ot_scan.py /path/to/authorized-ot-capture
```
