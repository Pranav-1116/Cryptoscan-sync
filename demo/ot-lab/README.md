# OT lab captures

Passive observation dumps for the OT/ICS scanner. CryptoScan never sends packets
toward these devices.

| File | What it shows |
| --- | --- |
| `opcua.otlog` | Siemens S7-1500: unencrypted `None` plus `SignAndEncrypt` / Basic256Sha256 |
| `modbus.otlog` | Plain Modbus TCP (no native crypto) |
| `dnp3.otlog` | DNP3 without Secure Authentication |

```bash
python scripts/run_ot_scan.py demo/ot-lab
```
