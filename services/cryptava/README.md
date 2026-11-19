# Cryptava — the CryptoScan host agent

Cryptava is one small program you install on each bank server. On a schedule it reads
the machine it runs on and sends one **signed** observation to the CryptoScan console.
The console turns that into six BOMs:

| BOM | What Cryptava reads on the host |
|---|---|
| **HBOM** (hardware) | DMI/sysfs: server make/model/serial, BIOS, CPU (incl. AES-NI / SHA-NI), memory, disks, NICs, PCI devices (incl. crypto accelerators), TPM, dm-crypt volumes, FIPS mode |
| **SBOM** (software) | package databases (dpkg, apk, rpm), Python packages, Java JARs |
| **CBOM** (crypto) | crypto libraries on disk **and which running process loaded them**; certificates on disk and served by local listeners (with their issuing CA); negotiated TLS version/cipher on every local listener; legacy TLS still accepted; SSH host keys and `sshd_config` algorithms; `openssl.cnf`, crypto-policies, nginx/Apache/HAProxy/PostgreSQL TLS settings, Java `java.security` |
| **NBOM** (network) | listening sockets with their owning process, the protocol each speaks (TLS/SSH/PostgreSQL/HTTP/Redis), established outbound connections |
| **VBOM** (vendors) | who supplies each thing found above: hardware maker, CPU vendor, OS publisher (with its public end-of-support date), package supplier, crypto-library project, certificate authority |
| **TechBOM** (topology) | built from all of the above (service → host → hardware, service → library, endpoint → certificate …), plus the business system you name in the config |

## How each BOM is collected — and when it is complete

Every report carries, per BOM, the list of **sources** the agent read and what each one
returned (`read`, `nothing found`, `not on host`, `no permission`, `unavailable`,
`turned off`, `not supplied`). The console shows it per agent: **Discovery → Cryptava
agents →** click an agent **→ how it was collected**. `cryptava collect --json` prints
the same thing on the server (`planes[].sources`).

| BOM | Read from the server | Supplied by the bank | `COMPLETE` when |
|---|---|---|---|
| **HBOM** | `/sys/class/dmi/id`, `/proc/cpuinfo`, `/proc/meminfo`, `dmidecode -t memory`, `/sys/block`, `/sys/class/net`, `/sys/bus/pci/devices`, `/sys/class/tpm` | asset-register **hardware** record — needed where the platform exposes no firmware tables (containers, many VMs, WSL) | platform identity comes from firmware **or** the register, and nothing readable was refused (DIMM layout is only expected when the agent runs on the machine itself) |
| **SBOM** | `/var/lib/dpkg/status`, `/lib/apk/db/installed`, `rpmdb.sqlite` (or `rpm -qa`), `*.dist-info/METADATA`, `*.jar` | — | an OS package database was read in full |
| **CBOM** | crypto `.so` files, `/proc/<pid>/maps`, certificate files in 23 server locations, the trust store, `/etc/ssh`, `openssl.cnf` / crypto-policies, nginx / Apache / HAProxy / PostgreSQL configs, `java.security`, certificates served in TLS handshakes | — | every process's memory map was readable |
| **NBOM** | `/proc/net/{tcp,tcp6,udp,udp6}`, `/proc/<pid>/fd`, a local probe of every TCP listener, established outbound peers | — | sockets were visible and every owner process inspectable |
| **VBOM** | vendor fields of everything above: `/etc/os-release`, DMI / CPU / PCI vendors, crypto-library projects, certificate issuers, package suppliers | asset-register **contracts** (vendor, contract id, support level, dates, account manager) | the contract register was supplied. A vendor without a contract is a *finding* (`no contract on record`), not a gap |
| **TechBOM** | the evidenced links between everything above | business-system mapping (`system` in the config) | the host is mapped to a business system |

### The asset-register record (`/etc/cryptava/asset-record.json`)

The two things a server cannot tell about itself — *what box is this* when firmware is
hidden, and *who are we paying to support it* — come from the bank's CMDB / procurement
system as one small JSON file per server. Install it with `install.sh --asset-record
FILE`, the Ansible variable `cryptava_asset_record`, a container mount at
`/etc/cryptava/asset-record.json`, or point `asset_record` / `CRYPTAVA_ASSET_RECORD`
elsewhere. Everything taken from it is sent as `IMPORTED` evidence naming the register,
never as an observation; when firmware is also readable the serials are cross-checked
and a mismatch is reported.

```json
{
  "source": "Meridian CMDB export",
  "exported_at": "2026-11-01",
  "hardware": {"manufacturer": "Dell Technologies", "model": "PowerEdge R750",
               "serial_number": "7Q2K3X3", "asset_tag": "MRDN-DC1-000412",
               "location": "DC1 / Hall B / Rack 04 / U12", "warranty_end": "2028-04-30"},
  "contracts": [
    {"vendor": "Dell Technologies", "contract_id": "PSP-88213", "support_level": "ProSupport Plus 4h",
     "start": "2023-05-01", "end": "2028-04-30", "account_manager": "R. Iyer",
     "covers": ["Intel", "Broadcom"]},
    {"vendor": "OpenSSL Software Foundation", "contract_id": "OSF-PS-117", "end": "2027-03-31"},
    {"vendor": "Alpine Linux", "support_level": "community"},
    {"vendor": "Meridian Bank", "support_level": "internal", "note": "our own PKI"}
  ]
}
```

`covers` lists component vendors an OEM contract also covers (the CPU and NIC inside a
Dell server); `products` narrows an entry to some of a vendor's products. Contract
states: `ACTIVE`, `EXPIRING_SOON` (≤ 90 days), `EXPIRED`, `COMMUNITY`, `INTERNAL`,
`NONE_ON_RECORD`. The sandbox ships one record per bank server in `sandbox/cryptava/`.

## Safety rules (what Cryptava will never do)

* **It reads, it never changes.** Files are opened read-only. The only programs it may
  run are `dmidecode -t …` and `rpm -qa --qf …`, with fixed arguments and no shell
  (`cryptava/util.py` → `ALLOWED_BINARIES`).
* **No secrets leave the host.** Private-key files are skipped unread. Process command
  lines are never read (they can hold passwords). Only public facts are sent:
  algorithm, key size, curve, fingerprints, validity dates.
* **Every link has proof.** Each relationship is sent together with the evidence that
  shows it; the console refuses anything else.
* **A part it could not read is reported, not hidden.** Each of the six parts reports
  `COMPLETE`, `PARTIAL` or `FAILED` with the reason.
* **Probes stay on the machine.** Listener checks connect to this host only, and can be
  switched off (`probe_listeners = false`) or limited (`probe_exclude_ports`).
* **No third-party packages.** Python 3.9+ standard library only. Signing uses
  `cryptography` if it is installed, otherwise a built-in Ed25519 (RFC 8032).

## How an agent joins (step by step)

1. **Console → Discovery → Cryptava agents → Add a server.** Type a unique name, e.g.
   `mrdn-prod-dc1-swiftgw01` (`<bank>-<env>-<dc>-<hostname>`). Names are unique; a
   duplicate is refused. The console shows a **one-time token** and the install command
   for where the agent will run: **Linux server** (`install.sh`), **Container /
   Kubernetes** (three environment variables) or **Sandbox bank server**
   (`run_sandbox.sh agents add <host> <id> <token>` — see `sandbox/README.md`).
2. **On the server**, run the command it shows:
   ```sh
   sudo ./install.sh --server https://cryptoscan.bank.example --agent-id <id> --token <token> \
        --asset-record /path/to/this-server.cmdb.json     # optional: HBOM identity + VBOM contracts
   ```
   The agent makes its own Ed25519 key pair (the private key never leaves the host),
   sends the public key with the token, and receives a machine key that can only post
   observations and heartbeats. The token is now used up.
3. **Every hour** (configurable) it collects, signs and sends. The console checks the
   signature against the key it registered in step 2 (`authenticity = VALID`), checks
   that the agent is speaking only for itself, and adds this host's slice to the estate.
   Other agents' hosts are never overwritten. Unchanged hosts send `NO_CHANGE`.
4. **Every minute** a heartbeat keeps the agent `online` on the Cryptava agents page
   (no heartbeat for 3 minutes shows it `offline`).
5. **Every minute** it also sends a signed **live performance sample**: CPU, memory,
   disk, network, process health, and a timed TLS handshake against each of the
   server's own TLS listeners. Optionally it also times the HSM response. The server
   shows in **Performance → Live Systems**. A figure it cannot read is sent as unknown
   with the reason, never as zero. See `docs/performance/05_CRYPTAVA_LIVE_SYSTEMS.md`.

A rebuilt host keeps its name: open the agent and click **new token** (or re-run the automated
rollout) and enrol again with `--force`. **retire** revokes the agent's machine key.

## Commands

```sh
cryptava collect                 # read this host and show the six parts — sends nothing
cryptava collect --output o.json # write the full observation to a file for review
cryptava enroll --agent-id ID --token TOKEN [--server URL]
cryptava run --once              # one collect → sign → send → heartbeat
cryptava run                     # the service loop (used by systemd)
cryptava status                  # identity (never the API key) and the last run
cryptava status --brief          # one line: CONNECTED / NOT DELIVERED / NOT ENROLLED, signature check, six BOM results, live metrics
cryptava perf --print            # read one live performance sample and print it — sends nothing
cryptava perf --once             # send one signed performance sample now
```

## Install options

| Where | How |
|---|---|
| One Linux server | `packaging/install.sh` (systemd unit with a read-only, capability-limited sandbox) |
| A fleet | `packaging/ansible/` role — one-step enrolment with an admin key kept in Ansible Vault |
| Kubernetes nodes | `packaging/kubernetes/cryptava-daemonset.yaml` (node filesystem read-only at `/host`) |
| Container image | `packaging/container/Dockerfile` |
| The CryptoScan sandbox | started by `./sandbox/run_sandbox.sh up` — one agent on each of the seven bank servers; `./sandbox/run_sandbox.sh agents check` shows whether each is connected |

Configuration: `packaging/config/cryptava.toml.example` (or JSON; every key can also be
set as `CRYPTAVA_<KEY>`). Identity and key: `/var/lib/cryptava/` (mode 0700, files 0600).

## What it does not cover yet

* Windows, AIX and mainframe hosts (Linux only).
* Database-internal encryption (TDE) and HSM partition contents — these need the
  agentless readers with database/HSM credentials.
* Pulling contracts straight from a CMDB API — the agent reads the per-server export
  (`/etc/cryptava/asset-record.json`); producing that file is the bank's CMDB job.

## Tests

```sh
python -m pytest services/cryptava/tests          # agent: parsers, signing, fake host, guards
python -m pytest services/api/tests/unit/test_cryptava_agent_flow.py   # agent ↔ real API
```
