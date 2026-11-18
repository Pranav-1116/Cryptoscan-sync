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

1. **Console → Platform → Agent fleet → enrol agent.** Type a unique name, e.g.
   `mrdn-prod-dc1-swiftgw01` (`<bank>-<env>-<dc>-<hostname>`). Names are unique; a
   duplicate is refused. The console shows a **one-time token** and the install command.
2. **On the server**, run the command it shows:
   ```sh
   sudo ./install.sh --server https://cryptoscan.bank.example --agent-id <id> --token <token>
   ```
   The agent makes its own Ed25519 key pair (the private key never leaves the host),
   sends the public key with the token, and receives a machine key that can only post
   observations and heartbeats. The token is now used up.
3. **Every hour** (configurable) it collects, signs and sends. The console checks the
   signature against the key it registered in step 2 (`authenticity = VALID`), checks
   that the agent is speaking only for itself, and adds this host's slice to the estate.
   Other agents' hosts are never overwritten. Unchanged hosts send `NO_CHANGE`.
4. **Every minute** a heartbeat keeps the agent `connected` in the fleet view.

A rebuilt host keeps its name: click **new token** on its row (or re-run the automated
rollout) and enrol again with `--force`. **retire** revokes the agent's machine key.

## Commands

```sh
cryptava collect                 # read this host and show the six parts — sends nothing
cryptava collect --output o.json # write the full observation to a file for review
cryptava enroll --agent-id ID --token TOKEN [--server URL]
cryptava run --once              # one collect → sign → send → heartbeat
cryptava run                     # the service loop (used by systemd)
cryptava status                  # identity (never the API key) and the last run
```

## Install options

| Where | How |
|---|---|
| One Linux server | `packaging/install.sh` (systemd unit with a read-only, capability-limited sandbox) |
| A fleet | `packaging/ansible/` role — one-step enrolment with an admin key kept in Ansible Vault |
| Kubernetes nodes | `packaging/kubernetes/cryptava-daemonset.yaml` (node filesystem read-only at `/host`) |
| Container image | `packaging/container/Dockerfile` |
| The CryptoScan sandbox | `./sandbox/run_sandbox.sh agents` — four agents on the simulated bank hosts |

Configuration: `packaging/config/cryptava.toml.example` (or JSON; every key can also be
set as `CRYPTAVA_<KEY>`). Identity and key: `/var/lib/cryptava/` (mode 0700, files 0600).

## What it does not cover yet

* Windows, AIX and mainframe hosts (Linux only).
* Database-internal encryption (TDE) and HSM partition contents — these need the
  agentless readers with database/HSM credentials.
* Vendor contracts and support entitlements — import them from the CMDB.

## Tests

```sh
python -m pytest services/cryptava/tests          # agent: parsers, signing, fake host, guards
python -m pytest services/api/tests/unit/test_cryptava_agent_flow.py   # agent ↔ real API
```
