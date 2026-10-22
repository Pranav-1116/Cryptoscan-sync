# CryptoScan Runtime Agent

A tiny, **read-only** host agent that tells you exactly which cryptography is
*running* on a machine — which processes have TLS libraries loaded, what
versions, and which TCP ports they listen on. It flags end-of-life and
weak-TLS-capable libraries (e.g. OpenSSL versions past their support date).

The agent is **deterministic** (no AI/ML) and uses only the Python standard
library. It does **not** require root for same-user processes.

## What it detects

From `/proc/<pid>/maps`, `comm`, `cmdline` and the system TCP tables:

- **TLS libraries**: OpenSSL, GnuTLS, NSS/NSPR, wolfSSL, mbedTLS, BoringSSL,
  LibreSSL, plus JVM (`libjvm.so`) and Go (`crypto/tls`) runtimes.
- **Library versions** resolved from the real OS package metadata (`dpkg` on
  Debian/Parrot/Ubuntu/Kali, `rpm` on Fedora/RHEL), with a risk verdict
  (`CURRENT` / `RESTRICTED` / `DEPRECATED` / `DISALLOWED`) and EOL notes.
  The mapped `.so` *soname* is only an ABI tag — `libgnutls.so.30` ships with
  every modern GnuTLS 3.3–3.8 and `libssl.so.3` spans OpenSSL 3.0–3.5 — so the
  agent never flags a library as deprecated from the soname alone; if a
  library is unmanaged (a browser's bundled copy) it is reported as an
  inventory observation, not a false EOL finding.
- **Listening TCP ports** per process (potential TLS endpoints).
- **Containerization** (docker / containerd / kubernetes / lxc markers).

Results are available through the authenticated **`/runtime`** page where its
API/profile is enabled; it is a deep link, not an Operate sidebar placement.

## Quick start (Linux)

The agent is self-contained: the `runtime/` package runs with any Python 3.9+
and **no pip installs**.

```bash
# Point it at your platform and authenticate:
export CRYPTOSCAN_API_URL="https://<your-platform>"
export CRYPTOSCAN_API_TOKEN="<api-token>"

# Scan this machine and submit the findings:
python -m runtime.main once --submit

# Or just print the inventory (no submission):
python -m runtime.main processes
```

`once --submit` prints the server response, e.g.
`{"accepted": 1, "persisted": {"created": 1}, "scanner_id": "runtime-agent-v1.0"}`.
Findings are de-duplicated per host/process/library and refreshed on repeat runs.

If you are running from inside this repository, put the services on
`PYTHONPATH` first (only needed for the richer algorithm registry — the agent
works without it):

```bash
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
python -m runtime.main once --submit
```

## Running on a laptop (this is the normal case)

The machine you scan does **not** need the whole platform — copy the `runtime/`
directory onto the laptop and point it at a reachable platform:

```bash
scp -r services/runtime/runtime user@laptop:~/cryptoscan-runtime/
# on the laptop:
cd ~/cryptoscan-runtime
export CRYPTOSCAN_API_URL="https://<platform-host>"
export CRYPTOSCAN_API_TOKEN="<token>"
python -m runtime.main once --submit      # one-shot scan + submit
```

For continuous visibility, schedule it with cron / systemd timer / Task Scheduler
(every few minutes is fine — repeated runs just refresh the same rows).

### Platform support

| OS        | `processes` / `once`        | `tap` / `import`            |
|-----------|-----------------------------|-----------------------------|
| Linux     | ✅ full `/proc` discovery    | ✅                          |
| macOS     | ⛔ `/proc` not present — use `tap`/`import` or run inside a Linux container/VM | ✅ |
| Windows   | ⛔ same — use `tap`/`import` or WSL | ✅ |

On **macOS/Windows**, the OS-agnostic modes still reveal negotiated TLS:

- **tap** — an observing TLS forward proxy that logs each session's negotiated
  version, cipher suite and certificate chain as JSONL:
  ```bash
  python -m runtime.main tap --listen 0.0.0.0:8443 --upstream api.example.com:443 --jsonl sessions.jsonl
  ```
- **import** — parse an `openssl s_client` capture (or a tap JSONL file):
  ```bash
  openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null > sclient.txt
  python -m runtime.main import sclient.txt --host host
  ```

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `CRYPTOSCAN_API_URL` | — | Platform base URL for submission. |
| `CRYPTOSCAN_API_TOKEN` | — | Bearer token used for submission. |
| `CRYPTOSCAN_RUNTIME_PROC_BASE` | `/proc` | Override the process tree root (used by tests / fixtures). |
| `CRYPTOSCAN_RUNTIME_SESSION_JSONL` | — | Default JSONL path for `tap` sessions. |
| `CRYPTOSCAN_HOSTNAME` / `HOSTNAME` | kernel nodename | Override the reported host identifier. |

Submission is **fail-open**: if the platform is unreachable, the scan still
prints locally and exits non-zero only on a hard scan error.

## Privacy / safety

- Read-only: never touches the scanned processes or opens connections in
  `processes`/`once` mode.
- No secrets, payloads or file contents are read — only mapped library names,
  command lines and listening socket metadata.
- Secrets/credentials are never stored in findings; only the vault-referenced
  API token is used for transport auth.

## Current evidence and deployment boundary — 2026-10-22

Loaded-library/process inventory is not proof that every advertised algorithm ran.
The separate C shim initializes OpenSSL metadata lookup before the first
intercepted EVP call, so a one-call process can retain available cipher/digest
metadata. That does not establish complete runtime coverage or authorize collection.

The console runtime page is the authenticated **`/runtime` deep link**, not an
“Operate” sidebar section. There are six current sidebar sections; use the
[navigation reference](../../docs/NAVIGATION-FEATURE-REFERENCE.md).
The supported controlled production adapter remains **local-source/v1**; host
agent/live ingestion examples require their own approved profile/qualification.
See [current implementation status](../../docs/CURRENT-IMPLEMENTATION-STATUS.md).
