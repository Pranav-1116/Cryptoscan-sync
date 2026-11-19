# Live systems — real-time performance from Cryptava agents

Every server that runs a **Cryptava agent** (`services/cryptava/`) also sends a signed
**performance sample every minute**. ZELNX Performance Intelligence shows those servers
in **Performance → Live Systems (Cryptava agents)**, and a compact table of them sits at
the top of **Performance Overview**. In the sandbox, all seven Meridian Bank servers
report.

The rules from `01_PRODUCT_SPEC.md` hold here too. A figure the agent could not read
is stored and shown as **unknown, with its reason**, never as `0`. Every figure carries
its unit, its source (`cryptava:<agent>`) and its timestamp. Labels are bounded and
never carry secrets. Link capacity is never shown as traffic. A server whose agent has
gone quiet is **stale**, not idle.

## What each sample contains

| Figure (taxonomy name) | How the agent reads it |
| --- | --- |
| `cpu.utilization_pct` | `/proc/stat` delta (host scope) · CPU time of the server's processes ÷ CPUs (workload scope) |
| `system.load` | host scope only: `/proc/loadavg` |
| `ram.utilization_pct`, `container.memory_bytes` | `/proc/meminfo` (host) · resident memory of the server's processes (workload) |
| `storage.capacity/used/available_bytes`, `storage.utilization_pct` | `statvfs("/")` of the server's filesystem |
| `disk.iops`, `disk.throughput_mbps`, `disk.latency_ms` | `/proc/diskstats` delta (host) · `/proc/<pid>/io` of the server (workload) |
| `network.throughput_mbps`, `network.interface_errors` | `/proc/net/dev` delta |
| `network.bandwidth_mbps` | interface link speed: **capacity, not traffic** |
| `network.connections`, `network.tcp_retransmissions` | `/proc/net/tcp*` established sockets · `/proc/net/snmp` delta |
| `process.health` | process states of the server; a zombie makes it `0` |
| `crypto.tls_handshake_ms` (+ `tls_version`, `algorithm`) | a timed TLS handshake against each of the server's own TLS listeners |
| `crypto.tls_negotiation_failures` | a listener that spoke TLS before and now fails |
| `crypto.hsm_operation_latency_ms` | only with `hsm_probe` set: TLS connect + first response from the HSM |

Rate figures always come from two counter readings and the real time between them,
never from one snapshot. **Scope:** `host` measures the whole machine. `workload` is
used when the agent runs as a sidecar sharing the server's processes, so it measures
only that server's processes. Every figure is labelled with the scope it used.

## How a sample is accepted

1. The agent signs the sample (schema `cryptoscan.cryptava-performance/1`) with its own
   Ed25519 key. The private key never leaves the host.
2. It posts the sample to `POST /api/v1/control/agents/heartbeat/performance` with its
   machine key. That key is scoped at activation to the heartbeat path, so it can send
   samples but read nothing.
3. The console checks each sample and refuses it when:
   * it was signed by a key other than the one the agent registered (`signature_not_valid`, `unsigned_sample`);
   * it was sent with another agent's machine key (403);
   * the agent is retired;
   * its timestamp is more than 120 s ahead (`clock_ahead`) or more than 24 h old.
4. Unit and type come from the performance taxonomy, never from the agent. The server
   sets the `agent`, `host`, `system` and `ip` labels itself. A sample cannot overwrite
   them.
5. Each figure becomes one `PerformanceMetric` row:
   * source: `cryptava:<agent>`;
   * evidence: `cryptava-signed:<fingerprint>`;
   * asset: the host's node in the live estate (`<agent>::host`).

   A re-sent sample is reported as a duplicate. It is never stored twice.

Cryptava rows are live operational telemetry. They are **not** bank-signed captures
(`04_BANK_CAPTURE_AND_SIMULATION.md`), so the Twin simulation does not accept them as
production performance context.

## Reading it

`GET /api/v1/performance/live-systems?tenant_id=<t>&minutes=30` (1–120 minutes)
returns one card per activated agent:

* `state`:
  * `live`: a sample within 3 intervals;
  * `stale`: the agent was seen but has gone quiet;
  * `no_samples`: enrolled, but no sample yet (a named gap).
* the newest figures, with units;
* `tls[]`: port, handshake ms, protocol, cipher;
* `missing[]`: each unread figure with its reason;
* `trend`: the last 30 points for CPU, memory, network and TLS.

The console polls every 15 s. The rest of Performance Intelligence now defaults to
**follow live: the last 30 minutes**. Picking a date range stops following.

Agents with no tenant report into `CRYPTAVA_PERFORMANCE_TENANT` (default `default`).
A console user with no organization membership reads that tenant.

## Volume

One agent sends about 17 rows a minute. Seven sandbox servers send about 3,600 rows per
30 minutes, inside the 5,000-sample read budget of a window. For larger fleets:

* raise `performance_interval` on the agents (`0` turns samples off);
* or narrow the window.

A truncated live view says so.

## On the agent

```sh
cryptava perf --print     # read one sample and print it (sends nothing)
cryptava perf --once      # send one sample now
cryptava status --brief   # … · live metrics 17 sent 2026-11-16T08:00:05Z
```

| Config key (`CRYPTAVA_<KEY>`) | Default | Meaning |
| --- | --- | --- |
| `performance_interval` | `60` | seconds between samples; `0` = off |
| `performance_scope` | `auto` | `host`, `workload`, or `auto` (workload when running as a sidecar) |
| `hsm_probe` | — | `host:port` of an HSM to time (e.g. `127.0.0.1:8443`) |
