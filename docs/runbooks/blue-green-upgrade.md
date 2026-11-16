# Blue-Green Upgrades — a flip you can undo

The spec marks blue-green deployment **High — "safer upgrades"**. The rule
this runbook exists to keep: *a release that turns out wrong must cost one
command, not one incident.*

## How it works

Two slots sit behind one entry point (`deploy/upstream.active` is the
pointer the nginx upstream template reads):

1. **`prepare --slot green`** — starts the new release beside the running
   one and health-checks it. A green slot that does not come up is stopped
   again; the active slot is untouched. *Activation refuses an unhealthy
   slot — never flip blind.*
2. **`activate --slot green`** — flips the entry point (atomic pointer
   write + `nginx -s reload`). Blue keeps running: the rollback path stays
   open.
3. **`verify --slot green`** — probes the now-active slot. **On failure
   the flip is undone automatically** — the blast radius of a bad release
   is one flip, immediately reversed.
4. **`rollback`** — the manual escape hatch, any time.

```bash
python3 scripts/blue_green.py prepare  --slot green
python3 scripts/blue_green.py activate --slot green
python3 scripts/blue_green.py verify   --slot green   # exits 1 + rolls back on failure
python3 scripts/blue_green.py status
```

`--dry-run` prints the plan and touches nothing — use it in the change
window before the window opens.

## Slot driver

The orchestrator (`scripts/blue_green.py:BlueGreen`) is substrate-agnostic:
the included `PointerFileDriver` targets the compose stack (slot =
`api-blue`/`api-green` compose services, flip = pointer file + nginx
reload). The repo also ships `HAProxyDriver` (`--driver haproxy`) — the
reference second adapter: slot = a server in one HAProxy backend, flip =
the Runtime API over the admin socket (`enable`/`disable server`,
`set server … weight/state`, `show stat` read-back). A green slot is
started at weight 0 (health-checked, zero traffic); `activate` gives it
the weight and drains the other — connection drain, not a cut. `active`
is read back from the pool: a split pool (both slots holding weight)
raises rather than guessing. An F5 pair is the same five methods
(`start/stop/health/activate/active`) against iControl REST — the state
machine does not change.

## Rolling vs blue-green

* **Rolling** (`maxUnavailable: 0` in the k8s deployments and the Helm
  chart) is the default for stateless API pods.
* **Blue-green** is for the risky cuts: major versions, schema-adjacent
  releases, the entry-point tier. The database keeps rolling
  backward-compatible migrations only (see the migration rules) — the
  slots share the database on purpose, so migrations must stay
  expand/contract.

## Verification (the contract, pinned)

`services/api/tests/security/test_infrastructure_contracts.py` pins the
state machine: unhealthy activation refused, failed verify auto-rolls
back, rollback names its target, dry-run changes nothing.
