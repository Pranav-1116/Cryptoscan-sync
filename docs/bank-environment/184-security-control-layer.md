# Guide 184 — the security control layer becomes something a bank can operate

**Positioning (unchanged, verbatim):** CryptoScan integrates with the bank's existing network and
security controls to build an evidence-backed cryptographic and security estate model.

Guides 181–183 built the layer and hardened its five guarantees. This guide answers the second
review (items 12–19), all of which shared one shape: *the code was right and the operation was not
finished*. Four modules each decided for themselves whether they were in production; the RLS
provisioning sequence lived in a runbook paragraph that every deployment retyped; "we take
backups" was never followed by a restore; the compose contracts could pass by not running; the
point-in-time claim had no bank-side prerequisite; the layer had no console, no translations for
the console it did not have, and no export a SIEM could ingest.

| # | Item | What was wrong | What exists now | Evidence |
|---|---|---|---|---|
| 12 | Four production detectors | four modules compared `ENVIRONMENT` four ways; a `.env`-configured deployment looked like development to whichever gate read `os.environ` | one predicate in `shared_config/environment.py`, imported by every gate — **eight** call sites, down from whichever file you happened to read | `test_environment_detector.py` (26 tests) |
| 13 | RLS provisioning was manual | production refuses a superuser/`BYPASSRLS` role; nothing scripted creating the right one | `scripts/provision_runtime_role.py` — `plan`/`apply`/`verify`, refuses inline passwords and reserved identities | `test_runtime_role_provisioning.py` (25) |
| 14 | No restore drill | API refuses an unapproved target and refuses PITR on a `pg_dump`; nothing ever restored | `scripts/restore_drill.py` + weekly workflow, hash-chained receipts | `test_restore_drill.py` (14) |
| 15 | Contracts skip-able | `pytest.mark.skipif` on a missing `docker compose` is green by absence | CI asserts `docker compose version` before rendering; the contract suite **fails** in CI when the CLI is absent, and only skips locally | `test_ci_workflow_contract.py` |
| 16 | PITR unowned | the honest wording had no counterpart on the bank's side | a nine-line prerequisite checklist at the top of `docs/runbooks/dr-recovery.md`, including "the shipped overlay archives nothing" | runbook |
| 17 | No console | the layer's whole output was JSON | `/security-controls` — controls, findings, refusals, chain, export; every state named, never a green list | `SecurityControls.test.tsx` (6) |
| 18 | i18n regression | a `t()` file grew hardcoded English labels, help text, headers and errors | 76 keys in `en.json` **and** `ar.json`, plus a test that fails on inline English | `Resilience.i18n.test.ts` (4) |
| 19 | Exports | findings could not leave the UI | CycloneDX 1.6 (schema-validated) and escaped CEF, from the same rows the console reads | `test_security_controls_export.py`, API export tests |

## 1. One production predicate (item 12)

The bug was not a wrong comparison. Every one of the four detectors compared the right string.
The bug was that there were four of them, so a deployment configured through `.env` looked like
development to whichever gate happened to read `os.environ`.

Item 12 asked for one function in `shared_config`. Following "one" honestly turned up **four more**
detectors the review had not named — `api/platform_state.py`, `api/middleware/security_headers.py`,
`api/routers/compliance.py`, `api/routers/telecom.py`, `api/security/passwords.py`,
`shared_models/redis_connection.py` — plus three scripts. All eight runtime gates now call
`shared_config.environment`:

```python
from shared_config import environment as platform_environment
is_production = platform_environment.is_production()      # the only question a gate should ask
environment = platform_environment.environment_name()     # when the gate needs staging too
```

Three decisions worth stating:

* **An unrecognised value is treated as production.** A typo (`prodcution`) must not downgrade a
  bank into development mode where guards relax. The detector says so in its own `note`.
* **The answer carries its provenance** — `{"value", "normalised", "effective", "source",
  "recognised", "note"}` where `source` is `<module>.<Class>.ENVIRONMENT`,
  `os.environ.ENVIRONMENT`, `environ argument` or `default`. "Which config did this process
  actually read" is now answerable, which is the question an incident asks.
* **The function is `environment_name()`, not `environment()`.** Re-exporting a function named
  `environment` from a package that also has an `environment` module makes
  `from shared_config import environment` return a module or a function depending on import order.
  That is precisely the class of bug this item exists to end.

The test that matters is not the alias table — it is the static scan that fails the suite if any
module outside `shared_config` compares an environment token with a production literal again.

## 2. RLS provisioning, scripted (item 13)

`scripts/provision_runtime_role.py` is the runbook paragraph in executable form:

```
python scripts/provision_runtime_role.py plan   --role cryptoscan_app --database cryptoscan
CRYPTOSCAN_PROVISION_ACK=1 python scripts/provision_runtime_role.py apply --dsn "$MIGRATION_DSN"
python scripts/provision_runtime_role.py verify --dsn "$CRYPTOSCAN_APP_DATABASE_URL"
```

It refuses a bootstrap identity (`postgres`, `root`, `cryptoscan`, `rdsadmin`), refuses a role name
it would have to quote and hope for, refuses a DSN with an inline password, and never renders a
`PASSWORD` clause. `verify` measures twelve facts from the runtime connection — including
`relforcerowsecurity`, because ENABLE without FORCE leaves the table owner exempt — and insists
the measuring connection *is* the runtime role. `apply` succeeding proves the SQL ran; only
`verify` speaks about binding, and the receipt says exactly that.

## 3. The restore drill (item 14)

`scripts/restore_drill.py` restores a real archive into `CRYPTOSCAN_RESTORE_TARGET_DB`, then
measures the result: schema, table counts, missing tables, migration revision, RLS binding. The
receipt is hash-chained into `restore-drill-history.jsonl`, so "we drilled on the 3rd" carries a
digest.

It refuses: no target, target equal to the source, a non-PostgreSQL engine, an empty store, a
named backup that does not exist, and **point-in-time on a `pg_dump`** — because a logical dump
carries no WAL, and restoring to "now" while reporting the requested timestamp would be theatre.
An empty restore is reported as `RESTORED_EMPTY` and its `claims.backup_restores` is `false`.

`.github/workflows/restore-drill.yml` runs it weekly against a disposable PostgreSQL pair, uploads
the receipt and the history as a 365-day artifact, and fails the job unless the result is
`RESTORED_AND_MEASURED`.

## 4. CI has the CLI (item 15)

The two compose contracts shell out to `docker compose config`; without the CLI they skipped, and a
skipped contract reports the same colour as a passing one. The `prod-config-guard` job now asserts
`docker compose version` *before* rendering, and the contract suite fails inside CI when the CLI is
missing — skipping is allowed only on a developer sandbox (`CI` unset). Two tests keep it honest:
one asserts the workflow step exists and precedes the render, the other asserts the suite cannot
skip itself green.

## 5. PITR stays the bank's (item 16)

The claim stays "not provided". `docs/runbooks/dr-recovery.md` now opens with a nine-line
bank-side prerequisite checklist: WAL archive destination, a real `archive_command` (the shipped
overlay sets `/bin/true`, which archives nothing), a physical base-backup schedule, WAL retention
covering the recovery window, a designated recovery host, a rehearsed recovery command, a measured
PITR drill, the scheduled restore drill, and key escrow. An unticked line is a gap, not a task for
the day of the incident.

## 6. The console (item 17)

`/security-controls` renders five tabs — controls, findings, refusals, chain, export — from the
routes that already existed. The design rule is the one the layer keeps failing in other people's
UIs: **"no findings" is four different facts**. A control nobody configured, a control whose
device refused, a control that was unreachable and a control that was read with nothing to report
each get their own state, their own meaning and their own next step. With no snapshot at all the
page says "no control has been read yet" rather than showing an empty table. There is no restore,
apply, delete or probe button.

## 7. i18n (item 18)

`Resilience.tsx` had 76 hardcoded English strings in a file that already called `t()`: labels,
help paragraphs, table headers, table rows and `setErr` messages. All 76 now live in `en.json`
and `ar.json`, keeping the English identical so the existing tests and the rendered English are
unchanged. `Resilience.i18n.test.ts` asserts every key the page asks for exists in both
dictionaries, that no English sentence survives inline, that nothing falls back to rendering its
own key, and that the Arabic is not a copy of the English (four protocol/digest terms excepted).

## 8. Exports (item 19)

`GET /security-controls/export?format=cyclonedx|cef` projects the same rows the console reads.

* **CycloneDX 1.6**, validated against the official schema. CycloneDX has no "control" primitive,
  so nothing is invented: each control is a `platform` component with a `urn:cryptoscan:control:*`
  bom-ref, and each finding is a 1.6 `annotation` whose `subjects` are those refs — the spec's own
  "note attached to one or more subjects". Evidence ids ride as `cryptoscan:evidence.id`
  properties; observation class, read state and refusals ride as `cryptoscan:*` metadata
  properties, and a partial estate says `cryptoscan:estate_completeness`.
* **CEF 0**, one line per finding, with `cs1Label=EvidenceId` so a SIEM alert joins back to the
  snapshot. Header and extension values are escaped, so a device string containing `|`, `=`, a
  space or a newline cannot forge a field.

Both refuse to upgrade a claim: a control that was never read exports as `CONFIGURED`, a refusal
exports as `REFUSED` with its reason, and neither exporter ever states that the estate is complete.

## 9. What this guide does not prove

* **No real device was read.** Every live probe goes through a recorded transport: the dialects
  are exercised, the devices are not.
* **No PITR.** Nothing here restores to a timestamp; the prerequisite checklist is a to-do for
  the bank, not an implementation.
* **The drill proves one archive, one target.** It says so in its own `claims` block.
* **The console and the exports were not exercised in a browser in this environment** — the
  frontend suite is written but `node_modules` is absent here, so the vitest files are unrun
  locally and will first execute in CI.
* **Nothing here qualifies the bank's controls.** A green state means the platform could read a
  device and had nothing to report — not that the control works.

Harness: `scripts/cbom_security_controls_live.py --check` → **18 pass / 0 partial / 0 fail**,
with the new **L-17** (one production predicate, typo fails closed) and **L-18** (CycloneDX
validates, CEF escapes, refusal stays a refusal). Machine-readable:
`184-security-control-layer.{json,md}`.
