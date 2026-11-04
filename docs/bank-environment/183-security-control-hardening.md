# 183 — Hardening the guarantees

**Status:** built in this guide.
**Layer:** `services/cbom/cbom/security_controls/` (`base.py`, `taxonomy.py`, `drivers.py`, `transport.py`).
**Harness:** `scripts/cbom_security_controls_live.py` — now 16 points, `L-01 … L-16`, 69 probes.
**Artifacts:** `docs/bank-environment/183-security-controls-hardening.{json,md}`.
**API:** `GET /security-controls/health` reports the taxonomy per control.
**Positioning sentence (use verbatim):**

> CryptoScan integrates with the bank's existing network and security controls to build an
> evidence-backed cryptographic and security estate model.

Guide 181 called the guarantees structural and guide 182 made them honest under failure. Both
were true statements; neither was *precise*. This guide is the difference between a promise and
a property — five places where the layer said something reasonable and then did not measure it.

---

## 1. A redaction rule that redacts everything is a broken rule

`PROHIBITED_SHAPES["CARD_NUMBER"]` was `(?<![\d.])(?:\d[ -]?){13,19}(?![\d.])`: any 13–19 digit
run. That matches an epoch in milliseconds (`1735689600000`), a microsecond timestamp
(`1735689600000123`), a 64-bit object id, a serial, an inode, a byte count, a trace id. A guard
that eats those is not a privacy control — it is an outage of the evidence, and it teaches
everyone to ignore the redaction list, which is where the real leaks will be.

**Two checks, both required.** A digit run is a PAN only when it is **Luhn-valid** *and* starts
with an **issuer range** (Visa `4`, Mastercard `51–55`/`2221–2720`, Amex `34`/`37`, Discover
`6011`/`65`, JCB `35`, Diners `30`/`36`/`38`). Luhn alone leaves a one-in-ten false-positive
rate; the IIN prefix takes it to nearly nothing, and the corpus in
`test_security_controls_hardening.py` holds it to zero over twenty legitimate fields.

**An allowlist, published.** `NUMERIC_ALLOWANCES` names the fields where a long digit run is
structural — timestamps, ids, serials, ports, byte counts, versions — and relaxes the *numeric
shape* for exactly those. It relaxes nothing else: `pan` is still a prohibited field under every
spelling, and a PEM key in a field called `timestamp` is still a PEM key. The trade is reviewable
because `redaction_allowlist()` publishes it:

```json
{"numeric_fields": ["timestamp", "serial", "inode", …],
 "allowed_shapes": ["CARD_NUMBER"],
 "card_rule": "… Luhn-valid *and* starts with an issuer range …",
 "never_allowed": ["AWS_ACCESS_KEY", "AUTHORIZATION_HEADER", "BEARER_TOKEN", "PEM_PRIVATE_KEY"]}
```

`L-12` checks both directions: twelve legitimate fields survive with no redaction, four cards
(Visa, Mastercard, Amex-15, Discover) are still caught, and a Luhn-valid number in no issuer
range is left alone.

## 2. Read-only has to be enforced where the bytes leave

The transport allow-list has existed since 182 and `L-01` tested the refusal. It did not test the
thing that matters: **whether the refusal happens above the socket**. A rule that raises *after*
the request is built is a preference, not a lock.

Two changes:

* `_client_factory` was declared on `HttpTransport` and **never used** — a promise the code did
  not keep, and the only hook that would have made the question testable. It is wired now, and
  it is also how a site plugs in its own mTLS session.
* the test injects a client that records every request it is asked to make. Four write verbs are
  refused, and the client's call list is **empty** — no byte was ever assembled, let alone sent.
  `GET` and `HEAD` do reach it, in that order, so the test cannot pass by the client being
  unreachable (`L-13`).

`READ_METHODS == frozenset({"GET", "HEAD"})` is asserted directly, so widening the allowlist is a
failing test rather than a quiet change.

## 3. An evidence id has to survive a version change in both directions

Guide 181's id was `EVID-<CONTROL>-<digest12>` over (control, vendor, system, kind, identity,
facts). The property it wanted — *a re-read of an unchanged rule is the same evidence* — held.
Two things it did not:

**A rule whose text changed under a stable identity.** A device policy keeps `policyid 12` and
changes its source range. If the caller passes only `facts={"action": "accept"}`, the id does not
move, and a diff of evidence ids reports "no change" about a rule that now permits a different
network. The device's own revision (`version`, `revision`, `etag`, `last_modified`,
`config_version`, …) is now discovered by `config_version()` and enters the digest, so a bumped
revision moves the id even when the summarised text does not; and `id_for(..., version=...)` lets
a caller that knows the revision say so explicitly.

**Evolving the digest rule.** Changing what goes into the hash silently re-mints every id, which
invalidates every report that quoted one. Ids are now `EVID-v1-<CONTROL>-<hash>`, the scheme is
`EVIDENCE_SCHEME`, and `evidence_scheme()` classifies an id as `v1`, `v0` (minted before this
guide — still readable, and named as legacy rather than misread) or `UNKNOWN`.
`EvidenceBook.verify()` recomputes a citation and says whether it still holds, without minting
anything: `L-14` checks stability, revision-tracking, the scheme tag, the legacy path and a
six-month-later re-verification.

## 4. Failure has a taxonomy everywhere

"No findings" was four different answers — never asked, refused, unreachable, and read with
nothing to report — and every surface rendered them identically: an empty list.

`taxonomy.py` is the one vocabulary. Nine states, each with a **group** (`COLLECTED`,
`FAILED`, `ABSENT`, `CHOSEN`), a **meaning**, an **operator action**, a **severity** and a
**retryable** flag:

| state | group | means |
| --- | --- | --- |
| `OK` | COLLECTED | every declared section was read |
| `PARTIAL_READ` | COLLECTED | some sections answered; `failed_sections` names the rest |
| `AUTH_FAILED` | FAILED | reachable, and the credential was refused |
| `RATE_LIMITED` | FAILED | the device asked us to slow down |
| `BAD_RESPONSE` | FAILED | the answer is not this dialect |
| `UNREACHABLE` | FAILED | no answer at all |
| `UNSUPPORTED_DIALECT` | ABSENT | no driver exists for this vendor |
| `NOT_CONFIGURED` | ABSENT | no credential, no address, no feed |
| `REFUSED` | CHOSEN | the layer refused on its own rule |

It appears in four places, and they agree because they call the same function:

1. **`health()`** — every collector now carries `state` and `taxonomy`, and passes the driver's
   whole read record through (`sections`, `failed_sections`, `coverage`, `truncated`, `limits`).
   A feed that reports `PARTIAL_READ` is no longer flattened to `REACHABLE`.
2. **the projection summary** — `summary.coverage` with counts, groups, `complete`,
   `nothing_asked` and a sentence: *"3 of 4 control(s) were read; 1 could not be read; the rows
   from the remaining controls are not evidence of their state."* An empty collection says *"no
   control was asked: an empty collection is a collection that did not happen, not one that
   found nothing."*
3. **`live_snapshot()["read"]`** — the state, the coverage, and the failed sections by name.
4. **`GET /security-controls/health`** — the console-facing route: every control the layer knows
   appears with its state, what it means, what to do, and whether it was collected; plus the
   taxonomy itself so a renderer never invents wording. `UNSUPPORTED_DIALECT` is reported for a
   device control with no driver instead of being absent from the list.

`for_diff()` adds the finding an operator most needs: a read that used to be complete and is now
partial. The estate did not change; the collector did.

## 5. Scale is a correctness problem

Nine controls times dozens of devices is hundreds of reads a cycle, and almost none of them
change. Three things, each recorded rather than assumed:

**Incremental, per section.** `SectionCache` keeps a digest per section — digests only, never
rows, so it cannot become the memory problem it exists to avoid. `driver.fetch(cache=…,
skip_unchanged=True)` does not re-emit a section whose rows hash the same, and names it in
`unchanged_sections`. `live_snapshot(..., previous=…, incremental=True)` merges the unchanged
rows back from the previous read, so the snapshot is still *complete* — the omission and the
merge are both in `read`, because a snapshot that silently contains less is worse than one that
fails.

**Coverage per device.** `coverage` reports `sections_declared`, `sections_read`,
`sections_failed` (by name), `sections_unchanged`, a `fraction` and `complete`, per device. Two
devices in one estate do not share a coverage number.

**A memory ceiling, recorded.** `MAX_ROWS_PER_SECTION` (2,000, or `max_rows` per driver) truncates
a section by a stable sort and records `rows_read` / `rows_kept` / `rows_dropped` with the reason:
*a partial section that looks whole is a clean audit of a rule nobody could see.*
`MAX_SNAPSHOT_BYTES` (4 MiB) bounds one device's contribution, `limits` in every read publishes
both, and a section that would exceed the remaining budget is refused as such rather than
silently dropped.

`L-16` checks all three: an unchanged section is skipped, a changed one is re-read, the snapshot
stays complete through the merge, coverage differs per device, and 40 rules past a cap of 10 are
reported as 40 read / 10 kept / 30 dropped.

## 6. What is still not proven

* **Real devices.** Every read is through a recorded transport, and an injected client proves the
  transport refuses to write. Neither proves a FortiGate answers the endpoints.
* **The 2,000-row cap is a guess at "big enough".** It is a starting point chosen so a snapshot
  stays bounded, not a measurement of the largest rule set a bank runs. It is published in
  `limits`, so a site can see when it bites.
* **A PAN in an allowlisted field is not caught.** That is the trade the allowlist makes
  deliberately, and it is why the list is published and the corpus is tested: a field only gets
  onto it if a reviewer agreed it holds a number, not a card.
* **`v0` ids are not migrated.** They are recognised and reported as legacy; nothing rewrites
  them, because rewriting a citation is the failure this guide is about.

## 7. Build decisions recorded

1. **Luhn + IIN, not a length heuristic.** A length rule cannot separate a card from a timestamp,
   and both are 13–16 digits.
2. **An allowlist by field name, not a global exemption.** `pan` stays prohibited; only the
   numeric *shape* is relaxed, and only for named fields.
3. **A scheme token in the id rather than a version column somewhere.** A citation has to be
   self-describing: a report that prints `EVID-v1-…` can be read by a system that has since
   moved to `v2`.
4. **Nine states, grouped into four.** Fewer states would merge `AUTH_FAILED` into
   `UNREACHABLE` (an operator would check the network for a credential problem); more would
   invite a state nobody renders.
5. **Digests in the cache, rows in the caller's store.** A collector that caches rows is a
   collector that runs out of memory on the device it was meant to protect.
