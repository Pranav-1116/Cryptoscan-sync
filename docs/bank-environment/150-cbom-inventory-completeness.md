# Component completeness: unmeasured is not clean

`cryptoscan.cbom-inventory-completeness-guide/1` · generated 2026-11-02T18:42:53.988240+00:00 · **4 pass · 0 partial · 0 fail** · 22 probes

Three questions sit between *no findings* and *no cryptography*:

```
was the component inspected at all?
did every task that ran finish?
do the tasks agree?
```

| state | what an absence of findings means | quotable |
|---|---|---|
| `UNMEASURED` | nobody looked, so the absence of findings is not evidence of absence | no |
| `INCOMPLETE` | part of the component was not inspected, so the absence of findings covers only the part that was | no |
| `EMPTY` | every task finished and found nothing, which is a measurement | yes |
| `CONTRADICTED` | the tasks disagree, so neither the findings nor the absence of them is settled | no |
| `COMPLETE` | every task finished and the findings are the component's inventory | yes |

Sample inventory: 4 component(s): 1 complete, 1 empty, 1 incomplete, 0 contradicted, 1 unmeasured; no total may be quoted for the inventory.

1. **unmeasured is not clean** — a component with no task says nothing about cryptography, not that it has none;
2. **one unfinished task is enough** — the component is `INCOMPLETE` whatever the finished tasks found, because the part nobody looked at is where old crypto lives;
3. **a contradiction is not a majority** — one task reporting clean while another reports a finding is `CONTRADICTED`, carrying both evidence ids;
4. **a claim that cannot be weighed is named** — from an unfinished task it is a *candidate*, from a task that never ran, with no evidence id, or with no task at all it is *refused*;
5. **the total is derived, not asserted** — only `COMPLETE` and measured `EMPTY` components may be counted, and `may_report_total` says whether any total is quotable at all.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `four_readings` | are "we did not look" and "we found nothing" the same sentence? | **PASS** | 6, 0 failing |
| `contradiction` | what happens when two tools disagree about the same component? | **PASS** | 5, 0 failing |
| `unweighable` | which claims cannot be counted, and why? | **PASS** | 6, 0 failing |
| `the_total` | which total may be quoted, and from which rows? | **PASS** | 5, 0 failing |

## `four_readings` — PASS

*are "we did not look" and "we found nothing" the same sentence?* (review 18 / 19)

- **PASS** `a-component-nobody-scanned-is-unmeasured` — legacy-batch was never inspected; no task ran, so nothing is claimed about it
- **PASS** `an-unfinished-task-makes-the-component-incomplete` — payments is partly inspected: syft-sbom did not finish, so the 1 finding(s) cover only the part that was
- **PASS** `every-task-finished-finding-nothing-is-a-measurement` — clean: every one of 2 task(s) finished and none found cryptography, which is a measurement and not an assumption
- **PASS** `agreement-is-complete` — gateway: 1 task(s) finished and produced 1 finding(s) across AES-128-CBC
- **PASS** `every-state-has-a-reading-of-what-an-absence-means` — UNMEASURED: nobody looked, so the absence of finding…; INCOMPLETE: part of the component was not inspected,…; EMPTY: every task finished and found nothing, w…; CONTRADICTED: the tasks disagree, so neither the findi…; COMPLETE: every task finished and the findings are…
- **PASS** `the-four-states-stay-four-states` — UNMEASURED → INCOMPLETE → EMPTY → CONTRADICTED → COMPLETE

## `contradiction` — PASS

*what happens when two tools disagree about the same component?* (review 18 / 19)

- **PASS** `one-task-saying-clean-against-another-finding-is-a-contradiction` — syft-sbom reported no cryptography while semgrep-crypto reported AES-128-CBC; the disagreement is reported, not averaged
- **PASS** `the-contradiction-carries-both-evidence-ids` — EV-1
- **PASS** `a-contradiction-is-not-a-majority-vote` — 2 contradiction(s) from three tasks
- **PASS** `an-unfinished-task-is-the-weaker-claim-and-wins` — both are recorded; the state reports the one that limits what may be said
- **PASS** `two-tasks-agreeing-are-one-algorithm-with-both-evidences` — {"algorithm": "AES-128-CBC", "evidence_ids": ["EV-1", "EV-2"], "tasks": ["semgrep-crypto", "syft-sbom"]}

## `unweighable` — PASS

*which claims cannot be counted, and why?* (review 18 / 12)

- **PASS** `a-finding-from-an-unfinished-task-is-a-candidate` — the task did not finish, so its finding is a candidate and not quotable
- **PASS** `a-finding-from-a-task-that-never-ran-is-refused` — the claim names a task that never ran on this component
- **PASS** `a-finding-with-no-evidence-id-is-refused` — the claim has no evidence id
- **PASS** `a-finding-that-names-no-task-cannot-be-weighed` — a claim that names no task cannot be weighed against the tasks that ran
- **PASS** `a-claim-that-is-not-an-object-is-refused` — a claim must be an object
- **PASS** `a-task-with-no-status-is-unfinished` — silence about a task's outcome is not an outcome

## `the_total` — PASS

*which total may be quoted, and from which rows?* (review 18)

- **PASS** `a-measured-empty-component-makes-a-total-quotable` — 2 component(s): 1 complete, 1 empty, 0 incomplete, 0 contradicted, 0 unmeasured; every component is settled (complete or measured empty), so a total may be quoted
- **PASS** `an-unmeasured-component-stops-the-total` — 2 component(s): 1 complete, 0 empty, 0 incomplete, 0 contradicted, 1 unmeasured; no total may be quoted for the inventory
- **PASS** `an-incomplete-component-stops-the-total-too` — 2 component(s): 1 complete, 0 empty, 1 incomplete, 0 contradicted, 0 unmeasured; no total may be quoted for the inventory
- **PASS** `the-counts-are-per-state-not-a-percentage` — {"COMPLETE": 1, "CONTRADICTED": 0, "EMPTY": 0, "INCOMPLETE": 1, "UNMEASURED": 0}
- **PASS** `an-empty-inventory-quotes-nothing` — 0 component(s): 0 complete, 0 empty, 0 incomplete, 0 contradicted, 0 unmeasured; no total may be quoted for the inventory

## What this does not prove

- the module weighs the tasks it is told about. A component whose collector was never registered looks UNMEASURED, which is honest, but a component whose collector was registered and silently skipped looks COMPLETE or EMPTY
- 'found: false' is a claim the tool must make. A tool that finishes without saying whether it looked at everything can only ever produce INCOMPLETE or COMPLETE, never a contradiction, and the contradiction is the useful row
- a contradiction is reported per algorithm, not per location. Two tools disagreeing about AES-128-CBC in the same file produce one row, and the reviewer still has to read the evidence
- the state is per component, not per file or per directory. A component that was 99% scanned is INCOMPLETE, which is the right answer and also loses the information about which 1% is missing — the task's own reason field carries that, if the collector fills it
- EMPTY is quotable, but it says only that the tasks that ran found nothing. It does not say the tasks were the right ones, and no completeness model can answer that
- the inventory total is a statement about components, not about systems. Joining it to the estate coverage rollup is the coverage renderer's job, and the two totals must not be added together
