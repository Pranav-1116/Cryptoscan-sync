#!/usr/bin/env python3
"""Guide 143 — KMS/HSM key inventory: supported, existing, used are three answers.

The review's item 11 asks where key metadata comes from and whether the CBOM can
tell a *configured* key from a *used* one. Banks get audited on exactly that
distinction (and it is the one a CBOM is most often faked on):

    the HSM supports RSA-4096  !=  an RSA-4096 key exists  !=  RSA-4096 was used

A collector that conflates them over-claims (the module can, so the bank has
one) or under-claims (a key exists but no use was recorded, so the key
disappears). ``cbom.kms_collectors`` keeps them apart:

* ``key_records_from_kms`` — inventory rows into key metadata, metadata only. A
  row carrying key material is **refused**, never sanitised.
* ``usage_events_from_keys`` — usable inventoried keys become ``CONFIGURED``;
  recorded operations become ``RUNTIME_OBSERVED`` and require an inventoried
  key, an operation, an evidence id and a timestamp.
* ``posture`` — weak sizes, rotation past the policy age, and keys whose age is
  unknown rather than assumed fresh.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-kms-collectors-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

AS_OF = date(2026, 6, 1)

KEY = {"provider": "AWS_KMS", "key_ref": "arn:aws:kms:eu-west-1:111:key/abc",
       "algorithm": "AES", "key_size": 256, "mode": "GCM", "purpose": "TLS",
       "status": "ENABLED", "created_at": "2025-01-05", "evidence_id": "KMS-1"}

USE = {"key_ref": "arn:aws:kms:eu-west-1:111:key/abc", "operation": "decrypt",
       "evidence_id": "USE-1", "observed_at": "2026-05-20T10:00:00Z"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "governance"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import kms_collectors, usage_evidence  # noqa: PLC0415

    return {"kc": kms_collectors, "ue": usage_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refusal(result: dict[str, Any], key: str = "refused") -> str:
    refused = result.get(key) or []
    return refused[0]["reason"] if refused else ""


def row_three_answers(modules: dict[str, Any]) -> dict[str, Any]:
    kc, ue = modules["kc"], modules["ue"]
    inventory = kc.key_records_from_kms([KEY])
    probe_set: list[dict[str, Any]] = []

    capability = ue.hsm_evidence("CAPABILITY")
    configured = ue.hsm_evidence("CONFIGURED_KEY", evidence_id="KMS-1")
    operation = ue.hsm_evidence("OPERATION", evidence_id="HSM-1", operation="sign")
    probe_set.append(_probe(
        "the-three-answers-are-three-classes",
        capability["class"] == "VENDOR_DECLARED" and capability["observed"] is False
        and configured["class"] == "CONFIGURED"
        and operation["class"] == "RUNTIME_OBSERVED" and operation["observed"] is True,
        "a capability is a declaration; a configured key is an observation of the inventory; "
        "only an operation is usage"))

    probe_set.append(_probe(
        "an-inventoried-key-is-configured-and-not-used",
        inventory["records"][0]["algorithm"] == "AES"
        and inventory["records"][0]["usable"] is True,
        inventory["statement"]))

    unused = kc.usage_events_from_keys(inventory["records"], [])
    probe_set.append(_probe(
        "a-key-nobody-used-produces-no-runtime-event",
        unused["configured"] == 1 and unused["operated"] == 0
        and "a configured key is not usage" in unused["statement"],
        unused["statement"]))

    used = kc.usage_events_from_keys(inventory["records"], [USE])
    probe_set.append(_probe(
        "a-recorded-operation-is-runtime-and-names-the-key",
        used["operated"] == 1
        and used["events"][-1]["class"] == "RUNTIME_OBSERVED"
        and used["events"][-1]["key_ref"] == KEY["key_ref"]
        and used["events"][-1]["operation"] == "DECRYPT",
        used["statement"]))

    profile = ue.usage_profile({"algorithm": "AES",
                                "parameters": {"key_size": 256, "mode": "GCM"}},
                               used["events"])
    probe_set.append(_probe(
        "the-two-layers-reach-the-usage-profile-separately",
        profile["layers"]["config"]["observed"] is True
        and profile["layers"]["runtime"]["observed"] is True
        and profile["usage"] == "OBSERVED" and profile["confidence"] == "HIGH",
        profile["statement"]))

    from cbom import promotion  # noqa: PLC0415

    key_only = ue.usage_profile({"algorithm": "AES", "parameters": {"key_size": 256}},
                                unused["events"])
    probe_set.append(_probe(
        "a-key-that-exists-is-configured-not-runtime",
        "RUNTIME_OBSERVED" not in key_only["observed_classes"]
        and promotion.promotion_level(key_only["observed_classes"]) == "CONFIGURED",
        f"promoted level {promotion.promotion_level(key_only['observed_classes'])}; "
        "the ladder needs an operation to reach RUNTIME"))

    return {"id": "three_answers",
            "question": "can the CBOM tell a supported algorithm from an existing key from a used one?",
            "phase": "review 11", "probes": probe_set}


def row_never_the_key(modules: dict[str, Any]) -> dict[str, Any]:
    kc = modules["kc"]
    probe_set: list[dict[str, Any]] = []

    material = kc.key_records_from_kms([{**KEY, "private_key": "-----BEGIN PRIVATE KEY-----"}])
    probe_set.append(_probe(
        "a-row-with-key-material-is-refused-not-sanitised",
        material["records"] == [] and "never material" in _refusal(material),
        _refusal(material)))

    unnamed = kc.key_records_from_kms([{"provider": "AWS_KMS", "algorithm": "AES"}])
    probe_set.append(_probe(
        "a-row-with-no-key-reference-is-refused",
        unnamed["records"] == [] and bool(_refusal(unnamed)), _refusal(unnamed)))

    no_evidence = kc.key_records_from_kms([{**KEY, "evidence_id": None}])
    events = kc.usage_events_from_keys(no_evidence["records"], [])
    probe_set.append(_probe(
        "a-key-with-no-evidence-id-is-not-a-configured-event",
        events["configured"] == 0 and "no evidence id" in _refusal(events),
        _refusal(events) or "configured anyway"))

    disabled = kc.key_records_from_kms([{**KEY, "status": "DISABLED"}])
    probe_set.append(_probe(
        "a-disabled-key-is-inventoried-but-not-usable",
        len(disabled["records"]) == 1 and disabled["records"][0]["usable"] is False
        and kc.usage_events_from_keys(disabled["records"], [])["configured"] == 0,
        "inventory keeps it; configuration does not claim it"))

    orphan = kc.usage_events_from_keys(kc.key_records_from_kms([KEY])["records"],
                                       [{**USE, "key_ref": "arn:aws:kms:eu-west-1:111:key/other"}])
    probe_set.append(_probe(
        "an-operation-on-an-uninventoried-key-is-refused",
        orphan["operated"] == 0 and "inventory is incomplete" in _refusal(orphan),
        _refusal(orphan)))

    incomplete = kc.usage_events_from_keys(kc.key_records_from_kms([KEY])["records"],
                                           [{"key_ref": KEY["key_ref"], "operation": "sign"}])
    probe_set.append(_probe(
        "an-operation-without-evidence-or-time-is-refused",
        incomplete["operated"] == 0 and "evidence_id, observed_at" in _refusal(incomplete),
        _refusal(incomplete)))

    probe_set.append(_probe(
        "an-unknown-provider-is-kept-and-marked",
        kc.key_records_from_kms([{**KEY, "provider": "SOMETHING_ELSE"}])["records"][0]
        ["provider_unknown"] is True,
        "coerced into the nearest known provider would be a guess"))

    return {"id": "never_the_key",
            "question": "does the collector store key references only, and refuse what it cannot attribute?",
            "phase": "review 11 / 12", "probes": probe_set}


def row_posture(modules: dict[str, Any]) -> dict[str, Any]:
    kc = modules["kc"]
    records = kc.key_records_from_kms([
        {**KEY, "algorithm": "RSA", "key_size": 1024, "created_at": "2019-01-01"},
        {**KEY, "key_ref": "ec", "algorithm": "ECDSA", "curve": "P-224",
         "key_size": None, "created_at": "2025-12-01"},
        {**KEY, "key_ref": "unknown-age", "created_at": None, "rotated_at": None},
    ])["records"]
    report = kc.posture(records, as_of=AS_OF, max_age_days=365)
    probe_set: list[dict[str, Any]] = []

    weak_refs = sorted(row["key_ref"] for row in report["weak_keys"])
    probe_set.append(_probe(
        "weak-sizes-and-old-curves-are-named",
        len(weak_refs) == 2, f"{len(weak_refs)} weak key(s)"))

    probe_set.append(_probe(
        "rotation-is-judged-against-the-banks-policy-age",
        any(row["age_days"] > 365 for row in report["rotation_overdue"])
        and report["policy_max_age_days"] == 365,
        report["statement"]))

    probe_set.append(_probe(
        "a-key-with-no-recorded-age-is-unknown-not-fresh",
        report["unknown_age"] == ["unknown-age"],
        f"unknown age: {report['unknown_age']}"))

    probe_set.append(_probe(
        "posture-counts-what-the-inventory-actually-names",
        report["by_algorithm"] == {"AES": 1, "ECDSA": 1, "RSA": 1}
        and report["keys"] == 3 and report["as_of"] == "2026-06-01",
        json.dumps(report["by_algorithm"], sort_keys=True)))

    return {"id": "posture",
            "question": "does the inventory say what is weak, what is stale, and what it does not know?",
            "phase": "review 11", "probes": probe_set}


def row_api_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probe_set = [
        _probe("the-kms-route-exists-and-is-typed",
               '@router.post("/kms/keys"' in router
               and "response_model=CbomKmsResponse" in router
               and "class CbomKmsRequest(BaseModel)" in router,
               "POST /cbom/kms/keys"),
        _probe("the-route-requires-a-cbom-reader-role",
               "def cbom_kms_keys(body: CbomKmsRequest," in router
               and "require_roles(*CBOM_USAGE_READERS)" in router.split("def cbom_kms_keys", 1)[1],
               "role-gated, not merely authenticated"),
        _probe("the-route-uses-the-collector-not-a-copy",
               "from cbom import kms_collectors as kc" in router
               and "kc.key_records_from_kms(body.rows)" in router,
               "one implementation, shared with the scripts and tests"),
    ]
    return {"id": "api_exposure",
            "question": "can an operator feed a KMS inventory in and get three separate answers?",
            "phase": "review 11", "probes": probe_set}


ROWS = (row_three_answers, row_never_the_key, row_posture, row_api_exposure)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "rows": rows,
        "limits": [
            "the collector reads rows it is given. It does not call AWS KMS, Azure Key Vault, "
            "GCP KMS or a PKCS#11 device itself, so 'the inventory is complete' is the caller's "
            "claim and the CBOM cannot check it",
            "metadata is only as current as the export. A key created after the inventory run is "
            "invisible, and an operation on it is refused as uninventoried rather than "
            "attributed to the nearest key",
            "rotation posture uses one policy age for the whole inventory. A bank with "
            "per-key-class policies gets one number here, so the finding is a trigger to look, "
            "not a breach",
            "'usable' is decided from a fixed status vocabulary (ENABLED/ACTIVE/AVAILABLE/"
            "IN_USE). A provider with different states is inventoried and marked unusable, "
            "which under-claims rather than over-claims",
            "the distinction supported/exists/used is per key record, not per call site. Two "
            "applications using one KMS key produce one record; separating them needs the "
            "application column filled in the export",
            "private material is refused by field-name heuristics (private_key, secret, "
            "password, material, ...). A provider that returns key bytes in an innocuously "
            "named column would get past the filter, so the export should never contain them",
            "posture does not decide what to migrate: a weak-but-disabled key is still counted "
            "as weak, and the migration judgement belongs to the quantum and assessment engines",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Supported, existing, used: three answers for a key",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's item 11: key metadata has to come from the key store, and the CBOM has "
        "to keep three facts apart that sound alike:",
        "",
        "| Claim | Evidence class | Means |",
        "|---|---|---|",
        "| the module supports RSA-4096 | `VENDOR_DECLARED` | a capability, no key implied |",
        "| an RSA-4096 key exists | `CONFIGURED` | an inventory fact, no use implied |",
        "| RSA-4096 was used | `RUNTIME_OBSERVED` | the only one of the three that is usage |",
        "",
        "`cbom.kms_collectors` implements that boundary: inventory rows become metadata "
        "records (never key material), usable keys become `CONFIGURED` events, and recorded "
        "operations become `RUNTIME_OBSERVED` events that require an inventoried key, an "
        "operation name, an evidence id and a timestamp.",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* ({row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    if not args.check:
        return 0
    if counts[FAIL]:
        return 2
    if counts[PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
