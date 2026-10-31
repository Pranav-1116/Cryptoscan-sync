"""One simulation engine, several questions — a subject, a change, a recompute.

Until now "simulation" in this product meant one question at a time: the PQC
migration planner, the twin's scenario kinds, the agility catalogue. Each carries its
own idea of what a simulation is, and none of them can answer "what happens to the
estate if *this* asset changes" without someone writing code for that question.

The engine here is deliberately small and general:

    baseline = evaluate(view, models)        # today's estate
    projected = evaluate(view.apply(changes)) # the estate after the change
    delta = projected - baseline              # what moved, per metric

Three things make it general rather than a PQC planner with a new name:

* **scenarios are data.** A scenario is a JSON document — a subject, a list of
  modifications, and the models to evaluate. It carries no callables, so it can be
  stored, versioned and diffed. `validate` refuses anything that is not plain data.
* **models are pluggable.** A model is a name, what it reads, and a function from an
  estate view to one number with its evidence. Adding a question does not touch this
  engine, and a test registers a model at runtime to prove it.
* **refusal is part of the result.** A modification that names an asset this estate
  does not hold is refused and reported; the scenario does not quietly evaluate a
  smaller change and present the difference as the answer.

What it does not do, and will not pretend to: it does not predict what an attacker
would do, it does not estimate likelihood, and its numbers are counts over evidence,
not risk scores. A simulation over a thin estate is arithmetic on a thin estate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

SCHEMA = "cryptoscan.simulation/1"
SCENARIO_SCHEMA = "cryptoscan.simulation-scenario/1"

#: the only operations a modification may use. Small on purpose: each one has a
#: meaning the models can rely on, and an unknown op is refused rather than ignored.
REMOVE = "REMOVE"
REPLACE = "REPLACE"
ADD = "ADD"
DISABLE = "DISABLE"
OPS: tuple[str, ...] = (REMOVE, REPLACE, ADD, DISABLE)

#: algorithm families a cryptographically-relevant quantum computer breaks (Shor).
#: This is arithmetic for the simulation, **not** the risk position: the authoritative
#: classification, scoring and migration deadlines live in `quantum.risk` and are not
#: reproduced here.
SHOR_VULNERABLE: frozenset[str] = frozenset(
    {"RSA", "DSA", "DH", "ECDH", "ECDSA", "ED25519", "X25519", "TLS1.2", "TLS1.3"}
)


# --------------------------------------------------------------------------- #
# the estate view a simulation reads
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class View:
    """An immutable snapshot: assets, established relationships, crypto artefacts.

    Frozen because a simulation must be replayable — applying a modification returns a
    *new* view, so a baseline and a projection never share mutable state.
    """

    assets: tuple[Mapping[str, Any], ...] = ()
    relationships: tuple[Mapping[str, Any], ...] = ()
    crypto: tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def from_graph(cls, graph: Any) -> "View":
        """Build from an ``EstateGraph`` (or anything with the same three reads)."""
        relationships = [
            edge for edge in graph.relationships() if str(edge.get("status") or "ESTABLISHED") == "ESTABLISHED"
        ]
        # The graph's own projection, not a re-derivation: `crypto_artifacts` already
        # folds evidence into an artefact with its usage state, and a simulation that
        # recomputed it would drift from every BOM built on the same evidence.
        artifacts = graph.crypto_artifacts() if hasattr(graph, "crypto_artifacts") else []
        crypto: list[Mapping[str, Any]] = [
            {
                "asset_id": artifact.get("asset_id"),
                "algorithm": artifact.get("algorithm"),
                "key_size": artifact.get("key_size"),
                "protocol": artifact.get("protocol"),
                "usage_state": artifact.get("usage_state"),
                "role": artifact.get("role"),
                "evidence_ids": list(artifact.get("evidence_ids") or []),
            }
            for artifact in artifacts
        ]
        return cls(
            assets=tuple(graph.assets()),
            relationships=tuple(relationships),
            crypto=tuple(crypto),
        )

    # -- reads ------------------------------------------------------------- #

    def asset_ids(self) -> set[str]:
        return {str(asset.get("asset_id")) for asset in self.assets}

    def asset(self, asset_id: str) -> Mapping[str, Any] | None:
        for asset in self.assets:
            if str(asset.get("asset_id")) == asset_id:
                return asset
        return None

    def dependents(self, asset_id: str) -> list[str]:
        """Assets that reach ``asset_id`` over established edges (transitive)."""
        reverse: dict[str, set[str]] = {}
        for edge in self.relationships:
            subject = str(edge.get("subject") or edge.get("subject_id") or "")
            target = str(edge.get("object") or edge.get("object_id") or "")
            if subject and target:
                reverse.setdefault(target, set()).add(subject)
        seen: set[str] = set()
        frontier = [asset_id]
        while frontier:
            node = frontier.pop()
            for parent in reverse.get(node, ()):  # type: ignore[union-attr]
                if parent not in seen:
                    seen.add(parent)
                    frontier.append(parent)
        return sorted(seen)

    # -- modification ------------------------------------------------------ #

    def apply(self, modifications: Iterable[Mapping[str, Any]]) -> tuple["View", list[dict], list[dict]]:
        """Return ``(projected_view, applied, refused)``.

        A refused modification is *not* partially applied: the returned view is the one
        that would exist if every non-refused change had happened, and the caller is
        told exactly which changes did not.
        """
        assets = [dict(asset) for asset in self.assets]
        crypto = [dict(item) for item in self.crypto]
        relationships = [dict(edge) for edge in self.relationships]
        applied: list[dict] = []
        refused: list[dict] = []

        for modification in modifications:
            op = str(modification.get("op") or "").upper()
            target = str(modification.get("target") or "")
            if op not in OPS:
                refused.append({"modification": dict(modification), "reason": f"unknown op {op!r}"})
                continue
            if not target:
                refused.append({"modification": dict(modification), "reason": "no target"})
                continue
            known = target in {str(asset.get("asset_id")) for asset in assets} or target in {
                str(item.get("asset_id")) for item in crypto
            }
            if op in (REMOVE, REPLACE, DISABLE) and not known:
                refused.append(
                    {
                        "modification": dict(modification),
                        "reason": (
                            f"no asset or crypto artefact {target!r} in this estate — the change "
                            "was not applied, and the projection below does not include it"
                        ),
                    }
                )
                continue

            if op == REMOVE:
                assets = [asset for asset in assets if str(asset.get("asset_id")) != target]
                crypto = [item for item in crypto if str(item.get("asset_id")) != target]
                relationships = [
                    edge
                    for edge in relationships
                    if target
                    not in {
                        str(edge.get("subject") or edge.get("subject_id") or ""),
                        str(edge.get("object") or edge.get("object_id") or ""),
                    }
                ]
            elif op == DISABLE:
                for asset in assets:
                    if str(asset.get("asset_id")) == target:
                        asset["disabled"] = True
                for item in crypto:
                    if str(item.get("asset_id")) == target:
                        item["usage_state"] = "DISABLED"
            elif op == REPLACE:
                attribute = str(modification.get("attribute") or "")
                value = modification.get("value")
                if not attribute:
                    refused.append(
                        {"modification": dict(modification), "reason": "REPLACE states no attribute"}
                    )
                    continue
                hit = False
                for item in crypto:
                    if str(item.get("asset_id")) == target:
                        item[attribute] = value
                        hit = True
                for asset in assets:
                    if str(asset.get("asset_id")) == target:
                        asset[attribute] = value
                        hit = True
                if not hit:  # pragma: no cover - guarded by `known`
                    refused.append({"modification": dict(modification), "reason": "nothing to replace"})
                    continue
            elif op == ADD:
                if known:
                    refused.append(
                        {"modification": dict(modification), "reason": f"{target!r} is already in this estate"}
                    )
                    continue
                entry = {"asset_id": target, "type": modification.get("asset_type") or "UNKNOWN"}
                entry.update({key: value for key, value in modification.items()
                              if key not in {"op", "target", "asset_type"}})
                assets.append(entry)
                # an added asset that states an algorithm brings a crypto artefact with
                # it, or the projection would report a host holding nothing
                if modification.get("algorithm"):
                    crypto.append(
                        {
                            "asset_id": target,
                            "algorithm": modification["algorithm"],
                            "key_size": modification.get("key_size"),
                            "usage_state": "CONFIGURED",
                        }
                    )

            applied.append(dict(modification))

        return (
            View(assets=tuple(assets), relationships=tuple(relationships), crypto=tuple(crypto)),
            applied,
            refused,
        )


# --------------------------------------------------------------------------- #
# models: one question each, no knowledge of any scenario
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Result:
    """One model's answer, with the evidence it was computed from."""

    model: str
    label: str
    metric: str
    value: float
    unit: str = "count"
    evidence_ids: tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "label": self.label,
            "metric": self.metric,
            "value": self.value,
            "unit": self.unit,
            "evidence_count": len(self.evidence_ids),
            "evidence_ids": list(self.evidence_ids)[:50],
            "detail": dict(self.detail),
        }


#: what a model is told besides the view: the subjects the scenario changes. A model
#: that needs them takes them from here rather than from module state, so two
#: simulations can run concurrently without seeing each other's subjects.
Context = Mapping[str, Any]


@dataclass(frozen=True)
class Model:
    """A named question over an estate view.

    ``evaluate`` is a pure function of ``(view, context)``: same inputs, same number,
    no clocks and no module state. A model that needs the scenario's subjects reads
    ``context["subjects"]`` and says so in ``reads``.
    """

    id: str
    label: str
    reads: tuple[str, ...]
    metric: str
    evaluate: Callable[[View, Context], Result]
    #: which direction of change is the bad one. A simulation that called a rise in
    #: coverage "WORSE" would be arithmetic without semantics.
    higher_is_worse: bool = True


def _family(algorithm: Any) -> str:
    text = str(algorithm or "").strip().upper().replace("_", "-")
    if not text:
        return ""
    return text.split("-", 1)[0]


def shor_vulnerable(view: View, context: Context) -> Result:  # noqa: ARG001 - uniform signature
    """Crypto artefacts whose algorithm family a quantum computer would break."""
    hits = [
        item
        for item in view.crypto
        if str(item.get("usage_state") or "ACTIVE").upper() != "DISABLED"
        and (
            str(item.get("algorithm") or "").upper() in SHOR_VULNERABLE
            or _family(item.get("algorithm")) in SHOR_VULNERABLE
        )
    ]
    return Result(
        model="shor_vulnerable",
        label="Quantum-vulnerable crypto artefacts",
        metric="vulnerable_artefacts",
        value=float(len(hits)),
        evidence_ids=tuple(str(item.get("asset_id")) for item in hits if item.get("asset_id")),
        detail={"algorithms": sorted({str(item.get("algorithm")) for item in hits})},
    )


def blast_radius(view: View, *, subjects: Iterable[str]) -> Result:
    """Assets that transitively depend on the subjects named by the scenario."""
    dependents: set[str] = set()
    for subject in subjects:
        dependents.update(view.dependents(str(subject)))
    return Result(
        model="blast_radius",
        label="Assets depending on the changed subjects",
        metric="dependent_assets",
        value=float(len(dependents)),
        evidence_ids=tuple(sorted(dependents)),
        detail={
            "subjects": sorted({str(subject) for subject in subjects}),
            "dependents": sorted(dependents)[:50],
        },
    )


def crypto_coverage(view: View, context: Context) -> Result:  # noqa: ARG001 - uniform signature
    """Fraction of assets for which at least one cryptographic artefact is evidenced."""
    asset_ids = view.asset_ids()
    covered = {str(item.get("asset_id")) for item in view.crypto if item.get("asset_id")} & asset_ids
    total = len(asset_ids)
    return Result(
        model="crypto_coverage",
        label="Assets with evidenced cryptography",
        metric="covered_assets",
        value=float(len(covered)),
        unit="assets",
        evidence_ids=tuple(sorted(covered)),
        detail={"assets": total, "covered": len(covered),
                "uncovered": sorted(asset_ids - covered)[:50]},
    )


def stranded_dependents(view: View, context: Context) -> Result:
    """Assets that depended on a subject which is now disabled or absent.

    The question a bank actually asks before an HSM maintenance window: disabling a
    device does not delete the edges that point at it, so the dependents stay — and
    they are now depending on something that cannot serve them. This measures that,
    against the baseline the scenario started from.
    """
    baseline = context.get("baseline") or view
    subjects = [str(subject) for subject in context.get("subjects") or ()]
    stranded: dict[str, list[str]] = {}
    for subject in subjects:
        asset = view.asset(subject)
        gone = asset is None or bool(asset.get("disabled"))
        if not gone:
            continue
        dependents = baseline.dependents(subject)
        if dependents:
            stranded[subject] = dependents
    return Result(
        model="stranded_dependents",
        label="Assets depending on a now-disabled subject",
        metric="stranded_assets",
        value=float(len({item for items in stranded.values() for item in items})),
        evidence_ids=tuple(sorted({item for items in stranded.values() for item in items})),
        detail={"stranded": {subject: items[:50] for subject, items in stranded.items()}},
    )


BUILTIN_MODELS: tuple[Model, ...] = (
    Model(
        id="shor_vulnerable",
        label="Quantum-vulnerable crypto artefacts",
        reads=("crypto",),
        metric="vulnerable_artefacts",
        evaluate=shor_vulnerable,
    ),
    Model(
        id="blast_radius",
        label="Assets depending on the changed subjects",
        reads=("assets", "relationships"),
        metric="dependent_assets",
        evaluate=lambda view, context: blast_radius(view, subjects=context.get("subjects") or ()),
    ),
    Model(
        id="stranded_dependents",
        label="Assets depending on a now-disabled subject",
        reads=("assets", "relationships", "context:baseline"),
        metric="stranded_assets",
        evaluate=stranded_dependents,
    ),
    Model(
        id="crypto_coverage",
        label="Assets with evidenced cryptography",
        reads=("assets", "crypto"),
        metric="covered_assets",
        evaluate=crypto_coverage,
        higher_is_worse=False,
    ),
)

REGISTRY: dict[str, Model] = {model.id: model for model in BUILTIN_MODELS}

# --------------------------------------------------------------------------- #
# scenarios are data
# --------------------------------------------------------------------------- #


def _plain_data(value: Any, path: str = "scenario") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _plain_data(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _plain_data(item, f"{path}[{index}]")
        return
    if callable(value):
        raise ValueError(
            f"{path} is callable — a scenario must be plain data so it can be stored and diffed"
        )
    if not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError(f"{path} is a {type(value).__name__}, which does not serialise")


def validate(scenario: Mapping[str, Any], *, registry: Mapping[str, Model] | None = None) -> dict[str, Any]:
    """Check a scenario document, and return it unchanged when it is one.

    Refusals are explicit: an unknown model, an unknown op, or a non-data value is an
    error here rather than a quietly shorter simulation later.
    """
    if not isinstance(scenario, Mapping):
        raise ValueError("a scenario must be a mapping")
    _plain_data(scenario)
    try:
        json.dumps(scenario)
    except (TypeError, ValueError) as exc:  # pragma: no cover - _plain_data catches it first
        raise ValueError(f"scenario does not serialise: {exc}") from exc
    if not scenario.get("id"):
        raise ValueError("a scenario needs an id")
    modifications = scenario.get("modifications") or []
    if not modifications:
        raise ValueError("a scenario needs at least one modification")
    for modification in modifications:
        op = str(modification.get("op") or "").upper()
        if op not in OPS:
            raise ValueError(f"unknown op {op!r}; expected one of {', '.join(OPS)}")
    known = {**(REGISTRY), **(registry or {})}
    for model_id in scenario.get("models") or []:
        if model_id not in known:
            raise ValueError(f"unknown model {model_id!r}; registered: {', '.join(sorted(known))}")
    return dict(scenario)


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #


def _evaluate(
    view: View, models: Iterable[str], registry: Mapping[str, Model], context: Context
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for model_id in models:
        out[model_id] = registry[model_id].evaluate(view, context).as_dict()
    return out


def run(
    scenario: Mapping[str, Any],
    view: View,
    *,
    models: Mapping[str, Model] | None = None,
) -> dict[str, Any]:
    """Evaluate a scenario: baseline, projection, and the delta between them."""
    registry: dict[str, Model] = {**REGISTRY, **(models or {})}
    document = validate(scenario, registry=registry)
    targets = tuple(
        str(item.get("target")) for item in document.get("modifications") or [] if item.get("target")
    )
    context: Context = {"subjects": targets, "scenario": document.get("id"), "baseline": view}
    wanted = list(document.get("models") or registry.keys())
    baseline_view = view
    baseline = _evaluate(baseline_view, wanted, registry, {**context, "baseline": baseline_view})
    projected_view, applied, refused = view.apply(document.get("modifications") or [])
    projected = _evaluate(projected_view, wanted, registry, context)

    delta: list[dict[str, Any]] = []
    for model_id in wanted:
        before = baseline[model_id]["value"]
        after = projected[model_id]["value"]
        delta.append(
            {
                "model": model_id,
                "metric": baseline[model_id]["metric"],
                "before": before,
                "after": after,
                "change": after - before,
                "unit": baseline[model_id]["unit"],
                "direction": (
                    "UNCHANGED"
                    if after == before
                    else (
                        "WORSE"
                        if (after > before) == registry[model_id].higher_is_worse
                        else "BETTER"
                    )
                ),
                "evidence_ids": sorted(
                    set(baseline[model_id]["evidence_ids"]) | set(projected[model_id]["evidence_ids"])
                )[:50],
            }
        )

    return {
        "schema": SCHEMA,
        "scenario": {
            "id": document.get("id"),
            "label": document.get("label"),
            "subject": document.get("subject"),
        },
        "models": [
            {
                "id": model_id,
                "label": registry[model_id].label,
                "metric": registry[model_id].metric,
                "reads": list(registry[model_id].reads),
            }
            for model_id in wanted
        ],
        "baseline": baseline,
        "projected": projected,
        "delta": delta,
        "modifications": {"applied": applied, "refused": refused},
        "complete": not refused,
        "note": (
            "this is arithmetic over the evidence in the view: counts before, counts after. It "
            "does not estimate likelihood, does not predict an attacker, and a projection over a "
            "thin estate is arithmetic on a thin estate"
        ),
    }


#: Four scenarios, four subject types, one engine — the point of the whole module.
#: They are plain data: a reader can store one, diff two, or post one without touching
#: Python, and the test suite validates and runs every one of them.
EXAMPLES: tuple[dict[str, Any], ...] = (
    {
        "schema": SCENARIO_SCHEMA,
        "id": "replace-rsa-with-ml-kem",
        "label": "Replace an RSA artefact with ML-KEM-768",
        "subject": {"type": "CRYPTO", "question": "does the quantum-vulnerable count fall?"},
        "modifications": [
            {"op": "REPLACE", "target": "app-payments", "attribute": "algorithm",
             "value": "ML-KEM-768", "key_size": 768}
        ],
        "models": ["shor_vulnerable", "crypto_coverage"],
    },
    {
        "schema": SCENARIO_SCHEMA,
        "id": "hsm-maintenance-window",
        "label": "Disable an HSM for its maintenance window",
        "subject": {"type": "HSM", "question": "which assets are stranded while it is down?"},
        "modifications": [{"op": "DISABLE", "target": "hsm-01"}],
        "models": ["stranded_dependents", "blast_radius"],
    },
    {
        "schema": SCENARIO_SCHEMA,
        "id": "decommission-load-balancer",
        "label": "Remove a load balancer from the estate",
        "subject": {"type": "LOAD_BALANCER", "question": "what loses its termination point?"},
        "modifications": [{"op": "REMOVE", "target": "lb-payments"}],
        "models": ["stranded_dependents", "blast_radius", "crypto_coverage"],
    },
    {
        "schema": SCENARIO_SCHEMA,
        "id": "introduce-pqc-library",
        "label": "Introduce a PQC-capable library onto an asset",
        "subject": {"type": "LIBRARY", "question": "does any metric move before it is used?"},
        "modifications": [
            {"op": "ADD", "target": "asset-new-lib", "asset_type": "LIBRARY",
             "name": "liboqs", "algorithm": "ML-KEM-768"}
        ],
        "models": ["shor_vulnerable", "crypto_coverage"],
    },
)


def catalogue_models() -> set[str]:
    """The model ids registered in this build."""
    return set(REGISTRY)


def catalogue() -> dict[str, Any]:
    """The models this engine can answer, for a caller that must not guess."""
    return {
        "schema": "cryptoscan.simulation-models/1",
        "models": [
            {
                "id": model.id,
                "label": model.label,
                "metric": model.metric,
                "reads": list(model.reads),
                "higher_is_worse": model.higher_is_worse,
            }
            for model in REGISTRY.values()
        ],
        "ops": list(OPS),
        "examples": [dict(example) for example in EXAMPLES],
        "note": (
            "a model is a question over an estate view. Adding one does not change the engine: "
            "it is registered, and a scenario names it"
        ),
    }


__all__ = [
    "ADD",
    "BUILTIN_MODELS",
    "EXAMPLES",
    "DISABLE",
    "OPS",
    "REGISTRY",
    "REMOVE",
    "REPLACE",
    "SCENARIO_SCHEMA",
    "SCHEMA",
    "SHOR_VULNERABLE",
    "Model",
    "Result",
    "View",
    "blast_radius",
    "catalogue",
    "catalogue_models",
    "crypto_coverage",
    "run",
    "shor_vulnerable",
    "validate",
]
