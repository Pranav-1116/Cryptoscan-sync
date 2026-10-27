"""Runtime crypto engine (spec 92).

The runtime question is stronger than the static one:

    static   — what cryptography is present / configured / referenced?
    runtime  — what cryptographic operation actually ran, in which process,
               with which algorithm, key size, mode and parameters?

Every module here is built around one honesty rule: an observation reports what
its adapter could see. Anything else is ``UNKNOWN``, and the *attribution level*
of the observation (how it was obtained) travels with the fact, so a Level 4
network observation is never presented as a Level 1 crypto-API observation.
"""

from runtime.engine.adapters import ADAPTERS, adapter_catalog, get_adapter
from runtime.engine.assets import (
    build_runtime_cbom,
    build_runtime_techbom,
    summarize_runtime_events,
)
from runtime.engine.events import (
    CryptoObservationRejected,
    build_runtime_event,
    build_runtime_events,
)
from runtime.engine.levels import (
    LEVEL_DESCRIPTIONS,
    LEVEL_NAMES,
    level_for_evidence,
)
from runtime.engine.policy import (
    DEFAULT_RUNTIME_POLICY,
    evaluate_runtime,
    runtime_pqc_readiness,
)
from runtime.engine.scope import (
    RuntimeScopeViolation,
    check_runtime_scope,
    normalize_runtime_scope,
    scope_window_state,
)

__all__ = [
    "ADAPTERS",
    "DEFAULT_RUNTIME_POLICY",
    "LEVEL_DESCRIPTIONS",
    "LEVEL_NAMES",
    "CryptoObservationRejected",
    "RuntimeScopeViolation",
    "adapter_catalog",
    "build_runtime_cbom",
    "build_runtime_event",
    "build_runtime_events",
    "build_runtime_techbom",
    "check_runtime_scope",
    "evaluate_runtime",
    "get_adapter",
    "level_for_evidence",
    "normalize_runtime_scope",
    "runtime_pqc_readiness",
    "scope_window_state",
    "summarize_runtime_events",
]
