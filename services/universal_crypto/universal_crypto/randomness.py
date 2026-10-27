"""§25 Cryptographic randomness detection.

Analyze RNG / CSPRNG / OS entropy source / DRBG / seed handling / weak
random APIs. Dangerous patterns (predictable randomness) are flagged only
where the evidence supports it — a call to ``random.random()`` feeding a
crypto key is evidence; ``random`` imported alone is not.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

#: strong sources (CSPRNG / OS entropy)
STRONG_RNG: dict[str, str] = {
    "os.urandom": "OS entropy", "secrets.token_bytes": "OS entropy",
    "secrets.token_hex": "OS entropy", "SecureRandom": "CSPRNG",
    "RAND_bytes": "CSPRNG", "getrandom": "OS entropy",
    "RandomNumberGenerator": "CSPRNG", "random_bytes": "OS entropy",
    "OpenSSL::Random": "CSPRNG", "crypto.randomBytes": "CSPRNG",
    "OsRng": "OS entropy", "getrandom::getrandom": "OS entropy",
    "crypto/rand": "OS entropy", "CSPRNG": "CSPRNG",
}

#: weak sources — flagged only when the value flows into a crypto operation
WEAK_RNG: dict[str, str] = {
    "random.random": "predictable PRNG (Mersenne Twister)",
    "random.choice": "predictable PRNG (Mersenne Twister)",
    "random.Random": "predictable PRNG (Mersenne Twister)",
    "random.seed": "explicit PRNG seed",
    "numpy.random": "predictable PRNG (Mersenne Twister)",
    "rand()": "C library rand (LCG)",
    "srand": "explicit PRNG seed",
    "java.util.Random": "predictable PRNG (LCG)",
    "Math.random": "predictable PRNG",
    "mt19937": "Mersenne Twister without crypto seeding",
    "Random(": "non-crypto Random",
}

_CRYPTO_FLOW = re.compile(
    r"(?:key|iv|nonce|salt|seed|token|secret|password|aes|rsa|encrypt|cipher|signature)"
    r"\s*[=:]", re.IGNORECASE)


class RandomnessAnalyzer:
    """§25 randomness analysis over source lines."""

    def analyze(self, lines: Iterable[str], *, asset_id: str = "default",
                location: str = "") -> dict[str, Any]:
        strong: list[dict[str, Any]] = []
        weak: list[dict[str, Any]] = []
        text = "\n".join(lines)
        # seed handling (§25): an explicit seed is dangerous when the same
        # file also feeds a PRNG into crypto material generation
        seed_sources = [s for s in WEAK_RNG
                        if "seed" in WEAK_RNG[s].lower() and s in text]
        crypto_flow_in_file = any(_CRYPTO_FLOW.search(line) for line in lines)
        for lineno, line in enumerate(lines, start=1):
            for source, kind in STRONG_RNG.items():
                if source in line:
                    strong.append({"source": source, "kind": kind,
                                   "line": lineno,
                                   "location": f"{location}:{lineno}" if location else str(lineno)})
                    break
            for source, kind in WEAK_RNG.items():
                if source in line:
                    flows_into_crypto = bool(_CRYPTO_FLOW.search(line))
                    # explicit seeds flag when crypto material is generated
                    # anywhere in the same file
                    seeded = source in seed_sources and crypto_flow_in_file
                    weak.append({"source": source, "kind": kind,
                                 "line": lineno,
                                 "flows_into_crypto": flows_into_crypto,
                                 "flagged": flows_into_crypto or seeded,
                                 "location": f"{location}:{lineno}" if location else str(lineno)})
                    break
        flagged = [w for w in weak if w["flagged"]]
        return {
            "asset_id": asset_id,
            "strong_sources": strong,
            "weak_sources": weak,
            "flagged": flagged,
            "verdict": "DANGEROUS_PATTERN" if flagged else (
                "NO_STRONG_SOURCE" if not strong and weak else "OK"),
        }
