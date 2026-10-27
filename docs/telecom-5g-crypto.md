# Telecom — 5G cryptographic configuration

The TLS probing in `telecom_scanner/classify.py` judges what a network
function **presents on the wire**. This document covers the other half: the
parts of TS 33.501 that live in configuration, where no external probe can
reach and where the permissive setting is indistinguishable from the safe one
in service.

That last property is why these checks exist at all. In every case below the
network works, the call connects, the bars are full, and the dashboard is
green. The only way to find them is to read the configuration.

| Module | Control | The finding that matters |
|---|---|---|
| `suci.py` | SUPI concealment (Annex C) | null-scheme sends the permanent subscriber identity in clear |
| `air_interface.py` | NEA/NIA (§5.11) | NEA0 **ahead of** NEA2 defeats configured AES |
| `n32.py` | inter-PLMN roaming (§13.2) | "end-to-end TLS" through an IPX contracted to modify |
| `authentication.py` | MILENAGE / TUAK | XOR test algorithm in production; OP provisioned instead of OPc |
| `key_hierarchy.py` | K → K_gNB chain (Annex A) | a 256-bit K does not buy a 256-bit radio link |

All five read **declarations**. They perform no concealment, derive no key,
compute no cryptogram, and refuse input that looks like key material
(`looks_like_key_material`) rather than analysing it.

---

## SUPI concealment — `suci.py`

In 2G/3G/4G the IMSI crosses the air in clear during initial attach, which is
what an IMSI catcher exploits. 5G conceals it: the UE encrypts the SUPI into a
SUCI with the home network's public key, so only the home SIDF recovers it.

The fix is optional. Protection **scheme 0 is the null-scheme** — it sends the
SUPI unconcealed and remains legal, because emergency registration needs it
and because not every operator has deployed home-network keys. An operator
running it commercially has 5G radio with 4G privacy, and attach succeeds
normally.

| id | scheme | conceals |
|---|---|---|
| 0 | null-scheme | **no** |
| 1 | ECIES Profile A (Curve25519) | yes |
| 2 | ECIES Profile B (secp256r1) | yes |
| 3–11 | reserved | — |
| 12–15 | operator-specific | **unverifiable** |

Schemes 12–15 are reported as *unverifiable*, not as a pass: they are legal
and opaque, and the honest answer is that configuration cannot settle it.

Both standard profiles are ECIES and therefore Shor-vulnerable. That is
recorded at `info`, not raised as a misconfiguration: a SUCI is decrypted
immediately and never stored, so the harvest-now-decrypt-later exposure is the
subscriber identity of traffic recorded today — real, bounded, and with no
3GPP PQC profile yet published to migrate to.

## Air interface — `air_interface.py`

NEA* for confidentiality, NIA* for integrity, both configured as an **ordered
priority list**. NEA0/NIA0 are null and are legal entries: TS 33.501 permits
NIA0 for unauthenticated emergency calls, where there is no key.

**Order matters as much as membership.** The gNB selects the highest-priority
algorithm the UE also supports, so `NEA0` sitting above `NEA2` means every
capable UE negotiates an unencrypted radio link *even though AES is configured
and present*. A membership-only check reports that configuration as healthy,
which is precisely the case `air.null_ciphering_preferred` exists to catch.

All four standardised algorithms use 128-bit keys (~64-bit under Grover);
3GPP is specifying 256-bit successors. Recorded as an inventory fact for
migration planning, not as a defect today.

## N32 roaming — `n32.py`

N32 is the SEPP-to-SEPP link, and the one 5G interface that routinely crosses
infrastructure neither operator owns. TS 33.501 defines two modes because of
that: **TLS** (end-to-end, opaque to the IPX) and **PRINS** (per-element JOSE,
so an authorised IPX can modify what policy permits, signed and attributable).

The check is not "is it encrypted" but whether the mode matches the topology:

* **TLS declared end-to-end while an IPX may modify** — incompatible. In
  practice something terminates the TLS at the intermediary, so protection
  ends at a third party, usually without either security team being told.
* **PRINS with no IPX** — per-element JOSE complexity and a weaker guarantee
  than plain TLS, for no reason.
* **PRINS with no modification policy, or a wildcard one** — the intermediary
  may rewrite anything; the control is surrendered.
* **`alg: none` JWS** — any party in the path can forge signalling.

Legacy signalling is reported alongside: a protected N32 does not help while
SS7/MAP, Diameter or GTP reach the same subscriber data unprotected. An
attacker picks the weak path.

## Authentication sets — `authentication.py`

MILENAGE (TS 35.205-208, AES-128, K=128) and TUAK (TS 35.231, Keccak-f[1600],
K=128 **or 256**) are both *examples* in the standard; an operator may
substitute its own, so a proprietary set is reported as unassessable rather
than as a pass.

**OP vs OPc is where deployments go wrong.** The value provisioned to a USIM
must be the derived per-subscriber `OPc = OP XOR AES_K(OP)`, never OP. OPc is
specific to one subscriber's K, so extracting it yields one card. OP is
identical across the fleet, so a single extracted USIM — a demonstrated attack
— yields the operator configuration field for every subscriber ever issued,
and it cannot be rotated without reissuing every card. Authentication succeeds
either way.

Two algorithms must never appear: **XOR** (TS 34.108 §8) is a conformance-test
vector with no security property, and finding it means test provisioning
reached production; **COMP128-1** was broken in 1998 and enables SIM cloning.

TUAK with a 128-bit K is flagged at `medium` — TUAK's advantage over MILENAGE
*is* the 256-bit key, so at 128 the migration cost is paid without the benefit.

## Key hierarchy — `key_hierarchy.py`

    K (128 or 256) → CK/IK → K_AUSF → K_SEAF → K_AMF → K_gNB → K_UPenc/K_UPint

Derivations are HMAC-SHA-256 (TS 33.220 Annex B) carrying 256 bits, but every
**leaf key truncates to 128** because NEA/NIA take 128-bit keys.

So the chain is bounded at both ends, and the endpoint reports both numbers
separately. A 256-bit K yields `grover_margin_long_term: 128` alongside
`grover_margin_air_interface: 64`. **Deploying TUAK with a 256-bit K does not
make the radio link 256-bit strong** — it protects the subscriber identity and
the authentication chain. Operators routinely believe the first purchase
bought the second, and a vendor quoting one number is not lying, only silent
about which.

`K_SEAF` must be derived with the **serving-network name** as an input. That
binding is what stops a visited network reusing a roaming subscriber's keys
elsewhere — the anti-bidding-down property 5G introduced over LTE. Omit it and
authentication still succeeds; it fails silently, so it is `critical`.

---

## Endpoints

All gated on `telecom.ingest`.

    POST /api/v1/telecom/suci/analyse            {profiles: [...]}
    POST /api/v1/telecom/air-interface/analyse   {nodes: [...]}
    POST /api/v1/telecom/n32/analyse             {links: [...]}
    POST /api/v1/telecom/authentication/analyse  {profiles: [...]}
    POST /api/v1/telecom/key-hierarchy/analyse   {networks: [...]}

## Limits — state these before anyone quotes coverage

These read **declared configuration**. They will report that a gNB is
*configured* for NEA0; they will not tell you what a UE actually negotiated,
which needs a UE-side capture this product does not perform. Likewise they
report that a UDM is *configured* with OP-provisioning; proving what a USIM
holds needs a card read or an AuC audit.

Do not let this be presented as "we verified the air interface" or "we
verified authentication". It is configuration assurance, which is a real and
useful control — and a different one.

**Not yet covered:** GTP-U / IPsec on the N3 and N9 user-plane interfaces.

61 tests: `services/telecom_scanner/tests/test_5g_crypto.py`.
