# IPsec negotiates twice, and PFS is not the DH group in phase 1

`cryptoscan.cbom-ipsec-guide/1` · generated 2026-11-03T01:15:20.888936+00:00 · **6 pass · 0 partial · 0 fail** · 30 probes

Review item 14: a VPN tunnel has two security associations, and a CHILD SA without its own PFS group has no forward secrecy for data even when phase 1 used a strong group.

```
IKE SA    (phase 1)   encryption · PRF/integrity · DH group
CHILD SA  (phase 2)   ESP encryption · ESP integrity · PFS group
  │                                              │
  │                                              └── absent ⇒ no forward secrecy
  └── IKEv1 + aggressive mode + PSK ⇒ offline PSK attack
```

3 IPsec SA pair(s) across 3 peer(s); 2 without a PFS group on the data path; 1 still using IKEv1; weak transforms in use: 3des, dh2, md5, sha1

| transform | rating | why |
|---|---|---|
| `3des` | weak | 64-bit block cipher with a sweet32 birthday bound |
| `des` | weak | 56-bit key |
| `dh1` | weak | 768-bit MODP group |
| `dh2` | weak | 1024-bit MODP group |
| `dh5` | weak | 1536-bit MODP group |
| `md5` | weak | MD5 integrity |
| `modp1024` | weak | 1024-bit MODP group |
| `modp1536` | weak | 1536-bit MODP group |
| `modp768` | weak | 768-bit MODP group |
| `null` | weak | no confidentiality at all |
| `sha-1` | weak | SHA-1 integrity |
| `sha1` | weak | SHA-1 integrity |

Peers without forward secrecy: branch42.fw.bank.example, partner.example

IKEv1 still in use: branch42.fw.bank.example

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `two_phases` | does one tunnel become two security associations? | **PASS** | 5, 0 failing |
| `pfs` | is forward secrecy for data its own answer, not an inference? | **PASS** | 5, 0 failing |
| `vpn_specific` | are the VPN-specific traps handled rather than flattened? | **PASS** | 5, 0 failing |
| `the_estate` | does the VPN surface turn into findings with peers attached? | **PASS** | 5, 0 failing |
| `facts` | does IPsec feed the CBOM without a second vocabulary? | **PASS** | 5, 0 failing |
| `shape` | does the report refuse to say more than the SA shows? | **PASS** | 5, 0 failing |

## `two_phases` — PASS

*does one tunnel become two security associations?* (review 14)

- **PASS** `a-tunnel-is-two-security-associations` — phase 1 and phase 2 are recorded separately
- **PASS** `a-clean-sa-has-no-problems` — aes256/sha256/dh14 with a PFS group: 0 problem(s)
- **PASS** `the-phase-1-group-does-not-count-as-pfs` — DH14 in phase 1 says nothing about the data path
- **PASS** `a-phase-2-without-pfs-is-named-as-such` — no PFS group, so the CHILD keys derive from the IKE SA
- **PASS** `the-statement-names-both-phases` — dc1.fw.bank.example (ikev2): ike aes256, sha256, dh14; child aes256, sha256; PFS on the data path; no weak transform in this SA

## `pfs` — PASS

*is forward secrecy for data its own answer, not an inference?* (review 14)

- **PASS** `the-estate-lists-peers-without-forward-secrecy` — branch42.fw.bank.example, partner.example
- **PASS** `a-strong-looking-proposal-is-still-flagged` — aes128gcm16 sounds modern and has no PFS group
- **PASS** `the-weak-pfs-group-is-judged-on-its-own` — PFS with a 1024-bit group is forward secrecy against yesterday
- **PASS** `the-statement-counts-the-peer-without-pfs` — 3 IPsec SA pair(s) across 3 peer(s); 2 without a PFS group on the data path; 1 still using IKEv1; weak transforms in use: 3des, dh2, md5, sha1
- **PASS** `a-valid-pfs-group-is-not-a-problem` — DH19 (ECDH P-256) is an acceptable PFS group

## `vpn_specific` — PASS

*are the VPN-specific traps handled rather than flattened?* (review 14)

- **PASS** `ikev1-aggressive-mode-with-a-psk-is-an-offline-attack` — a hash of the PSK travels on the wire
- **PASS** `the-same-psk-on-ikev2-is-not-that-finding` — IKEv2 has no aggressive mode
- **PASS** `an-ikev2-record-claiming-aggressive-mode-is-normalised` — the mode does not exist in IKEv2
- **PASS** `null-encryption-is-reported-and-not-called-safe` — integrity without encryption over the internet
- **PASS** `a-tunnel-with-no-child-sa-says-so` — one SA is not a tunnel

## `the_estate` — PASS

*does the VPN surface turn into findings with peers attached?* (review 14)

- **PASS** `the-estate-names-the-weak-transforms-in-use` — 3des, dh2, md5, sha1
- **PASS** `ikev1-peers-are-listed` — branch42.fw.bank.example
- **PASS** `a-refused-tunnel-is-listed-not-dropped` — two refusals, visible in the estate
- **PASS** `the-summary-repeats-the-worst-finding-per-peer` — {"branch42.fw.bank.example": "OFFLINE_PSK_ATTACK", "partner.example": "NO_FORWARD_SECRECY"}
- **PASS** `the-estate-states-what-one-sa-cannot-prove` — 4 stated limit(s)

## `facts` — PASS

*does IPsec feed the CBOM without a second vocabulary?* (review 14 / 16 boundary)

- **PASS** `facts-use-the-roles-the-rest-of-the-platform-uses` — BULK, KEY_EXCHANGE, PRF_AND_INTEGRITY
- **PASS** `every-fact-carries-its-phase-and-protocol` — 11 fact(s), each cited
- **PASS** `a-group-transform-carries-its-size` — a DH fact without its group size is not a fact
- **PASS** `a-symmetric-cipher-is-not-called-quantum-vulnerable` — AES/3DES need a bigger key at most, not a new primitive
- **PASS** `a-document-that-is-not-an-ipsec-estate-is-refused` — a foreign document is rejected, not converted

## `shape` — PASS

*does the report refuse to say more than the SA shows?* (review 14)

- **PASS** `an-unknown-ike-version-is-refused` — IKEv1 and IKEv2 have different transform vocabularies
- **PASS** `an-sa-with-no-evidence-is-refused` — an SA without a record is a claim
- **PASS** `an-unknown-transform-is-not-called-weak` — UNKNOWN, not WEAK: the table cannot see it
- **PASS** `a-phase-outside-the-two-is-refused` — IPsec has two phases
- **PASS** `the-only-attack-finding-describes-a-property-not-an-event` — the rating names what aggressive mode would allow, not what happened

## What this does not prove

- one SA pair is one choice. The peer's full proposal list is a different question, and a good transform in use may be the other side's preference
- an established SA is a configuration. Liveness, byte counters and whether the tunnel is carrying anything are not read here
- PSK strength is invisible: the model can see that a pre-shared key is in use and that aggressive mode would expose a hash of it, not whether that secret is guessable
- certificate authentication is only as strong as the chain behind it, which is guide 159's subject and not re-derived here
- the weak-transform table is a hand-maintained list with a reason per entry, not a compliance mapping; an operator can dispute one row without distrusting the rest
- a tunnel that is down, deleted or half-open is recorded as its state says and is not inferred to be one of those
