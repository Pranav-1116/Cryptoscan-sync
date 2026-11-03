# SSH negotiates four things, two of them per direction

`cryptoscan.cbom-ssh-guide/1` · generated 2026-11-03T01:12:12.874436+00:00 · **5 pass · 0 partial · 0 fail** · 25 probes

Review item 13: SSH is not a cipher suite. It negotiates **key exchange, host key, cipher and MAC**, and the last two run in each direction separately.

```
KEX · HOST_KEY · CIPHER (c→s, s→c) · MAC (c→s, s→c)
  │        │        └── an AEAD cipher negotiates no separate MAC
  │        └── ssh-rsa is SHA-1, rsa-sha2-256 is not
  └── the client's preference decides, not the server's
```

3 SSH session(s) across 3 host(s); 6 deprecated algorithm(s) in use: 3des-cbc, aes128-cbc, diffie-hellman-group1-sha1, hmac-md5, hmac-sha1-96, ssh-rsa; 1 host(s) negotiate different ciphers per direction

| dimension | deprecated examples | why |
|---|---|---|
| `KEX` | `diffie-hellman-group1-sha1` | 1024-bit group with SHA-1 |
| `HOST_KEY` | `ssh-rsa`, `ssh-dss` | SHA-1 signatures; DSA limited to 1024 bits |
| `CIPHER` | `3des-cbc`, `aes128-cbc`, `arcfour*` | 64-bit blocks, no AEAD, RC4 |
| `MAC` | `hmac-md5`, `hmac-sha1-96` | MD5, truncated SHA-1 |

Deprecated in use: 3des-cbc, aes128-cbc, diffie-hellman-group1-sha1, hmac-md5, hmac-sha1-96, ssh-rsa

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `four_negotiations` | does one SSH session become four answers, per direction? | **PASS** | 5, 0 failing |
| `ssh_specific` | are the two SSH-specific traps handled rather than flattened? | **PASS** | 5, 0 failing |
| `the_estate` | does the SSH estate turn into findings with hosts attached? | **PASS** | 5, 0 failing |
| `facts` | does SSH feed the CBOM without a second vocabulary? | **PASS** | 5, 0 failing |
| `shape` | does the report refuse to say more than the session shows? | **PASS** | 5, 0 failing |

## `four_negotiations` — PASS

*does one SSH session become four answers, per direction?* (review 13)

- **PASS** `a-session-is-four-negotiations-not-one-cipher` — jump.bank.example:22 negotiated curve25519-sha256 · ssh-ed25519 · chacha20-poly1305@openssh.com (c→s) · chacha20-poly1305@openssh.com (s→c); no deprecated algorithm in this session
- **PASS** `both-directions-are-recorded-with-their-own-algorithms` — c→s and s→c, separately
- **PASS** `an-asymmetric-session-names-the-weak-direction` — aes256-gcm one way, aes128-cbc the other
- **PASS** `an-aead-cipher-does-not-negotiate-a-separate-mac` — poly1305 authenticates; a CBC cipher still needs its MAC
- **PASS** `the-host-key-fingerprint-travels-and-the-key-never-does` — NOT_STORED

## `ssh_specific` — PASS

*are the two SSH-specific traps handled rather than flattened?* (review 13)

- **PASS** `ssh-rsa-is-sha1-and-not-the-same-as-rsa-sha2` — the same key type, two different signature algorithms
- **PASS** `the-server-s-offer-is-kept-apart-from-what-was-used` — SUPPORTED and NEGOTIATED are different answers
- **PASS** `an-unknown-algorithm-is-not-called-broken` — a name this table does not know is not a verdict
- **PASS** `a-dimension-outside-the-four-is-refused` — compression is not a cryptographic negotiation
- **PASS** `a-session-with-no-evidence-is-refused` — an SSH claim without a session record is a claim

## `the_estate` — PASS

*does the SSH estate turn into findings with hosts attached?* (review 13)

- **PASS** `the-estate-names-every-deprecated-algorithm-and-who-uses-it` — 3 SSH session(s) across 3 host(s); 6 deprecated algorithm(s) in use: 3des-cbc, aes128-cbc, diffie-hellman-group1-sha1, hmac-md5, hmac-sha1-96, ssh-rsa; 1 host(s) negotiate different ciphers per direction
- **PASS** `hosts-with-an-asymmetric-session-are-listed` — payments.bank.example
- **PASS** `a-session-is-never-summarised-as-one-algorithm` — four answers per session, not one
- **PASS** `a-refused-session-is-listed-not-dropped` — two refusals, both visible
- **PASS** `the-estate-states-what-one-session-cannot-prove` — 4 stated limit(s)

## `facts` — PASS

*does SSH feed the CBOM without a second vocabulary?* (review 13 / 16 boundary)

- **PASS** `facts-use-the-roles-the-rest-of-the-platform-uses` — BULK, KEY_EXCHANGE, MAC, SIGNATURE
- **PASS** `every-fact-is-marked-as-an-ssh-network-observation` — 12 fact(s), each cited
- **PASS** `quantum-exposure-is-named-without-a-migration-verdict` — curve25519-sha256, ecdh-sha2-nistp256, rsa-sha2-256, ssh-ed25519, ssh-rsa
- **PASS** `a-symmetric-cipher-is-not-called-quantum-vulnerable` — AES needs a bigger key at most, not a new primitive
- **PASS** `a-document-that-is-not-an-ssh-estate-is-refused` — a foreign document is rejected, not converted

## `shape` — PASS

*does the report refuse to say more than the session shows?* (review 13)

- **PASS** `the-banner-is-recorded-and-never-judged` — a version string is not a cryptographic property
- **PASS** `an-empty-algorithm-name-is-refused` — no name, no algorithm
- **PASS** `a-non-object-session-is-refused` — a string is not a session
- **PASS** `the-deprecation-and-quantum-tables-are-explainable` — 17 deprecated entries, each with a reason
- **PASS** `nothing-in-the-report-calls-anything-an-attack` — a weak SSH algorithm is a configuration fact

## What this does not prove

- one session is one negotiation. The server's full offer is a different question, and a modern algorithm in use today can be the client's preference rather than the server's policy
- SSH takes the first algorithm on the client's list that the server also offers, so a weak client can choose a weak algorithm against a strong server. Both lists matter and this model records both when they are given
- a host key is trusted by the client's known_hosts, which this model does not read. A fingerprint identifies a key; it does not vouch for it
- the deprecation table is a hand-maintained list with a reason per entry, not a compliance mapping. An operator can disagree with one row without distrusting the rest
- compression, port forwarding and agent forwarding are not negotiated cryptography in the sense this model measures, and none is judged here
- a version banner is recorded and never scored: OpenSSH 7.4 is not a weak algorithm, it is a version that may support weak ones
