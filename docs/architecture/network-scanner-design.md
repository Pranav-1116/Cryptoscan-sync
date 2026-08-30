# Network scanner design

## Classic pipeline

1. Discover targets (YAML, Kubernetes, DNS zone, hosts).
2. Optionally probe TLS (stdlib `ssl`) and parse cipher suites for TLS 1.2 and 1.3.
3. Parse PEM / live peer certs; validate hostname and chain; check OCSP then CRL.
4. Dedup inventory by fingerprint; emit expiry alerts.
5. Parse Envoy/Istio logs for passive confirmation of the same cipher.

## Enterprise pipeline (`network_scanner/enterprise/`)

Global Network Target Discovery → Active/Passive/Vendor/Controller Discovery →
Asset Registry → Protocol Detection → CryptoObservation → Evidence → Dependency
Graph → CBOM → PQC Risk & Simulation.

| Layer | Module | Responsibility |
|---|---|---|
| Target spec | `target_spec.py` | IPv4/IPv6/CIDR/range/hostname/domain/subdomain/DNS zone/DC/branch/VPN/MPLS/SD-WAN/cloud VPC-VNet/K8s scopes, `SINGLE_HOST…GLOBAL_ENTERPRISE_SCOPE` |
| Assets | `assets.py` | 23-field per-asset records, dedupe/merge registry |
| Scan modes | `scan_modes.py` | SAFE (default) / STANDARD / DEEP / AGGRESSIVE; DEEP+ require `authorization_scope`; every scan records mode, rate, concurrency, authority, times |
| Credentials | `credentials.py` | vault references only, `scrub_secrets` contract — never store secrets in records |
| Vendors | `vendors/` | `NetworkVendorPlugin` contract + registry; Cisco (IOS/IOS-XE/IOS-XR/NX-OS/ASA/Firepower/Meraki/Catalyst/Nexus/ISR/ASR + controller adapters), SNMP (pure-stdlib BER client), generic + 10 thin vendors |
| Protocols | `protocols/` | TLS/DTLS/QUIC/SSH/IPsec/IKE/WireGuard/OpenVPN/SSTP, STARTTLS family, SAML/OAuth/OIDC/Kerberos/AD-CS; four distinct statuses `PROTOCOL_PRESENT < CRYPTOGRAPHY_OBSERVED < CRYPTOGRAPHY_CONFIGURED < CRYPTOGRAPHY_VERIFIED` |
| TLS intel | `tls_intel.py` | versions, negotiated, suites, sig algs, KEX/curves, ALPN/SNI, resumption, OCSP, chains, fingerprints, weak/deprecated config; 4 profiles |
| Cert intel | `cert_intel.py` | reuse, dependency map, blast radius, CA hierarchy, trust store, expiry forecast, weak sigs, vulnerable keys, PQC candidates |
| Topology | `topology.py` | 10 relationship types, transitive queries, crypto paths, Neo4j Cypher export |
| Passive | `passive_engine.py` | SPAN/TAP/flow/firewall/LB/VPN/proxy/DNS logs, TLS handshake metadata — no active probing |
| Config protocols | `config_protocols.py` | NETCONF / RESTCONF / gNMI scanners with injected transports (credentialed) |
| SD-WAN | `sdwan.py` | controllers, edges, tunnels, crypto profiles, control-plane trust |
| Tunnels | `tunnels.py` | unified tunnel schema + weakness detection + PQC migration impact |
| Firewall/LB | `firewall_lb.py` | TLS termination profiles, cipher/VPN policies, termination edges |
| DNS + PKI | `dns_pki.py` | DNS infra, DNSSEC metadata, CAA/TLSA/SRV, Root→Intermediate→Issuing→Server hierarchy into Neo4j |
| HSM | `hsm.py` | metadata only — key material is never extracted |
| PQC readiness | `pqc_readiness.py` | per-asset classical crypto, dependencies, `MIGRATION_REQUIRED`, vendor capability, blockers |
| Simulation | `simulation.py` | hybrid migration over the dependency graph: compatibility, latency, packet overhead, MTU, bandwidth, hardware, peer, rollback |
| Blast radius | `blast_radius.py` | DIRECT / INDIRECT / BUSINESS / NETWORK / GEOGRAPHIC impact sets |
| Geo model | `geo.py` | Country → Region → Data Center → Cloud Region → Business Unit → Network Zone; crypto exposure by geography |
| Engine | `engine.py` | orchestrates the whole pipeline; entry point for scanner, CLI, monitor |

The engine is the single entry point the scanner CLI, the API NETWORK target
and the 24/7 monitor use. All network I/O is injectable (TLS probe, IKE probe,
sweep, SNMP socket factory) so the pipeline is fully unit-testable offline;
live defaults probe real networks under the configured scan mode.
