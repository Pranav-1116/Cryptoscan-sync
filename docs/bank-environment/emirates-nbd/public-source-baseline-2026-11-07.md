# Public-Source Technology and Vendor Baseline — Emirates NBD

> **Provenance:** user-provided document, saved verbatim 2026-10-16 (workspace date).
> Prepared for ZELNX (zelnx.com) — post-quantum migration assessment; prepared 7 November 2026.
> Method: desk research of public sources only. No scanning, probing or non-public data was used.
> Status: outside-in baseline. It is NOT a CBOM: public sources do not disclose algorithms,
> keys, certificates or HSMs.
> Structured form of this baseline: `baseline-dataset-2026-11-07.json` (same content,
> machine-readable; every row carries its refs and confidence).

---

Emirates NBD
Software, hardware, network and vendor inventory to seed a Cryptographic Bill of
Materials (CBOM)

ItemDetail
Prepared forZELNX (zelnx.com) - post-quantum migration assessment
Prepared on7 November 2026
MethodDesk research of public sources only: bank and vendor press releases, trade press, vendor customer stories,
public job adverts. No scanning, probing or non-public data was used.
StatusOutside-in baseline. It is NOT a CBOM: public sources do not disclose algorithms, keys, certificates or HSMs.
Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 11. Executive summary
Public sources show Emirates NBD (ENBD) running a large, multi-vendor estate. The best-documented layers are:
Infosys Finacle as the group core banking platform [3][4][24]; NCR for ATM hardware, software and services [1];
TCS BaNCS for payments [2]; Intellect Design Arena for transaction banking [5]; a Calypso treasury platform [6];
and Microsoft (Azure, Microsoft 365 Copilot, GitHub Copilot) plus AWS and OpenAI for cloud and AI
[9][10][11][12].
Hosting is a mix of an in-house private cloud [21] and third-party Tier III data centres from du [13], with Moro Hub
and Avaya providing a cloud contact-centre service [14]. Security and data-protection vendors named publicly
include Trend Micro [16], Data443 [15] and Silent Eight (AML/sanctions alert handling) [8]. Storage hardware is
Dell PowerMax [17].
Network detail is thin. The only direct evidence is a bank job advert referring to a Cisco and SONiC
software-defined fabric, and IPsec, ACL and routing-authentication work in its data centres [18][19]. Firewall,
load-balancer and HSM vendors are not publicly disclosed for ENBD.
Several disclosures are old (NCR 2014, Trend Micro undated). Treat them as 'was deployed', and confirm current
state with the bank.
2. How to read this document
A CBOM (Cryptographic Bill of Materials) lists every cryptographic asset an organisation relies on: algorithms and
their parameters, protocols (TLS, IPsec, SSH), certificates and PKI, keys and key stores, HSMs, and the libraries
and products that implement them. The CycloneDX 1.6 standard defines a cryptographic-asset model for this. It
is the input a post-quantum migration needs, because you cannot replace RSA/ECC where you do not know it is
used.
Public information cannot give that level of detail. What it can give is the supply chain around the crypto: which
platforms, hardware, networks and third parties exist, and therefore where cryptographic assets must be looked
for. This document therefore provides (a) a sourced inventory of disclosed technology and vendors, (b) an inferred
map of where cryptographic assets typically sit for each item, clearly labelled as inference, and (c) a request list for
the data only the bank can supply.
Confidence key. High = published by the bank or the vendor itself (press release / customer story). Medium = reported by
established trade press. Low = third-party aggregator, job advert or undated page; use only as a lead to verify. Dates are
publication dates; a disclosed product may since have been replaced.
3. Organisation profile
AttributePublic detailRef
GroupLeading banking group in the MENAT region; presence in 13 countries; over 20 million
customers.[13]
Digital brandsLiv. (digital-only bank); API developer portal for corporate clients.[9][25]
SubsidiaryEmirates Islamic Bank went live on Finacle in 2016 (first Islamic site for that platform).[2]
FootprintA bank job advert cites 853 branches and 4,213 ATMs/SDMs across the group.[18]
Markets with core
migratedSingapore (Nov 2018), UK (Jul 2019), Saudi Arabia (phase 3, Jan 2020); target of one
platform for all entities by end-2020.[3]
4. Software and platforms
Business applications and platforms the bank or vendors have publicly named.
Vendor / productRoleWhat was publicly disclosedRefConfidence / as-of
Infosys Finacle
(EdgeVerve)Group core bankingFinacle used at home and across
international entities; migration of all entities
to one updated platform; award for core
implementation (2020).[3][4][24]
High-Medium. 2020
and later.
Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 2Vendor / productRoleWhat was publicly disclosedRefConfidence / as-of
TCS BaNCS for
PaymentsPayments processingSelected as core payments platform to
standardise payments across India, Egypt,
Saudi Arabia, Singapore, UK and UAE.[2]Medium. Trade
press, date not
shown in snippet.
Intellect Design ArenaTransaction bankingTechnology selected to overhaul
wholesale/transaction banking as part of an
AED 1 billion digitisation commitment.[5]Medium. Date not
shown.
Calypso (treasury)Treasury front-to-backEnd-to-end upgrade consolidating treasury
products into a single core system across
markets.[6]Medium. Vendor
press release via
Finextra.
Pine Labs Credit+Merchant acquiring /
creditPartnership to deliver in-store and online
merchant acquiring solution.[7]Medium. Finextra
press article.
Silent EightAML / sanctions
screeningAI and machine-learning platform to automate [8]
screening alert disposition; proof of value on
the bank's screening alerts.High. 2024
announcement.
Microsoft 365 Copilot,
GitHub Copilot X,
ChatGPT use casesProductivity and
developer AIAnnounced July 2023; 'more than a thousand
developers' on Copilot X; hackathon with
McKinsey and QuantumBlack.[10]High. Jul 2023.
OpenAI modelsEnterprise / sovereign AIReported as first MENA bank to use OpenAI
sovereign AI infrastructure, connecting
models to internal systems and APIs.[12]Medium. Trade
press; date not
shown.
Cloudera / Hadoop;
Bloomberg; SAPData platform; market
data; enterprise appsListed by a procurement-research aggregator
as detected products. Not confirmed by the
bank here.[20]Low. Aggregator;
verify.
API banking platformOpen/API bankingAPI developer portal described as the
region's most comprehensive; vendor not
named.[25]Medium. Vendor
unknown.
5. Hardware and data-centre infrastructure
Compute, storage, ATM and hosting infrastructure disclosed publicly.
Vendor / productRoleWhat was publicly disclosed
Ref
Confidence / as-of
NCR (ATM estate)ATM / self-service
hardware, software,
servicesChosen as unified end-to-end self-service
vendor; APTRA software; Windows 7
platform at the time of the 2014
announcement.[1]
High but old (Feb
2014).
Dell PowerMaxEnterprise storageCustomer story: bank's core runs on
PowerMax; 30% data-centre cost reduction;
response times down to 1 ms.[17]High (vendor story).
Date not shown.
VMwareVirtualisationTrend Micro story states the IT environment is [16]
VMware.Low-Medium.
Undated, likely old.
In-house private cloudPrivate cloud platformBank launched own private cloud, claimed as
a regional banking first; underlying vendors
not named in the retrieved text.[21]Medium. Circa 2018.
du Tier III data centresThird-party hostingdu hosts the bank's first third-party data
centre and a further Tier III data hall in Dubai
(announced Oct 2023).[13]High. Oct 2023.
Moro Hub (DEWA)Cloud hosting /
contact-centre platformMoro Connect cloud contact-centre built on
Avaya OneCloud for the bank.[14]High. Feb 2021.
Microsoft Azure; AWSPublic cloudAzure powers Liv.; AWS used for ML,
analytics, IoT and NLP in retail banking.[9][11]High (Azure, Jul
2021); Medium
(AWS, date not
shown).
6. Network and connectivity
Public evidence on networking is limited to job adverts and hosting announcements; no vendor has published an
ENBD network deployment.
Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 3Vendor / productRoleWhat was publicly disclosed
Ref
Confidence / as-of
Cisco + SONiC SDN
fabricData-centre networkJob advert for a Lead Technology Engineer to [18]
build and maintain an 'ENBD SDN-Fabric'
using Enterprise SONiC and legacy
networking; stack described as Cisco and
SONiC.Low-Medium. Job
advert, undated.
IPsec, ACLs, routing
authenticationNetwork security
practicesJob advert lists network-security
responsibilities including IPsec, ACLs and
routing protocol authentication across bank
data centres, server rooms and IDFs (owned
or rented).[19]Low-Medium. Job
advert.
duTelecom / hosting and
voicedu provides data-centre hosting; du also
launched 'Next Gen Voice' cloud-native
communications platform with the bank (per
aggregator).[13][20]High (hosting); Low
(voice).
Avaya / Moro ConnectUnified communications
/ contact centreLong-standing Avaya relationship; cloud
CCaaS delivered through Moro Hub in 2021.[14]High. Feb 2021.
Firewall, WAN,
load-balancer, NAC
vendorsPerimeter and internal
securityNot publicly disclosed. No ENBD-specific
vendor evidence was found. Do not assume
any.-Gap.
7. Security, compliance and data protection
Security, fraud, compliance and data-protection products and providers named in public sources.
Vendor / productRoleWhat was publicly disclosed
Ref
Confidence / as-of
Trend Micro Deep
SecurityServer / workload
protectionCustomer story: in use about five years at the
time, with plan to extend to the VMware
platform.[16]
High but old
(undated).
Data443 Risk
MitigationData security /
classificationMulti-year subscription agreement spanning
the bank's technology landscape, supporting
a 'cloud first' migration of data and users.[15]Medium. Vendor
press release.
Silent EightCompliance AIAutomates screening alert investigations;
improves auditability.[8]High. 2024.
Security operations
(SOC/SIEM) vendorDetection and responseNot publicly disclosed for ENBD in the
sources found.-Gap.
HSM, PKI and
key-management
vendorsCryptographic
infrastructureNot publicly disclosed. Core CBOM item to
request from the bank.-Gap.
8. Consolidated vendor register
One line per third party named in the sources above. 'First seen' is the earliest public date found, not a contract
date.
VendorCategoryRelationship (as disclosed)First seen
Infosys / EdgeVerve
(Finacle)Core bankingGroup core banking platform2018-2020
TCS (BaNCS)PaymentsPayments platform across 6 marketsn/a in snippet
Intellect Design ArenaTransaction bankingWholesale / transaction banking overhaula n/a in snippet
CalypsoTreasuryFront-to-back treasuryn/a in snippet
NCRATM hardware and
softwareUnified preferred ATM vendorFeb 2014
Pine LabsMerchant acquiringCredit+ and acquiring platformn/a in snippet
Silent EightCompliance AIAML/sanctions alert disposition2024
MicrosoftCloud, productivity, AIAzure (Liv.), M365 Copilot, GitHub Copilot XJul 2021; Jul
2023
Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 4VendorCategoryRelationship (as disclosed)First seen
AWSCloud / MLML, analytics, NLP for retail bankingn/a in snippet
OpenAIAI modelsEnterprise / sovereign AI infrastructuren/a in snippet
McKinsey /
QuantumBlackConsultingGenerative AI hackathon and use-case design2023
du (EITC)Hosting / telecomTier III data centres; voice platformOct 2023
Moro Hub (DEWA) and
AvayaCloud contact centreMoro Connect CCaaSFeb 2021
DellStoragePowerMaxn/a
Trend MicroWorkload securityDeep Security on VMwaren/a
Data443Data securityMulti-year data-protection subscriptionn/a
VMwareVirtualisationPer Trend Micro storyn/a
Cisco / SONiCNetworkPer job advert onlyn/a
9. Where cryptographic assets likely sit (inference)
Everything in this section is inference from the type of technology disclosed. None of it is stated by the
bank or vendors. It tells a CBOM team where to look first, and what question to ask.
Area (from sections
4-7)Cryptographic assets typically
presentBasis for inferenceQuestion to confirm
Core banking
(Finacle) and
payments (TCS
BaNCS)TLS between tiers; database/TDE
keys; service-account keys; message
signing for payment channels;
HSM-backed key use.Core and payments platforms
are disclosed [2][3].Which HSMs and key hierarchies
protect core and payments? Which
TLS versions between tiers?
ATM estate (NCR
APTRA)PIN and terminal key management,
key-loading protocols, TLS to the
ATM switch, EMV key material.ATM vendor and software
disclosed [1].Current ATM software/OS, key-loading
method, and migration plan for terminal
keys.
Public cloud (Azure,
AWS)Cloud KMS keys or BYOK, TLS
certificates, storage encryption,
workload identities.Azure and AWS use disclosed
[9][11].Who holds the keys for each cloud
workload? Are customer-managed
keys used?
Hosted/private DC
(du, in-house cloud)Inter-site links encryption, hypervisor
and storage encryption, certificate
authorities for internal services.Third-party and private DCs
disclosed [13][21].How are DC-to-DC and DC-to-branch
links encrypted?
Network (SDN
fabric, IPsec)IPsec/IKE algorithms and groups,
routing authentication keys, VPN
certificates.Job advert cites IPsec and
routing authentication [19].IKE version, DH groups, and
authentication method for all VPNs.
API banking and AI
integrationsAPI gateway certificates, mTLS,
OAuth/JWT signing keys, secrets for
AI-to-system connectors.API portal and OpenAI
integration disclosed [12][25].Where are API signing keys held? How
are AI connector secrets managed?
Contact centre
(Avaya / Moro)TLS and SRTP for voice, SIP trunk
certificates, recording encryption.Cloud contact centre disclosed
[14].Voice-encryption settings and
recording-storage encryption.
Data protection
(Data443, Trend
Micro)Agent-to-server TLS, encryption of
data at rest where the product applies
it.Products disclosed [15][16].Which datasets are encrypted by these
products and with which keys?
10. Gaps and unverified claims
• No public source gives ENBD's cryptographic algorithms, key lengths, certificate inventory, PKI, HSM vendor or
TLS configuration. A CBOM cannot be completed from public data.
• Unverified: one third-party startup guide claims ENBD ran a quantum key distribution (QKD) pilot with a Toshiba
system between two Dubai branches [22]. This could not be confirmed by the bank or Toshiba, and the source
is low quality. Treat it as a question to ask the bank, not as fact.
• Dated items (NCR 2014, Trend Micro, VMware) may no longer reflect the estate.
• Aggregator data (Cloudera, Bloomberg, SAP) [20] is unconfirmed.
• Job adverts show practices at the time of posting and may describe a specific team, not the whole bank.
• Network, firewall, SIEM/SOC, identity, PAM and HSM vendors are absent from public sources.
11. Data request list for an authorised CBOM engagement
These items cannot be obtained from public sources and need the bank's consent and cooperation. Discovery
tooling should only be run inside an agreed scope.
• HSM inventory: vendor, model, firmware, partitions, key hierarchies, FIPS 140 level, which applications use
each.
• PKI: internal and external CAs, hierarchy depth, signature algorithms, certificate templates, lifetimes, revocation
method.
• Certificate inventory for internet-facing, internal, mobile-app, API and device certificates, with key type and size.
• TLS and SSH configuration baselines per tier (load balancers, API gateways, middleware, databases), including
minimum versions and cipher suites.
• Network crypto: IPsec/IKE parameters, site-to-site and partner VPNs, wireless authentication (802.1X / EAP
method), routing authentication.
• Payment and card crypto: PIN/key management, key-exchange methods for ATMs and terminals, card-scheme
and interbank connectivity, message signing.
• Core and database encryption: transparent data encryption, tokenisation, backup encryption, and who holds the
keys.
• Cloud key management: KMS or BYOK/HYOK arrangements for each cloud and hosted facility, with key location
and rotation.
• Software supply chain: crypto libraries and versions per application (SBOM), code-signing keys, and CI/CD
secrets handling.
• Vendor contracts and roadmaps: each vendor's PQC readiness statement and the date they will support NIST
FIPS 203/204/205.
• Data-retention classes: which data must stay confidential for 10+ years (the 'harvest now, decrypt later'
exposure).
12. References
[1] NCR press release, 20 Feb 2014 - Emirates NBD selects NCR as unified preferred technology partner
https://investor.ncrvoyix.com/news-releases/news-release-details/emirates-nbd-selects-ncr-its-unified-preferred-technology
[2] FinTech Futures - Emirates NBD upgrades payments system with TCS
https://fintechfutures.com/?p=15159034
[3] FinTech Futures, 6 Jan 2020 - Emirates NBD completes third phase of core banking upgrade
https://www.fintechfutures.com/core-banking-technology/emirates-nbd-completes-third-phase-of-its-core-banking-systems-upgrade
[4] The Asian Banker, Nov 2020 - Emirates NBD and Infosys Finacle core banking award
https://theasianbanker.com/press-releases/emirates-nbd-and-infosys-finance-win-best-core-banking-technology-implementation-in-the-middle-east-award-for-rationalising-processes-and-cost-through-use-of-agile-technology-2020
[5] Finextra - Emirates NBD overhauls wholesale banking operations (Intellect)
https://finextra.com/newsarticle/33436/emirates-nbd-overhauls-wholesale-banking-operations
[6] Finextra - Emirates NBD goes end-to-end with Calypso treasury tech
https://finextra.com/pressarticle/77391/emirates-nbd-goes-end-to-end-with-calypso-treasury-tech
[7] Finextra - Emirates NBD to implement Pine Labs Credit+ platform
https://www.finextra.com/pressarticle/100793/emirates-nbd-to-implement-pine-labs-credit-platform
[8] Financial IT, 2 Feb 2024 - Emirates NBD partners with Silent Eight
https://financialit.net/news/machine-learning/emirates-nbd-partners-silent-eight-automate-alert-disposition-and-enhance
[9] Microsoft News, 15 Jul 2021 - Liv. elevates digital banking with Azure
https://news.microsoft.com/en-xm/2021/07/15/emirates-nbds-liv-elevates-digital-banking-experiences-with-microsoft-azure-cloud-services/
[10] Intelligent CIO, 14 Jul 2023 - Emirates NBD adopts Microsoft 365 Copilot, GitHub Copilot X, ChatGPT
https://www.intelligentcio.com/me/2023/07/14/emirates-nbd-adopts-microsoft-365-copilot-github-copilot-x-chatgpt-to-harness-generative-ai/
Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 6[11] Technology Magazine - Emirates NBD partners with AWS
https://technologymagazine.com/enterprise-it/emirates-nbd-partners-aws-create-ai-enabled-bank-future
[12] FF News - Emirates NBD first MENA bank to use OpenAI sovereign AI infrastructure
https://ffnews.com/news/emirates-nbd-becomes-first-mena-bank-to-harness-openai-s-sovereign-ai-infrastruc-09cf5332
[13] Zawya, Oct 2023 - du announces strategic win with Emirates NBD (Tier III data center)
https://zawya.com/en/press-release/companies-news/du-announces-strategic-win-with-emirates-nbd-to-host-a-tier-iii-data-center-cdgl5g7s
[14] Finextra, Feb 2021 - Emirates NBD to implement cloud communications package from Moro
https://www.finextra.com/pressarticle/86178/emirates-nbd-to-implement-cloud-communications-package-from-moro
[15] Stock Titan - Data443 deploys data product for Emirates NBD
https://www.stocktitan.net/news/ATDS/data443-deploys-market-leading-data-product-for-flagship-global-bank-q3293dmeu62i.html
[16] Trend Micro customer story - Emirates NBD
https://trendmicro.com/tr_tr/about/customer-stories/emirates-nbd.html
[17] Dell customer story - Emirates NBD (PowerMax)
https://www.dell.com/en-ca/lp/customer-stories-emirates-nbd
[18] Job advert (Foundit) - Lead Technology Engineer, Network, Emirates NBD
https://www.foundit.in/job/lead-technology-engineer-network-emirates-nbd-bengaluru-bangalore-43835762
[19] Job advert (Foundit Gulf) - Technology Engineer, Emirates NBD Dubai
https://www.founditgulf.com/job/technology-engineer-uae-national-emirates-nbd-dubai-69418154
[20] RFP.wiki - Emirates NBD technology stack (aggregator)
https://www.rfp.wiki/financial-services-banking-fintech/core-banking-systems/emirates-nbd
[21] Intelligent CIO Middle East, issue 30 - Emirates NBD Group launches private cloud
https://me.magazine.intelligentcio.com/intelligent-cio-middle-east-issue-30/0062109001525980808/p11
[22] UAE Free Zone Finder - quantum startup guide 2026 (UNVERIFIED claim of QKD pilot)
https://uaefreezonefinder.com/uae-quantum-computing-startup-guide-2026/
[23] Gulf News - Emirates Islamic digitisation and core platform
https://gulfnews.com/amp/story/business%2Fbanking%2Fdigitisation-its-all-in-the-family-1.2130607
[24] EdgeVerve / Finacle case study - Emirates NBD
https://www.casestudies.com/company/edgeverve/case-study/emirates-nbd-customer-case-study
[25] Business Chief - Emirates NBD generative AI and API developer portal
https://businesschief.ae/technology/emirates-nbd-to-transform-operations-with-generative-ai

Emirates NBD - public-source CBOM supply-chain baseline - prepared 7 Nov 2026 for ZELNX
Page 7
