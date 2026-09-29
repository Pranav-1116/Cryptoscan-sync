# CryptoScan acceptable-use terms

**Template status:** legal, security, and product review required  
**Applies to:** `[CUSTOMER]`, Authorized Users, and systems connected to the
Services

These terms define safe and authorized use. They complement the MSA and Order
Form. They do not grant permission to scan systems that the customer does not
own or have written authorization to test.

## 1. Permitted use

Customer may use CryptoScan to:

- inventory and assess cryptographic assets in approved sources;
- analyze source code, configuration, certificates, CBOM/SBOM, logs, cloud
  metadata, and other approved artifacts;
- monitor approved assets for cryptographic drift;
- generate reports and evidence for Customer's internal security, risk,
  governance, remediation, audit, and migration purposes;
- run approved integrations with Customer's identity, cloud, ticketing, SIEM,
  repository, HSM/KMS, and evidence systems; and
- perform pilot or production activities within the agreed Order Form scope.

## 2. Authorization requirement

Before connecting a source, Customer must confirm that it owns the source or
has written authorization from the owner to access, scan, export, and process
it. Customer must maintain the authorization record and provide it on request.

Customer is responsible for target accuracy, network permission, rate limits,
cloud role scope, repository permissions, and all third-party terms.

## 3. Prohibited use

Customer must not use the Services to:

- scan, probe, enumerate, or access a system without authorization;
- perform destructive testing, exploitation, denial of service, stress testing,
  password attacks, or intrusive network activity unless a written Order Form
  expressly permits it;
- upload private keys, passwords, authentication tokens, payment PINs,
  plaintext secrets, malware, or prohibited personal data;
- bypass authentication, tenant isolation, access controls, quotas, or rate
  limits;
- use the Service to create a competing product or extract rules, models,
  detection logic, or source code;
- reverse engineer or interfere with the Service except to the extent law
  permits and the MSA allows;
- impersonate another customer, user, vendor, or provider;
- use findings to harass, threaten, discriminate against, or unlawfully profile
  a person;
- represent a report as a certification, regulator approval, legal opinion, or
  independent assessment;
- misrepresent synthetic, corpus, pilot, or local evidence as production or
  customer evidence; or
- violate export controls, sanctions, privacy law, confidentiality duties,
  third-party licences, or applicable banking rules.

## 4. Safe scan controls

Customer and Vendor will agree on:

- scan mode: passive, read-only, active, or import-only;
- allowed targets and source paths;
- maximum rate, concurrency, and time window;
- excluded paths, hosts, repositories, and data classes;
- credential scope and expiration;
- network and proxy controls;
- stop command and emergency contact;
- retention and export policy; and
- testing evidence and log handling.

The safest default is read-only collection and analysis in a dedicated
customer-controlled deployment.

## 5. Data and content rules

Customer must minimize data and remove unnecessary Personal Data before upload.
Customer must not include production credentials or key material. If an
approved source contains incidental Personal Data or secrets, Customer must
identify the source and Vendor will process it only under the DPA and agreed
security measures.

Vendor may reject a source that presents unacceptable risk, lacks authority,
contains prohibited material, or could cause unsafe network or system impact.

## 6. Security testing by customers

Customer may conduct reasonable security testing of its dedicated deployment
only with advance written approval that states scope, dates, source IPs,
methods, rate limits, and contacts. Testing Vendor infrastructure or another
customer's environment is prohibited.

Vulnerability reports must be sent to the Security Contact, not publicly
released before coordinated remediation under the Vulnerability Disclosure
Process.

## 7. Third-party integrations

Customer authorizes only the integrations listed in the Order Form. Customer
is responsible for third-party terms and permissions. Vendor is not liable for
third-party availability or changes outside Vendor control, but will document
material connector failures and safe degraded behavior.

## 8. Findings and decisions

CryptoScan output is decision support. Customer must validate material findings
before taking production, legal, regulatory, safety, or business action. An
unknown or not-evaluated result is not a clean result. Customer remains the
risk owner for remediation, exceptions, and compliance conclusions.

## 9. Suspension

Vendor may suspend a source, user, integration, or account where reasonably
necessary to prevent unauthorized access, material harm, unlawful use, data
exposure, or service abuse. Vendor will limit suspension to the affected scope
where practical, notify Customer, preserve evidence, and restore access when
safe and authorized.

## 10. Reporting violations

Report suspected unauthorized access, credential exposure, unsafe scanner
behavior, Personal Data exposure, or prohibited use to:

- Security: `[SECURITY CONTACT]`
- Privacy: `[PRIVACY CONTACT]`
- Support: `[SUPPORT CONTACT]`

Include Customer, environment, time, scope, and safe evidence. Do not email
private keys or credentials.

## 11. Customer acknowledgement

Customer confirms that it has authority for the proposed scope, has reviewed
prohibited uses, and will brief Authorized Users. Any exception must be
written, time-bounded, risk-assessed, and approved by the responsible security
owner.
