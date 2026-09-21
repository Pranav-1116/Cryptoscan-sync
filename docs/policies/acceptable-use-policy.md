# Acceptable Use Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
personnel, contractors, and (in the tenant sections) clients of the
platform · **Next review:** [ORG: YYYY-MM-DD] · **Criteria:** TSC CC1.3,
CC6.3

## 1. Purpose

State the rules for using the CryptoScan platform and its access. Users
acknowledge this policy at onboarding ([ORG: acknowledgement process —
digital signature at first login]) and on each material revision.

## 2. Platform use

1. **Your account is personal.** Credentials, sessions and API keys are
   non-transferable. Sharing an account voids the attribution the audit
   trail provides — every action is logged to the identity that
   performed it.
2. **Least privilege in practice.** Request only the role you need
   (Access Control Policy §2); privileged roles (`superadmin`, `ciso`)
   are for their defined duties, not general use.
3. **MFA is not optional.** TOTP (or the hardware MFA where enrolled)
   must remain enabled; disabling it requires the documented exception
   path.
4. **Scan targets.** Scans are authorised work only: each target is
   validated by the platform's target-validation control
   (`api/security/target_validation.py`), and scanning a target you are
   not entitled to test is a disciplinary and potentially legal matter.
   The `scanner` role exists precisely to keep machine scan submission
   inside that boundary.
5. **Data handling.** Findings and reports are Class-2/Class-3 data
   (Data Classification Policy). Do not export, screenshot or forward
   tenant findings outside the tenant boundary; support requests use the
   de-identification rules.
6. **No circumvention.** Rate limits, the airgapped-scan boundary and
   tenant isolation are controls, not friction. Bypassing them is a
   SEV-1 incident and a disciplinary matter regardless of intent.
7. **Incident duty.** Anyone who observes suspicious activity, a failed
   control alarm, or a possible breach must report it the same day to
   [ORG: reporting channel] — reporting in good faith is protected,
   hiding an observation is a policy breach.

## 3. Corporate systems (personnel)

1. Company laptops, mail and repositories are company property; the
   platform's secrets, keys and client data never live on unmanaged
   devices.
2. Personal use of company systems is permitted only where it does not
   interfere with duty, create a security exposure, or involve client
   data.
3. [ORG: insert standard IT rules — remote work, media, USB, public
   posting — or reference the corporate HR handbook.]

## 4. Tenant obligations (clients)

1. Tenants are responsible for the entitlement of their scan targets and
   for the accuracy of the systems register they maintain.
2. Tenant administrators enforce this policy for their users; the
   platform's access-review export (Access Control Policy §3.7) is
   provided so tenants can run the same quarterly recertification on
   their own users, and tenant data never mixes across tenants.
3. Contractual data-protection duties (PDPL / DIFC / ADGM) apply to the
   tenant as data controller; this policy defines the processor-side
   rules only.

## 5. Enforcement

Violations are handled per [ORG: corporate disciplinary procedure].
Repeated or security-critical violations (account sharing, MFA
disabling, unauthorised targets, circumvention) result in immediate
access suspension pending investigation.

## 6. Acknowledgement

[ORG: acknowledgement record location — the user store or the HR
system, with the acceptance timestamp retained as evidence for the
CC1.3/CC6.3 files.]
