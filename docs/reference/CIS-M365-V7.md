# CIS Microsoft 365 Foundations Benchmark v7.0.0

M365-Assess supports **CIS Microsoft 365 Foundations Benchmark v7.0.0** (`cis-m365-v7`) alongside
v6.0.1 (`cis-m365-v6`). v7 is the default CIS framework in the report; v6 stays selectable.

## Coverage

| | Count |
|---|---|
| Recommendations in v7.0.0 | 160 |
| Automated recommendations | 143 (all have at least one check) |
| Manual recommendations | 17 (9 have a related check that reports `Review`; 8 are not assessed) |
| Controls with a mapped check | 152 |
| Checks mapped to v7 | 179 |

Not assessed (Manual in the benchmark, no safe read-only API signal): 2.4.5, 5.1.3.2, 5.1.3.3,
5.2.4.1 to 5.2.4.5.

Profiles use the benchmark's own applicability (E3/E5 x Level 1/Level 2). Profile counts per
framework definition: E3-L1 100, E3-L2 37, E5-L1 114, E5-L2 46.

## What changed from v6

- **New checks (14)** for recommendations that did not exist in v6 or had no check:

  | Control | Check | Collector |
  |---|---|---|
  | 3.2.3 DLP published for Copilot | `COMPLIANCE-DLP-004` | Compliance |
  | 5.1.3.4 M365 group creation restricted | `ENTRA-GROUP-007` | Entra |
  | 5.1.5.3 to 5.1.5.6 default app management policy | `ENTRA-APPMGMT-001` to `-004` | Entra |
  | 5.2.2.13 periodic reauthentication | `CA-REAUTH-001` | Entra |
  | 5.2.2.14 trusted named locations | `CA-NAMEDLOC-003` | Entra |
  | 5.2.2.15 exclusionary geographic access control | `CA-GEOBLOCK-001` | Entra |
  | 5.2.2.16 Token Protection | `CA-TOKENPROT-001` | Entra |
  | 5.2.2.17 authentication transfer blocked | `CA-AUTHTRANSFER-001` | Entra |
  | 5.2.3.9 smart lockout duration | `ENTRA-PASSWORD-006` | Entra |
  | 5.2.3.10 Authenticator on companion apps | `ENTRA-AUTHMETHOD-009` | Entra |
  | 6.3.2 personal email accounts and calendars | `EXO-OWA-002` | Exchange |

  5.2.3.8 (lockout threshold) reuses the existing `ENTRA-PASSWORD-003`.
- **Changed thresholds/logic in existing checks**
  - `ENTRA-DEVICE-002` (5.1.4.2): maximum devices per user is now 10 or fewer (was 15).
  - `ENTRA-AUTHMETHOD-003` (5.2.3.1): now requires application name **and** geographic location in
    Authenticator notifications. Number matching is no longer part of the control (Microsoft
    enforces it tenant-wide); it is shown for context only.
- **Renumbered**: "users cannot create security groups" moved from 5.1.3.2 to 5.1.3.1.
- **Removed from the benchmark**: 5.1.3.1 (dynamic guest group, `ENTRA-GROUP-002`) and 7.3.2
  (OneDrive sync restriction, `SPO-SYNC-001`). Those checks still run and still map to v6 and other
  frameworks; they simply have no v7 control.
- **Retitled** with unchanged intent: 5.1.2.2, 5.1.6.3, 5.3.1.

## Where the data lives

v7 mappings are **not** stored in `registry.json`. The weekly CheckID sync rewrites `registry.json`
and `cis-m365-v6.json` wholesale, which would erase them. Instead:

| File | Purpose |
|---|---|
| `controls/cis-m365-v7-mapping.json` | 160-recommendation catalog (title, Automated/Manual, profiles) and the check -> control mapping |
| `controls/frameworks/cis-m365-v7.json` | Framework definition used by the report (scoring, sections, display order) |
| `controls/local-extensions.json` | The 14 new checks, so the sync preserves them |

`Import-ControlRegistry` merges the overlay into each registry entry's `frameworks['cis-m365-v7']`
at load time, so every consumer sees v7 like any other framework. The CIS reverse lookup used for
legacy `CisControl` CSV columns is built from v7 by default; pass `-CisFrameworkId 'cis-m365-v6'` to
use v6.

`scripts/Build-RegistryStats.ps1` counts overlay mappings, and the framework-key consistency test
accepts the overlay's framework ID.

## Maintaining the mapping

When CIS publishes an update or errata, edit `cis-m365-v7-mapping.json` directly: add or retitle a
catalog entry, then add or change the `checks` entry for the relevant `checkId`. Run
`scripts/Build-RegistryStats.ps1` and the `Cis-M365-v7-Mapping` tests. The coverage test fails if an
Automated recommendation has no check, which is the signal to write a new one.

Upstreaming the v7 mappings and the 14 checks to CheckID would let them flow through the normal
sync; until then the overlay is the source of truth.

## Notes

- The CIS benchmark text is licensed by CIS. This repository carries recommendation IDs, short
  titles, profile applicability and its own check logic and remediation wording only. Do not commit
  the benchmark PDF or its audit/remediation text.
- Checks that cannot read their data report `Review`, never a guessed `Pass`/`Fail`.
- Collectors were validated with mocked Graph/Exchange/Purview responses. Run a live assessment
  against a test tenant before relying on the new checks, in particular
  `defaultAppManagementPolicy`, the Conditional Access `authenticationFlows`/`secureSignInSession`
  fields, and the Copilot DLP `EnforcementPlanes`/`LocationInclusions` properties.
