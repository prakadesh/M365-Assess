# CIS Microsoft 365 Foundations Benchmark v7.0.0 integration

## Status and scope

M365-Assess now recognizes CIS Microsoft 365 Foundations Benchmark v7.0.0 (released May 20, 2026) as a separate framework alongside the existing v6.0.1 integration. The v6 definition and mappings remain in place so existing reports and historical comparisons are not silently changed.

The v7 implementation is a **best-effort crosswalk** from existing M365-Assess checks to v7 recommendation identifiers. The current overlay maps 154 check identifiers to 138 unique v7 recommendation IDs out of 160 total recommendations. It is not a complete implementation of every v7 recommendation, and the presence of a framework in the report does not imply that all recommendations were assessed.

## Integration design

- `controls/frameworks/cis-m365-v7.json` declares the benchmark version, profile labels, section taxonomy, and profile scoring denominators.
- `controls/cis-m365-v7-overlay.json` carries version-specific check-to-recommendation mappings without modifying the generated upstream `registry.json`.
- `Common/Import-ControlRegistry.ps1` applies this overlay at load time while retaining the original v6 mappings.
- Automated findings are only mapped when an available check has a defensible relationship to a v7 control. Recommendations with no appropriate check remain unmapped / unassessed; they must not be treated as a pass.

## Crosswalk decisions

The v7 benchmark change history identifies renumbering and profile changes. The integration accounts for key changes in the overlay:

- The security-group creation setting is mapped to v7 control `5.1.3.1`; the older dynamic guest-group recommendation is not carried forward.
- The user application-registration setting is mapped using the existing dedicated check rather than an adjacent third-party app control.
- The two Intune recommendations at `4.1` and `4.2` use the v7 Level 1 profiles.
- The removed OneDrive sync recommendation is excluded.
- A legacy anti-phishing mapping that previously collided with Intune control `4.2`, and a generic duplicate enrollment entry, are excluded.
- The Entra smart-lockout threshold check is mapped to `5.2.3.8`.
- `EXO-DIRECTSEND-001` now reads the Exchange Online `RejectDirectSend` organization setting directly and is mapped to `6.5.5` (E3/E5 Level 2). The older unauthenticated-relay connector heuristic is retained separately and is not treated as the v7 Direct Send control.

The exact mapping list is kept in the JSON overlay and should be reviewed against the CIS benchmark available through the CIS website before relying on a specific mapping for a formal audit.

## Known gaps and safe interpretation

This release does not implement dedicated checks for every v7 addition or manual-only recommendation. The 22 currently unmapped v7 recommendation IDs are: `2.4.5`, `3.2.3`, `5.1.3.2`, `5.1.3.3`, `5.1.3.4`, `5.1.5.3`–`5.1.5.6`, `5.2.2.13`–`5.2.2.17`, `5.2.3.9`, `5.2.3.10`, `5.2.4.1`–`5.2.4.5`, and `6.3.2`. These gaps include Copilot DLP, app credential lifetime/creation, My Groups behavior, session controls, password reset procedures, and the Outlook personal-account/calendar setting.

Treat the report as **partial assessment coverage**, not a certification or a statement of full CIS compliance. Do not convert a missing finding or absent mapping into a pass. Complete manual review and validate licensing, applicability, evidence, and the actual configured state before remediation or audit attestation.

## CIS terms and source material

The official benchmark is available from [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365). This repository intentionally does not redistribute the benchmark PDF or reproduce its full recommendation text. Consult the CIS source for authoritative audit steps, rationale, impact, and remediation instructions.
