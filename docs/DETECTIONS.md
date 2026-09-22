# Detection design

ATT&CK references checked against MITRE's official technique pages on 2026-09-21. A technique mapping describes suspected behavior; it is not proof of intent.

## AUTH-001

Group failure events by host, user, and source IP. Sort by event timestamp, then find the first window containing at least five failures at most 300 seconds apart (inclusive). Emit one finding per group per batch. The seeded sixth failure remains raw telemetry but is not in the first threshold-crossing evidence window.

Known gaps: no cross-batch state, distributed guessing, password spraying, success-after-failure escalation, ingestion deduplication, or volume-based scoring. Saved-password retries can match. [MITRE T1110.001](https://attack.mitre.org/techniques/T1110/001/).

## EXEC-002

Match `powershell.exe`, `powershell`, `pwsh`, or `pwsh.exe` with an exact whitespace-delimited `-enc`, `-encodedcommand`, or `-encodedcommand:` token after lowercasing. This deliberately simple parser will miss alternate abbreviations, quoted/combined flags, full process paths, and other obfuscation. It never decodes or runs the command. Approved management scripts can match. [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/).

## EXFIL-003

Match a network event labeled `cloud_storage` with `bytes_sent >= 104857600`. The fixture is 251658240 bytes (240 MiB). Destination categorization is supplied by the synthetic generator; no domain reputation service is implied. Legitimate backups can match. There is no baseline learning, aggregation across flows, or data-loss confirmation. [MITRE T1567.002](https://attack.mitre.org/techniques/T1567/002/).

## Evaluation

Tests include threshold boundaries, benign controls, grouped identity separation, and shuffled event order. They establish behavior on controlled fixtures, not real-world precision or recall. All severities are rule-defined and are not calibrated probabilities.
