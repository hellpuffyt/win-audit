# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-08-30

### Added

- Initial release of `win-audit`.
- Read-only collectors for services, scheduled tasks, SMB shares, local
  accounts, security policy/registry state, and the Windows Firewall.
- Twenty analyser rules covering privilege-escalation-prone service and
  task configurations, weak share permissions, risky account settings,
  weak protocol/policy defaults, and permissive firewall rules.
- `Invoke-WinAudit` entry point with `-Severity`, `-Only`, `-Exclude`,
  `-OutputFormat` (Console/Json/Csv), `-FailSeverityThreshold`, and a
  `-Remediate` reference-only mode.
- Pester 5 test suite (99 tests) covering every analyser rule's fire and
  no-fire paths plus mocked collector paths.
