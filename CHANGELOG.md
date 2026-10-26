# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- `Invoke-WinAudit` help described `-Severity` as "at or above" a level. It has
  always kept only the severities you list; the help now says so, and
  `tests/WinAudit.Invoke.Tests.ps1` pins the filter and exit-code behaviour.

### Changed

- README: the module has 23 checks across six categories (it said 20 and
  five), security reports go through a private advisory (`SECURITY.md`),
  and a "Known limitations" section lists gaps found by a static review.
- CI declares `permissions: contents: read`.

### Added

- `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.

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
