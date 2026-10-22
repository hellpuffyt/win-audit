# Security policy

## Supported versions

Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please report security issues in win-audit itself privately through GitHub:
https://github.com/hellpuffyt/win-audit/security/advisories/new

Do not open a public issue for a vulnerability, and do not attach real
audit reports: they list a machine's accounts, shares, services and
weaknesses. Describe the problem with synthetic data instead.

## Scope

win-audit is designed to be read-only: it reads system state and writes
only the report file you name with `-OutputPath`. In scope: any code path
that changes system state, executes a remediation command, writes outside
`-OutputPath`, or can be made to run attacker-controlled code (for example
through a crafted service path, task action or share name). Findings that
win-audit reports about your machine are not vulnerabilities in win-audit.
