# Contributing

Thanks for considering a contribution to `win-audit`.

## Ground rules

- **Read-only, always.** Nothing in this module may change system state.
  `-Remediate` prints a command; it never runs one. Any change that
  executes a mutating command against the live system will be rejected.
- **Collectors stay thin.** A collector's only job is to call a native
  cmdlet/API and return plain `[pscustomobject]` data. Decision-making
  (what counts as a finding, and at what severity) belongs in an analyser
  in `Private/Analyzers.ps1`, not in a collector.
- **Analysers stay pure.** No filesystem, registry, or CIM access inside
  an analyser. They take data in, return `WinAudit.Finding` objects out.
  This is what makes them testable without a vulnerable machine.

## Adding a new check

1. Add or extend a collector in `Private/Collectors.ps1` if the raw data
   isn't already gathered.
2. Add the rule to the relevant `Get-WinAudit*Findings` function in
   `Private/Analyzers.ps1`, building the finding with `New-WinAuditFinding`.
   Give it a new, stable `WA-<CATEGORY>-<NNN>` ID.
3. Add a Pester test proving the rule **fires** on a synthetic finding
   object, and a second test proving it does **not** fire on a healthy
   one. Both are required - the no-fire test is what keeps the tool from
   becoming too noisy to trust.
4. Document the check in the README's checks table.

## Before submitting a change

```powershell
Import-Module PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning

Import-Module Pester -MinimumVersion 5.5.0
Invoke-Pester -Path tests -CI
```

Both must be clean. If PSScriptAnalyzer flags something that is a
deliberate, justified choice (e.g. `Write-Host` for interactive console
output), use a scoped `SuppressMessageAttribute` with a `Justification`
on the specific function - not a blanket exclusion.

## Style

- Follow the existing module layout: `Public/` for exported cmdlets,
  `Private/` for collectors, analysers, and helpers.
- PowerShell 5.1 compatible syntax (no `??`, no ternary operator).
- Every exported function needs comment-based help.
