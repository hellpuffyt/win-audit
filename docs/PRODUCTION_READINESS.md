# Production readiness — win-audit

Audit of the `audit/production-readiness` branch. Evidence only; the
classification at the end is a proposal for the maintainer to confirm.

- Tested commit: `18c9dd7` (adds this file, the README/CHANGELOG/SECURITY.md/
  .editorconfig changes and CI permissions). Module code (`*.ps1`, `*.psm1`,
  `*.psd1`, `tests/`) is byte-identical to the default branch (`38c8ec3`),
  which is what was linted and tested.
- Date: 2026-10-22
- Audit host: macOS 27 (Apple Silicon). **No Windows host and no Windows
  PowerShell were available.** PowerShell 7.6.7 (official linux-arm64 build,
  SHA-256 checked) was run inside a throwaway Ubuntu 24.04 container to get
  the platform-neutral evidence below.

## Scope

A PowerShell module (`Invoke-WinAudit`) that audits a Windows machine
read-only: thin collectors (CIM, `Get-ScheduledTask`, `Get-SmbShare`,
registry reads, `Get-Acl`, `Get-AuthenticodeSignature`, firewall cmdlets)
feed pure analysers that emit findings with severity, risk text and a
remediation command, which is printed, never executed. 23 rules across six
categories. Windows PowerShell 5.1+.

## What was verified, and how

| Evidence | Environment | Result |
|---|---|---|
| Read-only claim (static) | source review of `Private/`, `Public/`, `WinAudit.psm1` | No state-changing cmdlet, registry write, `Invoke-Expression`, `Start-Process` or `&` of finding text in any code path. Every `Set-`/`Remove-`/`Disable-`… occurrence is inside a `-Remediation` string literal. The only writes are the report itself: `Out-File`/`Export-Csv` to the user-supplied `-OutputPath`. `-Remediate` only calls `Write-Host` with the remediation strings. |
| `Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning` (the CI gate) | pwsh 7.6.7 / PSScriptAnalyzer 1.25.0, Linux container | 0 warnings, 0 errors; 1 informational (`PSUseOutputTypeCorrectly`) |
| `Import-Module ./WinAudit.psd1` | same | imports; exports exactly `Invoke-WinAudit` |
| `Invoke-Pester -Path tests` | same, Pester 6.2.0 | 99 tests: 95 passed, 4 failed, 0 skipped. All 68 analyser, 23 helper and 2 module tests pass. The 4 failures are collector tests that `Mock` `Get-CimInstance` / `Get-LocalGroupMember`, which do not exist on Linux (`CommandNotFoundException`), so they cannot run here. They are counted as failed, not as passed. |
| CI definition | `.github/workflows/ci.yml` | single job on `windows-latest`, `shell: powershell` (Windows PowerShell 5.1): installs Pester ≥ 5.5.0 and PSScriptAnalyzer, fails on any analyzer warning, imports the module, runs Pester with `Run.Exit`, uploads results. Default branch run: success. |

## What remains unverified

- **No collector has ever been executed against a live system** by this
  audit, and CI does not run `Invoke-WinAudit` either: it only imports the
  module and runs mocked tests. Whether CIM / scheduled-task / SMB /
  firewall / registry reads behave as assumed on real Windows is unverified.
- Windows PowerShell 5.1 behaviour (the documented minimum). Only PowerShell
  7 on Linux was run.
- The 4 mocked collector tests (Windows-only cmdlets).
- CI on this branch (pending until pushed). CI installs Pester with
  `-MinimumVersion 5.5.0`, which today resolves to Pester 6.x; the suite
  passed under Pester 6.2.0 on pwsh 7, but not verified on Windows
  PowerShell 5.1.

## Issues found by static review (documented, not fixed)

Nothing can be executed against Windows here, so no module code was changed.
A fix without the ability to run its test would be untested code. These are
listed in the README "Known limitations" and proposed for the maintainer:

| # | Issue | Effect | Proposed fix |
|---|---|---|---|
| 1 | SMBv1 is read only from `LanmanServer\Parameters\SMB1`, which is absent on most current systems. | WA-POL-002 false negative when SMBv1 is enabled via the optional feature. | Use `(Get-SmbServerConfiguration).EnableSMB1Protocol` (read-only), falling back to the registry. |
| 2 | Defender real-time protection is read only from the Group Policy key. | WA-POL-005 misses real-time protection turned off locally. | `(Get-MpComputerStatus).RealTimeProtectionEnabled` when available. |
| 3 | WinRM `AllowUnencrypted` is read only from the policy key. | WA-POL-007 misses the local `WSMan:\localhost\Service\AllowUnencrypted` setting. | Also read the WSMan provider value. |
| 4 | Administrators group looked up by English name. | On localized Windows, WA-ACC-002 silently reports nothing (exception swallowed). | Look up by SID `S-1-5-32-544`; warn when the lookup fails. |
| 5 | `$findings \| ConvertTo-Json` | One finding → a JSON object, not an array; zero findings → no output, not `[]`. Consumers must special-case both. | `ConvertTo-Json -InputObject @($findings) -Depth 5`. |
| 6 | WA-SVC-001 treats `LocalService`/`NetworkService` as privileged and its text says "SYSTEM privileges". | Overstated risk text for those accounts (conservative, not a miss). | Word the risk by account. |
| 7 | User-writable heuristic ignores `C:\ProgramData`. | Possible WA-SVC-001 / WA-TASK-001 misses for binaries there. | Check the directory ACL instead of the path pattern where available. |

## Changes on this branch

- README: "20 checks across five categories" corrected to 23 across six (the
  rules table and code have 23 rule IDs); security reports go to a private
  advisory instead of a public issue; "Known limitations" section added.
- `SECURITY.md`, `.editorconfig`, CHANGELOG `[Unreleased]` entry.
- CI: `permissions: contents: read` (the job only reads the repository and
  uploads an artifact). Action references are tag pins (`@v4`), left as they
  were.

## Clean-clone verification

`git clone` of the branch into an empty scratch directory: the files match
the branch, `WinAudit.psd1` / `WinAudit.psm1` / `Private/` / `Public/` /
`tests/` are present. The README's own steps (`Import-Module
.\win-audit\WinAudit.psd1`, `Invoke-WinAudit`, `Invoke-Pester -Path tests
-CI`) need Windows and could not be followed literally. The platform-neutral
subset was run from the same tree in the container above.

## Security review

- Read-only claim holds by reading (see table). No network access, no
  dynamic code execution; remediation strings embed service/task/share names
  from the system but are only printed, never evaluated.
- No external module dependencies at runtime. Secret scan of the full
  history: no hits.

## CI status

- Default branch (`38c8ec3`): success.
- Audit branch: pending until pushed.

## Acceptance checklist

| Item | Expected behavior | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Read-only | no state-changing call outside report output | static review | pass (static) | none found | Private/, Public/ |
| Lint | 0 analyzer warnings | `Invoke-ScriptAnalyzer -Severity Warning` | pass (pwsh 7, Linux) | 0 | ci.yml |
| Analyser rules | each fires on bad input, not on healthy | `WinAudit.Analyzers.Tests.ps1` | pass (pwsh 7, Linux) | 68/68 | Analyzers.ps1 |
| Helpers | path/ACL/severity heuristics | `WinAudit.Helpers.Tests.ps1` | pass (pwsh 7, Linux) | 23/23 | Helpers.ps1 |
| Module surface | exports only `Invoke-WinAudit` | `WinAudit.Module.Tests.ps1`, import | pass | 2/2 | WinAudit.psm1 |
| Collector shape | mocked CIM/group data maps correctly | `WinAudit.Collectors.Tests.ps1` | 2 pass, 4 not runnable off Windows | — | Collectors.ps1 |
| Live audit on Windows | runs, returns findings, changes nothing | needs Windows | not run | — | Invoke-WinAudit.ps1 |
| Windows PowerShell 5.1 | supported minimum | needs Windows | not run | — | WinAudit.psd1 |

## Classification proposal

**Partially Verified**, the most this host allows. The read-only design was
checked by reading; lint and the 95 platform-neutral tests pass under
PowerShell 7 on Linux. Nothing has run on Windows: neither the live
collectors, Windows PowerShell 5.1, nor the 4 Windows-only mocked tests.
Static review found the detection gaps listed above.
