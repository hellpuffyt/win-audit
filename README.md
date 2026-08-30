# win-audit

A read-only PowerShell module that audits a Windows machine's security
posture - services, scheduled tasks, shares, local accounts/policy, and
firewall configuration - and reports findings with a severity, a
plain-language explanation of what an attacker gains, and the exact
PowerShell command to fix it.

## What

`Invoke-WinAudit` inspects the machine it runs on and returns a list of
findings. Each finding has a stable ID, a severity (Info/Low/Medium/
High/Critical), the object it concerns, the risk in plain terms, and a
copy-pasteable remediation command. Nothing is changed on the system -
not even with `-Remediate`.

## Why

Windows hardening guidance mostly exists as long PDFs (CIS benchmarks,
STIGs, vendor whitepapers). What an administrator actually needs day to
day is something that looks at *this* machine, tells them what is
actually wrong right now, explains why it matters, and gives them the
command to fix it - without taking any action on its own. A security
tool that changes things while you're still assessing the machine is a
liability, so `win-audit` never does.

## Features

- **Read-only by design.** Every check is a collector (raw data in) plus
  a pure analyser (findings out) - no check ever writes to the registry,
  the filesystem, a service, or account state.
- **20 checks** across five categories: services, scheduled tasks,
  shares, accounts, policy, and firewall.
- **Severity-scored findings** with plain-language risk explanations and
  a ready-to-review remediation command for each.
- **Filterable**: `-Severity`, `-Only`, and `-Exclude` narrow the report
  by severity, rule ID, or category.
- **Three output formats**: console table, JSON, CSV.
- **CI-friendly exit code**: `-FailSeverityThreshold` sets a non-zero
  exit code when a finding at or above that severity is present, for use
  in a scheduled compliance check.
- **`-Remediate` is reference-only.** It prints every finding's fix
  command to the console. It does not, and will never, execute anything.

## Checks reference

| ID | Category | Check | Risk | Remediation (example) |
|---|---|---|---|---|
| WA-SVC-001 | Services | Privileged service binary in a user-writable directory | Local user replaces the binary; runs as SYSTEM on next start | Move binary to a protected path, update `PathName` via `Invoke-CimMethod` |
| WA-SVC-002 | Services | Unquoted service path containing a space | Classic unquoted-service-path privilege escalation | `sc.exe config <svc> binPath= "<quoted path>"` |
| WA-SVC-003 | Services | Weak ACL on the service binary (Everyone/Users can write) | Anyone in that group can overwrite the binary | `icacls` to remove the broad grant, restrict to Administrators/SYSTEM |
| WA-SVC-004 | Services | Auto-start service not Microsoft-signed | Larger unattended attack surface on every boot | Review vendor; `Set-Service -StartupType Manual` if unneeded |
| WA-TASK-001 | Scheduled Tasks | SYSTEM task action in a user-writable path | Local user swaps the binary; SYSTEM code execution on next trigger | Move target to a protected path, `Set-ScheduledTask` with new action |
| WA-TASK-002 | Scheduled Tasks | Task stores a password credential (LogonType=Password) | Credential recoverable by an admin/SYSTEM attacker | Reconfigure with a gMSA / `-LogonType ServiceAccount` |
| WA-TASK-003 | Scheduled Tasks | Logon-triggered task outside `\Microsoft\` task tree | Common persistence pattern; deserves review | `Disable-ScheduledTask` if unwanted |
| WA-SHR-001 | Shares | Everyone/Authenticated Users granted write/change | Any network user can write into the share | `Revoke-SmbShareAccess` / `Grant-SmbShareAccess` with a scoped principal |
| WA-SHR-002 | Shares | Administrative shares present with auto-share policy still on | Anyone with local admin creds reaches the full disk over the network | Disable `AutoShareServer`/`AutoShareWks` in the registry |
| WA-SHR-003 | Shares | Share path itself is user-writable at the filesystem level | NTFS ACL on the folder can undermine the share ACL | Move content to a dedicated, ACL'd directory |
| WA-ACC-001 | Accounts | Password never expires | Compromised credential never forced to rotate | `Set-LocalUser -PasswordNeverExpires $false` |
| WA-ACC-002 | Accounts | Member of local Administrators (inventory) | Full control of the machine - review for anyone who shouldn't be there | `Remove-LocalGroupMember` if unwarranted |
| WA-ACC-003 | Accounts | Guest account enabled | Unauthenticated/trivial entry point | `Disable-LocalUser -Name Guest` |
| WA-ACC-004 | Accounts | Account does not require a password | Anyone can authenticate with no credential | Set a password; require one going forward |
| WA-POL-001 | Policy | LM/NTLMv1 responses permitted | Crackable/relayable authentication | `LmCompatibilityLevel = 5` |
| WA-POL-002 | Policy | SMBv1 enabled | No relay protection; EternalBlue-class exposure | `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol` |
| WA-POL-003 | Policy | UAC disabled or set to never-notify | Silent/automatic elevation for any process | `EnableLUA`/`ConsentPromptBehaviorAdmin` registry values |
| WA-POL-004 | Policy | PowerShell script block logging disabled | No forensic trail for malicious PowerShell | Enable `EnableScriptBlockLogging` policy |
| WA-POL-005 | Policy | Defender real-time protection disabled | Malware not scanned on write/execute | `Set-MpPreference -DisableRealtimeMonitoring $false` |
| WA-POL-006 | Policy | RDP enabled without Network Level Authentication | Pre-auth exposure of the logon UI | Set `UserAuthentication = 1` on the RDP-Tcp listener |
| WA-POL-007 | Policy | WinRM allows unencrypted traffic | Commands/credentials readable on the wire | `Set-Item WSMan:\localhost\Service\AllowUnencrypted $false` |
| WA-FW-001 | Firewall | A firewall profile is disabled | Every inbound connection on that profile is unfiltered | `Set-NetFirewallProfile -Enabled True` |
| WA-FW-002 | Firewall | Inbound allow rule open on Any address/Any port | Removes firewall protection for whatever is listening | Scope the rule's address/port, or disable it |

## Architecture

```
WinAudit.psd1          Module manifest
WinAudit.psm1           Loader: dot-sources Private/ then Public/, exports Public/
Public/
  Invoke-WinAudit.ps1    Entry point: orchestrates collectors + analysers, filters, formats output
Private/
  Collectors.ps1         Thin wrappers over Get-CimInstance / Get-ScheduledTask / Get-SmbShare /
                          Get-LocalUser / registry reads. Return plain data, no decisions.
  Analyzers.ps1           Pure functions: raw data in, WinAudit.Finding objects out. No I/O.
  Helpers.ps1             Shared pure helpers (path heuristics, ACL checks, severity ranking).
tests/                    Pester 5 suite - analysers tested with synthetic objects, a few
                          collector paths tested with Mock.
```

The collector/analyser split is what makes this testable without a real
vulnerable machine: every rule's logic lives in a function that takes
`[pscustomobject]` input and returns finding objects, with zero calls to
`Get-Service`, the registry, or anything else live.

## Installation

```powershell
git clone https://github.com/hellpuffyt/win-audit.git
Import-Module .\win-audit\WinAudit.psd1
```

Requires Windows PowerShell 5.1 or later. No external dependencies for
running the module itself (Pester and PSScriptAnalyzer are only needed
to run the test suite / linter).

## Usage

```powershell
# Full report to the console
Invoke-WinAudit

# Only High/Critical findings, as JSON to a file
Invoke-WinAudit -Severity High,Critical -OutputFormat Json -OutputPath report.json

# Just the service checks, CSV to a file
Invoke-WinAudit -Only Services -OutputFormat Csv -OutputPath services.csv

# Exclude a noisy rule
Invoke-WinAudit -Exclude WA-SVC-004

# Print remediation commands for review (nothing is executed)
Invoke-WinAudit -Remediate

# Scheduled compliance check: non-zero exit code if anything High+ is found
Invoke-WinAudit -FailSeverityThreshold High -OutputFormat Json -OutputPath C:\reports\audit.json
exit $LASTEXITCODE
```

## Output

- **Console** (default): a sorted, colour-free table - severity descending,
  then category.
- **JSON**: `-OutputFormat Json [-OutputPath <file>]`. Written to the
  pipeline if no path is given.
- **CSV**: `-OutputFormat Csv [-OutputPath <file>]`. Same fallback.

Every finding object has: `Id`, `Severity`, `Category`, `Object`, `Risk`,
`Remediation`, `Details`.

## Safety - read-only by design

`win-audit` never calls a state-changing cmdlet. Collectors only read
(`Get-*`, registry `Get-ItemProperty`, `Get-Acl`, `Get-AuthenticodeSignature`).
`-Remediate` formats and prints the same remediation string that's
already in each finding object - it does not build a script object, does
not use `Invoke-Expression`, and does not run anything. Review any
remediation command before you run it yourself; several of them
(disabling SMBv1, changing UAC, removing accounts) can affect other
software on the machine.

## Testing

```powershell
Import-Module Pester -MinimumVersion 5.5.0
Invoke-Pester -Path tests -CI
```

99 tests / 100+ assertions. Every analyser rule has a test proving it
fires on a crafted finding case and a separate test proving it does
**not** fire on the healthy equivalent - a security tool that's too
noisy gets turned off, so the false-positive guards get equal weight to
the detections themselves. A handful of collector tests mock
`Get-CimInstance`, `Get-ItemProperty`, and `Get-LocalGroupMember` to
verify the collector -> analyser data shape without touching the real
system.

Lint:

```powershell
Import-Module PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning
```

CI (`.github/workflows/ci.yml`) runs both on `windows-latest` only -
every check here reads Windows-specific state (CIM, the registry,
`Get-ScheduledTask`, `Get-SmbShare`, `Get-NetFirewallRule`), so this
module is Windows-only and CI does not claim otherwise.

## Security

If you find a security issue in this tool itself (not a finding it
reports about your machine), please open an issue describing the
problem. There is no separate disclosure address for this project.

## License

MIT - see [LICENSE](LICENSE).
