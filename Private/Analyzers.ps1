#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
    Analysers are pure functions: raw collector data in, [WinAudit.Finding]
    objects out. None of these touch the filesystem, the registry, or a
    live service - which is what makes them exhaustively unit-testable
    with synthetic [pscustomobject] input.
#>

function Get-WinAuditServiceFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Services
    )

    $findings = @()
    $privilegedAccounts = @('LocalSystem', 'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService')

    foreach ($svc in $Services) {
        $startName = [string]$svc.StartName
        $isPrivileged = ($privilegedAccounts -contains $startName) -or [string]::IsNullOrWhiteSpace($startName)
        $binaryPath = if ($svc.PSObject.Properties.Match('BinaryPath').Count -gt 0 -and $svc.BinaryPath) {
            $svc.BinaryPath
        }
        else {
            Get-WinAuditBinaryPathFromServicePath -PathName $svc.PathName
        }

        # WA-SVC-001: privileged service binary in a user-writable directory.
        if ($isPrivileged -and (Test-WinAuditUserWritablePath -Path $binaryPath)) {
            $findings += New-WinAuditFinding -Id 'WA-SVC-001' -Severity 'Critical' -Category 'Services' `
                -Object $svc.Name `
                -Risk "The service '$($svc.Name)' runs as $startName but its executable lives in a location a standard user can write to. A local user can replace the binary and have it run with SYSTEM privileges on next start or reboot - a direct path to full privilege escalation." `
                -Remediation "Move the binary for '$($svc.Name)' to a protected location (e.g. Program Files) and update it: `$svc = Get-CimInstance Win32_Service -Filter `"Name='$($svc.Name)'`"; Invoke-CimMethod -InputObject `$svc -MethodName Change -Arguments @{ PathName = 'C:\Program Files\<Vendor>\<app>.exe' }" `
                -Details "PathName: $($svc.PathName)"
        }

        # WA-SVC-002: unquoted service path with a space in the executable path.
        if (Test-WinAuditUnquotedServicePath -PathName $svc.PathName) {
            $findings += New-WinAuditFinding -Id 'WA-SVC-002' -Severity 'High' -Category 'Services' `
                -Object $svc.Name `
                -Risk "The service '$($svc.Name)' has an unquoted path containing spaces. Windows will try each space-delimited prefix as a candidate executable before the real one - if a local user can drop a file at one of those prefixes, it runs with the service's privileges." `
                -Remediation "sc.exe config `"$($svc.Name)`" binPath= `"$binaryPath`"" `
                -Details "PathName: $($svc.PathName)"
        }

        # WA-SVC-003: weak binary ACL - Everyone/Authenticated Users/Users can write to the executable.
        if (Test-WinAuditWeakAcl -AccessRules $svc.AccessRules) {
            $findings += New-WinAuditFinding -Id 'WA-SVC-003' -Severity 'Critical' -Category 'Services' `
                -Object $svc.Name `
                -Risk "The executable backing service '$($svc.Name)' grants write access to a broad, low-privilege group. Anyone in that group can overwrite the binary and have it execute with the service's privileges." `
                -Remediation "icacls `"$binaryPath`" /remove:g Everyone `"Authenticated Users`" `"BUILTIN\Users`"; icacls `"$binaryPath`" /grant:r `"BUILTIN\Administrators:F`" `"NT AUTHORITY\SYSTEM:F`"" `
                -Details "BinaryPath: $binaryPath"
        }

        # WA-SVC-004: auto-start service whose binary is not Microsoft-signed.
        if ($svc.StartMode -eq 'Auto' -and $svc.PSObject.Properties.Match('IsMicrosoftSigned').Count -gt 0 -and $svc.IsMicrosoftSigned -eq $false) {
            $findings += New-WinAuditFinding -Id 'WA-SVC-004' -Severity 'Low' -Category 'Services' `
                -Object $svc.Name `
                -Risk "The auto-start service '$($svc.Name)' is not signed by Microsoft. This is not inherently malicious - most third-party software is unsigned or signed by its vendor - but it increases the attack surface that starts unattended on every boot and is worth an inventory review." `
                -Remediation "Confirm the vendor and purpose of '$($svc.Name)', then either set it to Manual/Disabled if unneeded: Set-Service -Name '$($svc.Name)' -StartupType Manual, or verify it against your approved-software list." `
                -Details "BinaryPath: $binaryPath"
        }
    }

    return $findings
}

function Test-WinAuditWeakAcl {
    <#
        .SYNOPSIS
            Determines whether a set of filesystem access rules grants
            write-class access to a broad, low-privilege principal.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object[]]$AccessRules
    )

    if (-not $AccessRules -or $AccessRules.Count -eq 0) {
        return $false
    }

    $broadPrincipals = @('Everyone', 'NT AUTHORITY\Authenticated Users', 'Authenticated Users', 'BUILTIN\Users', 'Users')

    foreach ($rule in $AccessRules) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($broadPrincipals -notcontains $rule.IdentityReference) { continue }
        if ($rule.FileSystemRights -match 'Write|Modify|FullControl') {
            return $true
        }
    }

    return $false
}

function Get-WinAuditScheduledTaskFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Tasks
    )

    $findings = @()

    foreach ($task in $Tasks) {
        $fullName = if ($task.TaskPath) { "$($task.TaskPath)$($task.TaskName)" } else { $task.TaskName }
        $runAsSystem = $task.RunAsUser -match '^(NT AUTHORITY\\)?SYSTEM$'

        # WA-TASK-001: SYSTEM task whose action points at a user-writable path.
        if ($runAsSystem) {
            foreach ($actionPath in $task.Actions) {
                $exePath = Get-WinAuditBinaryPathFromServicePath -PathName $actionPath
                if (Test-WinAuditUserWritablePath -Path $exePath) {
                    $findings += New-WinAuditFinding -Id 'WA-TASK-001' -Severity 'Critical' -Category 'ScheduledTasks' `
                        -Object $fullName `
                        -Risk "Scheduled task '$fullName' runs as SYSTEM and executes a program from a user-writable location. A local user can replace that file to gain SYSTEM code execution on the task's next trigger." `
                        -Remediation "Move the target of '$fullName' to a protected directory and update the task action: `$action = New-ScheduledTaskAction -Execute 'C:\Program Files\<Vendor>\<app>.exe'; Set-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)' -Action `$action" `
                        -Details "Action: $actionPath"
                    break
                }
            }
        }

        # WA-TASK-002: task configured with a stored password (LogonType Password).
        if ($task.LogonType -eq 'Password') {
            $findings += New-WinAuditFinding -Id 'WA-TASK-002' -Severity 'High' -Category 'ScheduledTasks' `
                -Object $fullName `
                -Risk "Scheduled task '$fullName' stores a plaintext-recoverable credential (LogonType=Password) in the Task Scheduler credential store. An attacker with SYSTEM or admin access can extract it via vault/LSA tooling and reuse the account elsewhere." `
                -Remediation "Reconfigure '$fullName' to run under a Group Managed Service Account or with LogonType S4U/ServiceAccount instead of a stored password: Set-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)' -User 'DOMAIN\gMSA$' -LogonType Password -> prefer -LogonType ServiceAccount with a gMSA." `
                -Details "LogonType: $($task.LogonType)"
        }

        # WA-TASK-003: logon-triggered task defined outside the standard Microsoft task tree.
        if (($task.Triggers -contains 'Logon') -and ($task.TaskPath -notmatch '^\\Microsoft\\')) {
            $findings += New-WinAuditFinding -Id 'WA-TASK-003' -Severity 'Medium' -Category 'ScheduledTasks' `
                -Object $fullName `
                -Risk "Task '$fullName' fires at user logon and lives outside the standard \Microsoft\ task tree - a common persistence pattern for malware and unauthorized software. It deserves a look even if it turns out to be legitimate." `
                -Remediation "Review the task's action and owner, then disable it if unwanted: Disable-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)'" `
                -Details "TaskPath: $($task.TaskPath)"
        }
    }

    return $findings
}

function Get-WinAuditShareFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Shares,

        [bool]$AutoShareEnabled = $false
    )

    $findings = @()
    $broadPrincipals = @('Everyone', 'Authenticated Users', 'NT AUTHORITY\Authenticated Users')
    $writeRights = @('Full', 'Change')
    $sawAdminShare = $false

    foreach ($share in $Shares) {
        $isAdmin = $share.Name -match '\$$'
        if ($isAdmin) { $sawAdminShare = $true }

        # WA-SHR-001: Everyone/Authenticated Users granted write-class access.
        foreach ($rule in $share.AccessRules) {
            if ($rule.AccessControlType -eq 'Allow' -and
                ($broadPrincipals -contains $rule.AccountName) -and
                ($writeRights -contains $rule.AccessRight)) {
                $findings += New-WinAuditFinding -Id 'WA-SHR-001' -Severity 'Critical' -Category 'Shares' `
                    -Object $share.Name `
                    -Risk "Share '$($share.Name)' grants '$($rule.AccountName)' $($rule.AccessRight) access. Any user on the network (or any local account, if 'Everyone' includes them) can write files into it - including planting an executable that runs when another user or a service opens it." `
                    -Remediation "Revoke-SmbShareAccess -Name '$($share.Name)' -AccountName '$($rule.AccountName)' -Force; Grant-SmbShareAccess -Name '$($share.Name)' -AccountName 'BUILTIN\Users' -AccessRight Read -Force" `
                    -Details "Path: $($share.Path)"
                break
            }
        }

        # WA-SHR-003: share path itself is user-writable at the filesystem level.
        if (Test-WinAuditUserWritablePath -Path $share.Path) {
            $findings += New-WinAuditFinding -Id 'WA-SHR-003' -Severity 'Medium' -Category 'Shares' `
                -Object $share.Name `
                -Risk "Share '$($share.Name)' points at '$($share.Path)', a path that is typically writable by standard users regardless of the share-level ACL. NTFS permissions on the folder itself may undermine any restriction placed at the share level." `
                -Remediation "Move the shared content to a dedicated, access-controlled directory and re-point the share: Set-SmbShare -Name '$($share.Name)' -Path 'D:\Shares\<name>'; then set NTFS ACLs with icacls." `
                -Details "Path: $($share.Path)"
        }
    }

    # WA-SHR-002: administrative shares present with the default auto-share policy still enabled.
    if ($sawAdminShare -and $AutoShareEnabled) {
        $findings += New-WinAuditFinding -Id 'WA-SHR-002' -Severity 'Low' -Category 'Shares' `
            -Object 'AdministrativeShares' `
            -Risk 'Administrative shares (C$, ADMIN$, etc.) are present and Windows will keep recreating them on every reboot because AutoShareServer/AutoShareWks is still enabled. These shares let anyone with local admin credentials reach the full disk over the network, widening lateral-movement options if credentials are ever compromised.' `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareServer -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareWks -Value 0 -Type DWord  # then remove existing admin shares with Remove-SmbShare" `
            -Details 'Applies machine-wide; admin shares are recreated on reboot until this policy is changed.'
    }

    return $findings
}

function Get-WinAuditAccountFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Accounts,

        [AllowNull()]
        [object[]]$AdministratorsGroupMembers = @()
    )

    $findings = @()

    foreach ($account in $Accounts) {
        if ($account.Disabled) { continue }

        # WA-ACC-001: password never expires.
        if ($account.PasswordExpires -eq $false) {
            $findings += New-WinAuditFinding -Id 'WA-ACC-001' -Severity 'Low' -Category 'Accounts' `
                -Object $account.Name `
                -Risk "Account '$($account.Name)' is configured so its password never expires. A compromised or weak credential for this account stays valid indefinitely instead of being forced to rotate." `
                -Remediation "`$acc = Get-LocalUser -Name '$($account.Name)'; `$acc | Set-LocalUser -PasswordNeverExpires `$false" `
                -Details ''
        }

        # WA-ACC-003 / WA-ACC-004: Guest enabled, or account permits a blank password.
        if ($account.Name -eq 'Guest') {
            $findings += New-WinAuditFinding -Id 'WA-ACC-003' -Severity 'High' -Category 'Accounts' `
                -Object $account.Name `
                -Risk 'The built-in Guest account is enabled. It provides an unauthenticated or trivially-authenticated entry point to the machine and is one of the first accounts attackers probe for.' `
                -Remediation "Disable-LocalUser -Name 'Guest'" `
                -Details ''
        }

        if ($account.PasswordRequired -eq $false) {
            $findings += New-WinAuditFinding -Id 'WA-ACC-004' -Severity 'Critical' -Category 'Accounts' `
                -Object $account.Name `
                -Risk "Account '$($account.Name)' does not require a password. Anyone with local or, if enabled, network logon rights can authenticate as this user with no credential at all." `
                -Remediation "`$acc = Get-LocalUser -Name '$($account.Name)'; `$acc | Set-LocalUser -PasswordNeverExpires `$false; Set-LocalUser -Name '$($account.Name)' -Password (Read-Host -AsSecureString 'New password')" `
                -Details ''
        }
    }

    # WA-ACC-002: membership in the local Administrators group, for inventory/review.
    foreach ($member in $AdministratorsGroupMembers) {
        $findings += New-WinAuditFinding -Id 'WA-ACC-002' -Severity 'Info' -Category 'Accounts' `
            -Object $member.Name `
            -Risk "'$($member.Name)' is a member of the local Administrators group and can fully control this machine, including disabling security controls and reading any local secret. Not a defect by itself - flagged so the admin roster can be reviewed for anyone who should not be there." `
            -Remediation "Remove-LocalGroupMember -Group 'Administrators' -Member '$($member.Name)'  # only if membership is unwarranted" `
            -Details "ObjectClass: $($member.ObjectClass)"
    }

    return $findings
}

function Get-WinAuditPolicyFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Policy
    )

    $findings = @()

    # WA-POL-001: LM/NTLMv1 permitted (level below 3 allows LM/NTLMv1 responses).
    if ($null -ne $Policy.LmCompatibilityLevel -and [int]$Policy.LmCompatibilityLevel -lt 3) {
        $findings += New-WinAuditFinding -Id 'WA-POL-001' -Severity 'High' -Category 'Policy' `
            -Object 'LmCompatibilityLevel' `
            -Risk 'The LAN Manager authentication level permits LM and/or NTLMv1 responses, both of which are crackable with commodity hardware and vulnerable to relay attacks. An attacker who can capture or coerce authentication traffic can recover usable credentials.' `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord" `
            -Details "Current level: $($Policy.LmCompatibilityLevel) (send NTLMv2 only, refuse LM/NTLM = 5)"
    }

    # WA-POL-002: SMBv1 enabled.
    if ($Policy.Smb1Enabled -eq $true) {
        $findings += New-WinAuditFinding -Id 'WA-POL-002' -Severity 'Critical' -Category 'Policy' `
            -Object 'SMB1Protocol' `
            -Risk 'SMBv1 is enabled. It has no protection against relay attacks, weak integrity checking, and was the transport for EternalBlue/WannaCry-class worms. There is no supported reason to keep it on outside of legacy device compatibility.' `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
            -Details ''
    }

    # WA-POL-003: UAC disabled or set to never-notify.
    if ($Policy.UacEnabled -eq $false) {
        $findings += New-WinAuditFinding -Id 'WA-POL-003' -Severity 'High' -Category 'Policy' `
            -Object 'UAC' `
            -Risk 'User Account Control is disabled entirely. All processes run with the full rights of the logged-on account with no elevation prompt, so any malicious or compromised process silently gets administrator-level access.' `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord  # then reboot" `
            -Details ''
    }
    elseif ($Policy.UacNeverNotify -eq $true) {
        $findings += New-WinAuditFinding -Id 'WA-POL-003' -Severity 'Medium' -Category 'Policy' `
            -Object 'UAC' `
            -Risk 'UAC is set to elevate without prompting for administrators. Malware running under an admin token can self-elevate with no user-visible consent step.' `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord" `
            -Details ''
    }

    # WA-POL-004: PowerShell script block logging disabled.
    if ($Policy.ScriptBlockLogging -eq $false) {
        $findings += New-WinAuditFinding -Id 'WA-POL-004' -Severity 'Medium' -Category 'Policy' `
            -Object 'PowerShellScriptBlockLogging' `
            -Risk 'PowerShell script block logging is disabled. Obfuscated or malicious PowerShell run on this machine leaves little forensic trail, which slows detection and incident response significantly.' `
            -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord" `
            -Details ''
    }

    # WA-POL-005: Defender real-time protection disabled.
    if ($Policy.DefenderRealTimeOff -eq $true) {
        $findings += New-WinAuditFinding -Id 'WA-POL-005' -Severity 'High' -Category 'Policy' `
            -Object 'DefenderRealTimeProtection' `
            -Risk 'Windows Defender real-time protection is disabled. Malware delivered after this point will not be scanned or blocked on write/execute.' `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Details ''
    }

    # WA-POL-006: RDP enabled with Network Level Authentication off.
    if ($Policy.RdpEnabled -eq $true -and $Policy.RdpNlaEnabled -eq $false) {
        $findings += New-WinAuditFinding -Id 'WA-POL-006' -Severity 'High' -Category 'Policy' `
            -Object 'RemoteDesktop' `
            -Risk 'Remote Desktop is enabled without Network Level Authentication. The full logon UI is exposed pre-authentication, increasing exposure to unauthenticated RDP vulnerabilities and credential-guessing tools.' `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord" `
            -Details ''
    }

    # WA-POL-007: WinRM allows unencrypted traffic.
    if ($Policy.WinRmAllowUnencrypted -eq $true) {
        $findings += New-WinAuditFinding -Id 'WA-POL-007' -Severity 'High' -Category 'Policy' `
            -Object 'WinRM' `
            -Risk 'WinRM is configured to allow unencrypted traffic. Commands, output, and any credentials passed through a WinRM session can be read by anyone on the network path.' `
            -Remediation "Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value `$false" `
            -Details ''
    }

    return $findings
}

function Get-WinAuditFirewallFindings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Each function returns zero or more finding objects; the plural noun accurately describes the return value.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Profiles,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rules
    )

    $findings = @()

    foreach ($fwProfile in $Profiles) {
        # WA-FW-001: firewall profile disabled.
        if ($fwProfile.Enabled -eq $false) {
            $findings += New-WinAuditFinding -Id 'WA-FW-001' -Severity 'High' -Category 'Firewall' `
                -Object $fwProfile.Name `
                -Risk "The Windows Firewall '$($fwProfile.Name)' profile is disabled. Every inbound connection on that profile is unfiltered - any listening service is directly reachable regardless of its own configuration." `
                -Remediation "Set-NetFirewallProfile -Name '$($fwProfile.Name)' -Enabled True" `
                -Details ''
        }
    }

    foreach ($rule in $Rules) {
        # WA-FW-002: inbound allow rule open to Any address on Any port.
        if ($rule.Enabled -eq $true -and $rule.AddressAny -eq $true -and $rule.PortAny -eq $true) {
            $findings += New-WinAuditFinding -Id 'WA-FW-002' -Severity 'High' -Category 'Firewall' `
                -Object $rule.DisplayName `
                -Risk "Inbound rule '$($rule.DisplayName)' allows any protocol from any remote address to any local port. This effectively removes the firewall's protection for whatever is listening, exposing every local service to the network." `
                -Remediation "Set-NetFirewallRule -Name '$($rule.Name)' -RemoteAddress <trusted-range> -LocalPort <required-ports> -Protocol <TCP|UDP>  # scope the rule down, or: Disable-NetFirewallRule -Name '$($rule.Name)'" `
                -Details "Rule name: $($rule.Name)"
        }
    }

    return $findings
}
