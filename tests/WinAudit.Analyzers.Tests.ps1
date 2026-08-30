#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Import-Module (Join-Path $PSScriptRoot '..\WinAudit.psd1') -Force

Describe 'Get-WinAuditServiceFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestSvc {
                param(
                    $Name = 'TestSvc',
                    $StartName = 'LocalSystem',
                    $PathName = '"C:\Program Files\Vendor\svc.exe"',
                    $StartMode = 'Auto',
                    $BinaryPath = 'C:\Program Files\Vendor\svc.exe',
                    $IsMicrosoftSigned = $true,
                    $AccessRules = @()
                )
                [pscustomobject]@{
                    Name              = $Name
                    DisplayName       = $Name
                    StartName         = $StartName
                    PathName          = $PathName
                    StartMode         = $StartMode
                    State             = 'Running'
                    BinaryPath        = $BinaryPath
                    IsMicrosoftSigned = $IsMicrosoftSigned
                    AccessRules       = $AccessRules
                }
            }
        }

        It 'WA-SVC-001 fires for a SYSTEM service with a binary in a user-writable directory' {
            $svc = Get-TestSvc -StartName 'LocalSystem' -PathName '"C:\Users\bob\svc.exe"' -BinaryPath 'C:\Users\bob\svc.exe'
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SVC-001 does not fire for a SYSTEM service with a binary under Program Files' {
            $svc = Get-TestSvc -StartName 'LocalSystem' -PathName '"C:\Program Files\Vendor\svc.exe"' -BinaryPath 'C:\Program Files\Vendor\svc.exe'
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-001') | Should -BeNullOrEmpty
        }

        It 'WA-SVC-002 fires for an unquoted path containing a space' {
            $svc = Get-TestSvc -PathName 'C:\Program Files\Vendor\svc.exe -k netsvcs' -BinaryPath 'C:\Program Files\Vendor\svc.exe'
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-002') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SVC-002 does not fire for a quoted path containing a space' {
            $svc = Get-TestSvc -PathName '"C:\Program Files\Vendor\svc.exe" -k netsvcs' -BinaryPath 'C:\Program Files\Vendor\svc.exe'
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-002') | Should -BeNullOrEmpty
        }

        It 'WA-SVC-002 does not fire for an unquoted path with no spaces' {
            $svc = Get-TestSvc -PathName 'C:\Windows\System32\svc.exe -k netsvcs' -BinaryPath 'C:\Windows\System32\svc.exe'
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-002') | Should -BeNullOrEmpty
        }

        It 'WA-SVC-003 fires when Everyone has Write access to the binary' {
            $rules = @([pscustomobject]@{ IdentityReference = 'Everyone'; FileSystemRights = 'Write'; AccessControlType = 'Allow' })
            $svc = Get-TestSvc -AccessRules $rules
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-003') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SVC-003 does not fire when only Administrators have FullControl' {
            $rules = @([pscustomobject]@{ IdentityReference = 'BUILTIN\Administrators'; FileSystemRights = 'FullControl'; AccessControlType = 'Allow' })
            $svc = Get-TestSvc -AccessRules $rules
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-003') | Should -BeNullOrEmpty
        }

        It 'WA-SVC-004 fires for an auto-start service that is not Microsoft-signed' {
            $svc = Get-TestSvc -StartMode 'Auto' -IsMicrosoftSigned $false
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-004') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SVC-004 does not fire for an auto-start service that is Microsoft-signed' {
            $svc = Get-TestSvc -StartMode 'Auto' -IsMicrosoftSigned $true
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-004') | Should -BeNullOrEmpty
        }

        It 'WA-SVC-004 does not fire for a manual-start, unsigned service' {
            $svc = Get-TestSvc -StartMode 'Manual' -IsMicrosoftSigned $false
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            ($findings | Where-Object Id -EQ 'WA-SVC-004') | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully healthy service' {
            $svc = Get-TestSvc
            $findings = Get-WinAuditServiceFindings -Services @($svc)
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditScheduledTaskFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestTask {
                param(
                    $TaskName = 'TestTask',
                    $TaskPath = '\Microsoft\Windows\TestArea\',
                    $RunAsUser = 'SYSTEM',
                    $LogonType = 'ServiceAccount',
                    $Actions = @('C:\Program Files\Vendor\run.exe'),
                    $Triggers = @('Boot')
                )
                [pscustomobject]@{
                    TaskName  = $TaskName
                    TaskPath  = $TaskPath
                    RunAsUser = $RunAsUser
                    LogonType = $LogonType
                    Actions   = $Actions
                    Triggers  = $Triggers
                }
            }
        }

        It 'WA-TASK-001 fires for a SYSTEM task with a user-writable action path' {
            $task = Get-TestTask -RunAsUser 'SYSTEM' -Actions @('C:\Users\bob\run.exe')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-TASK-001 does not fire for a SYSTEM task with a protected action path' {
            $task = Get-TestTask -RunAsUser 'SYSTEM' -Actions @('C:\Program Files\Vendor\run.exe')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-001') | Should -BeNullOrEmpty
        }

        It 'WA-TASK-001 does not fire for a non-SYSTEM task with a user-writable action path' {
            $task = Get-TestTask -RunAsUser 'DOMAIN\svcaccount' -Actions @('C:\Users\bob\run.exe')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-001') | Should -BeNullOrEmpty
        }

        It 'WA-TASK-002 fires when the task stores a password credential' {
            $task = Get-TestTask -LogonType 'Password'
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-002') | Should -Not -BeNullOrEmpty
        }

        It 'WA-TASK-002 does not fire when the task uses ServiceAccount logon' {
            $task = Get-TestTask -LogonType 'ServiceAccount'
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-002') | Should -BeNullOrEmpty
        }

        It 'WA-TASK-003 fires for a logon-triggered task outside the Microsoft task tree' {
            $task = Get-TestTask -TaskPath '\ThirdParty\' -Triggers @('Logon')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-003') | Should -Not -BeNullOrEmpty
        }

        It 'WA-TASK-003 does not fire for a logon-triggered task inside the Microsoft task tree' {
            $task = Get-TestTask -TaskPath '\Microsoft\Windows\TestArea\' -Triggers @('Logon')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-003') | Should -BeNullOrEmpty
        }

        It 'WA-TASK-003 does not fire for a boot-triggered task outside the Microsoft task tree' {
            $task = Get-TestTask -TaskPath '\ThirdParty\' -Triggers @('Boot')
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            ($findings | Where-Object Id -EQ 'WA-TASK-003') | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully healthy task' {
            $task = Get-TestTask
            $findings = Get-WinAuditScheduledTaskFindings -Tasks @($task)
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditShareFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestShare {
                param(
                    $Name = 'Data',
                    $Path = 'D:\Shares\Data',
                    $AccessRules = @([pscustomobject]@{ AccountName = 'BUILTIN\Users'; AccessRight = 'Read'; AccessControlType = 'Allow' })
                )
                [pscustomobject]@{ Name = $Name; Path = $Path; AccessRules = $AccessRules }
            }
        }

        It 'WA-SHR-001 fires when Everyone has Full access' {
            $rules = @([pscustomobject]@{ AccountName = 'Everyone'; AccessRight = 'Full'; AccessControlType = 'Allow' })
            $share = Get-TestShare -AccessRules $rules
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SHR-001 fires when Authenticated Users has Change access' {
            $rules = @([pscustomobject]@{ AccountName = 'Authenticated Users'; AccessRight = 'Change'; AccessControlType = 'Allow' })
            $share = Get-TestShare -AccessRules $rules
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SHR-001 does not fire when only Read access is granted broadly' {
            $rules = @([pscustomobject]@{ AccountName = 'Everyone'; AccessRight = 'Read'; AccessControlType = 'Allow' })
            $share = Get-TestShare -AccessRules $rules
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-001') | Should -BeNullOrEmpty
        }

        It 'WA-SHR-002 fires when an administrative share is present and auto-share policy is enabled' {
            $share = Get-TestShare -Name 'C$' -Path 'C:\'
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $true
            ($findings | Where-Object Id -EQ 'WA-SHR-002') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SHR-002 does not fire when auto-share policy is disabled' {
            $share = Get-TestShare -Name 'C$' -Path 'C:\'
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-002') | Should -BeNullOrEmpty
        }

        It 'WA-SHR-003 fires when the share path is user-writable' {
            $share = Get-TestShare -Path 'C:\Users\Public\Shared'
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-003') | Should -Not -BeNullOrEmpty
        }

        It 'WA-SHR-003 does not fire when the share path is a protected, dedicated directory' {
            $share = Get-TestShare -Path 'D:\Shares\Data'
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            ($findings | Where-Object Id -EQ 'WA-SHR-003') | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully healthy share' {
            $share = Get-TestShare
            $findings = Get-WinAuditShareFindings -Shares @($share) -AutoShareEnabled $false
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditAccountFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestAccount {
                param(
                    $Name = 'bob',
                    [bool]$Disabled = $false,
                    [bool]$PasswordExpires = $true,
                    [bool]$PasswordRequired = $true
                )
                [pscustomobject]@{
                    Name             = $Name
                    Disabled         = $Disabled
                    PasswordExpires  = $PasswordExpires
                    PasswordRequired = $PasswordRequired
                    SID              = 'S-1-5-21-0-0-0-1001'
                }
            }
        }

        It 'WA-ACC-001 fires when an enabled account has a non-expiring password' {
            $acct = Get-TestAccount -PasswordExpires $false
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-ACC-001 does not fire when the password expires normally' {
            $acct = Get-TestAccount -PasswordExpires $true
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-001') | Should -BeNullOrEmpty
        }

        It 'WA-ACC-002 fires (as an inventory entry) for every local Administrators group member' {
            $acct = Get-TestAccount
            $admins = @([pscustomobject]@{ Name = 'CONTOSO\alice'; ObjectClass = 'User' })
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers $admins
            ($findings | Where-Object Id -EQ 'WA-ACC-002').Object | Should -Be 'CONTOSO\alice'
        }

        It 'WA-ACC-002 does not fire when there are no Administrators group members supplied' {
            $acct = Get-TestAccount
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-002') | Should -BeNullOrEmpty
        }

        It 'WA-ACC-003 fires for an enabled Guest account' {
            $acct = Get-TestAccount -Name 'Guest' -Disabled $false
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-003') | Should -Not -BeNullOrEmpty
        }

        It 'WA-ACC-003 does not fire for a disabled Guest account' {
            $acct = Get-TestAccount -Name 'Guest' -Disabled $true
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-003') | Should -BeNullOrEmpty
        }

        It 'WA-ACC-004 fires for an enabled account that does not require a password' {
            $acct = Get-TestAccount -PasswordRequired $false
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-004') | Should -Not -BeNullOrEmpty
        }

        It 'WA-ACC-004 does not fire for an account that requires a password' {
            $acct = Get-TestAccount -PasswordRequired $true
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            ($findings | Where-Object Id -EQ 'WA-ACC-004') | Should -BeNullOrEmpty
        }

        It 'skips a disabled non-Guest account entirely' {
            $acct = Get-TestAccount -Name 'oldsvc' -Disabled $true -PasswordExpires $false -PasswordRequired $false
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            $findings | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully healthy account' {
            $acct = Get-TestAccount
            $findings = Get-WinAuditAccountFindings -Accounts @($acct) -AdministratorsGroupMembers @()
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditPolicyFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestPolicy {
                param(
                    $LmCompatibilityLevel = 5,
                    $Smb1Enabled = $false,
                    $UacEnabled = $true,
                    $UacNeverNotify = $false,
                    $ScriptBlockLogging = $true,
                    $DefenderRealTimeOff = $false,
                    $RdpEnabled = $false,
                    $RdpNlaEnabled = $true,
                    $WinRmAllowUnencrypted = $false,
                    $AutoShareEnabled = $false
                )
                [pscustomobject]@{
                    LmCompatibilityLevel  = $LmCompatibilityLevel
                    Smb1Enabled           = $Smb1Enabled
                    UacEnabled            = $UacEnabled
                    UacNeverNotify        = $UacNeverNotify
                    ScriptBlockLogging    = $ScriptBlockLogging
                    DefenderRealTimeOff   = $DefenderRealTimeOff
                    RdpEnabled            = $RdpEnabled
                    RdpNlaEnabled         = $RdpNlaEnabled
                    WinRmAllowUnencrypted = $WinRmAllowUnencrypted
                    AutoShareEnabled      = $AutoShareEnabled
                }
            }
        }

        It 'WA-POL-001 fires when LM/NTLMv1 responses are permitted' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -LmCompatibilityLevel 1)
            ($findings | Where-Object Id -EQ 'WA-POL-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-001 does not fire when NTLMv2-only is enforced' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -LmCompatibilityLevel 5)
            ($findings | Where-Object Id -EQ 'WA-POL-001') | Should -BeNullOrEmpty
        }

        It 'WA-POL-002 fires when SMBv1 is enabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -Smb1Enabled $true)
            ($findings | Where-Object Id -EQ 'WA-POL-002') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-002 does not fire when SMBv1 is disabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -Smb1Enabled $false)
            ($findings | Where-Object Id -EQ 'WA-POL-002') | Should -BeNullOrEmpty
        }

        It 'WA-POL-003 fires High when UAC is fully disabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -UacEnabled $false)
            $f = $findings | Where-Object Id -EQ 'WA-POL-003'
            $f | Should -Not -BeNullOrEmpty
            $f.Severity | Should -Be 'High'
        }

        It 'WA-POL-003 fires Medium when UAC is set to never notify' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -UacEnabled $true -UacNeverNotify $true)
            $f = $findings | Where-Object Id -EQ 'WA-POL-003'
            $f | Should -Not -BeNullOrEmpty
            $f.Severity | Should -Be 'Medium'
        }

        It 'WA-POL-003 does not fire when UAC is enabled and prompts normally' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -UacEnabled $true -UacNeverNotify $false)
            ($findings | Where-Object Id -EQ 'WA-POL-003') | Should -BeNullOrEmpty
        }

        It 'WA-POL-004 fires when script block logging is disabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -ScriptBlockLogging $false)
            ($findings | Where-Object Id -EQ 'WA-POL-004') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-004 does not fire when script block logging is enabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -ScriptBlockLogging $true)
            ($findings | Where-Object Id -EQ 'WA-POL-004') | Should -BeNullOrEmpty
        }

        It 'WA-POL-005 fires when Defender real-time protection is off' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -DefenderRealTimeOff $true)
            ($findings | Where-Object Id -EQ 'WA-POL-005') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-005 does not fire when Defender real-time protection is on' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -DefenderRealTimeOff $false)
            ($findings | Where-Object Id -EQ 'WA-POL-005') | Should -BeNullOrEmpty
        }

        It 'WA-POL-006 fires when RDP is enabled without NLA' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -RdpEnabled $true -RdpNlaEnabled $false)
            ($findings | Where-Object Id -EQ 'WA-POL-006') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-006 does not fire when RDP is enabled with NLA' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -RdpEnabled $true -RdpNlaEnabled $true)
            ($findings | Where-Object Id -EQ 'WA-POL-006') | Should -BeNullOrEmpty
        }

        It 'WA-POL-006 does not fire when RDP is disabled' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -RdpEnabled $false -RdpNlaEnabled $false)
            ($findings | Where-Object Id -EQ 'WA-POL-006') | Should -BeNullOrEmpty
        }

        It 'WA-POL-007 fires when WinRM allows unencrypted traffic' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -WinRmAllowUnencrypted $true)
            ($findings | Where-Object Id -EQ 'WA-POL-007') | Should -Not -BeNullOrEmpty
        }

        It 'WA-POL-007 does not fire when WinRM requires encryption' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy -WinRmAllowUnencrypted $false)
            ($findings | Where-Object Id -EQ 'WA-POL-007') | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully hardened policy set' {
            $findings = Get-WinAuditPolicyFindings -Policy (Get-TestPolicy)
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditFirewallFindings' {
    InModuleScope WinAudit {
        BeforeAll {
            function Get-TestProfile {
                param($Name = 'Domain', $Enabled = $true)
                [pscustomobject]@{ Name = $Name; Enabled = $Enabled }
            }
            function Get-TestRule {
                param(
                    $Name = 'Rule1',
                    $DisplayName = 'Rule 1',
                    $Enabled = $true,
                    $AddressAny = $true,
                    $PortAny = $true
                )
                [pscustomobject]@{
                    Name        = $Name
                    DisplayName = $DisplayName
                    Direction   = 'Inbound'
                    Action      = 'Allow'
                    Enabled     = $Enabled
                    AddressAny  = $AddressAny
                    PortAny     = $PortAny
                }
            }
        }

        It 'WA-FW-001 fires when a firewall profile is disabled' {
            $findings = Get-WinAuditFirewallFindings -Profiles @(Get-TestProfile -Enabled $false) -Rules @()
            ($findings | Where-Object Id -EQ 'WA-FW-001') | Should -Not -BeNullOrEmpty
        }

        It 'WA-FW-001 does not fire when the firewall profile is enabled' {
            $findings = Get-WinAuditFirewallFindings -Profiles @(Get-TestProfile -Enabled $true) -Rules @()
            ($findings | Where-Object Id -EQ 'WA-FW-001') | Should -BeNullOrEmpty
        }

        It 'WA-FW-002 fires for an inbound allow rule open on any address and any port' {
            $findings = Get-WinAuditFirewallFindings -Profiles @() -Rules @(Get-TestRule -AddressAny $true -PortAny $true)
            ($findings | Where-Object Id -EQ 'WA-FW-002') | Should -Not -BeNullOrEmpty
        }

        It 'WA-FW-002 does not fire when the rule is scoped to a specific port' {
            $findings = Get-WinAuditFirewallFindings -Profiles @() -Rules @(Get-TestRule -AddressAny $true -PortAny $false)
            ($findings | Where-Object Id -EQ 'WA-FW-002') | Should -BeNullOrEmpty
        }

        It 'WA-FW-002 does not fire when the rule is scoped to a specific address' {
            $findings = Get-WinAuditFirewallFindings -Profiles @() -Rules @(Get-TestRule -AddressAny $false -PortAny $true)
            ($findings | Where-Object Id -EQ 'WA-FW-002') | Should -BeNullOrEmpty
        }

        It 'WA-FW-002 does not fire for a disabled rule' {
            $findings = Get-WinAuditFirewallFindings -Profiles @() -Rules @(Get-TestRule -Enabled $false)
            ($findings | Where-Object Id -EQ 'WA-FW-002') | Should -BeNullOrEmpty
        }

        It 'produces no findings for a fully healthy firewall configuration' {
            $findings = Get-WinAuditFirewallFindings -Profiles @(Get-TestProfile) -Rules @(Get-TestRule -AddressAny $false -PortAny $false)
            $findings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-WinAuditWeakAcl' {
    InModuleScope WinAudit {
        It 'returns true when Everyone has Write access' {
            $rules = @([pscustomobject]@{ IdentityReference = 'Everyone'; FileSystemRights = 'Write'; AccessControlType = 'Allow' })
            Test-WinAuditWeakAcl -AccessRules $rules | Should -BeTrue
        }

        It 'returns true when BUILTIN\Users has Modify access' {
            $rules = @([pscustomobject]@{ IdentityReference = 'BUILTIN\Users'; FileSystemRights = 'Modify'; AccessControlType = 'Allow' })
            Test-WinAuditWeakAcl -AccessRules $rules | Should -BeTrue
        }

        It 'returns false when only Administrators have FullControl' {
            $rules = @([pscustomobject]@{ IdentityReference = 'BUILTIN\Administrators'; FileSystemRights = 'FullControl'; AccessControlType = 'Allow' })
            Test-WinAuditWeakAcl -AccessRules $rules | Should -BeFalse
        }

        It 'returns false when Everyone only has Read access' {
            $rules = @([pscustomobject]@{ IdentityReference = 'Everyone'; FileSystemRights = 'Read'; AccessControlType = 'Allow' })
            Test-WinAuditWeakAcl -AccessRules $rules | Should -BeFalse
        }

        It 'returns false for an empty access rule set' {
            Test-WinAuditWeakAcl -AccessRules @() | Should -BeFalse
        }

        It 'returns false for a Deny rule granting Everyone Write (not an Allow)' {
            $rules = @([pscustomobject]@{ IdentityReference = 'Everyone'; FileSystemRights = 'Write'; AccessControlType = 'Deny' })
            Test-WinAuditWeakAcl -AccessRules $rules | Should -BeFalse
        }
    }
}
