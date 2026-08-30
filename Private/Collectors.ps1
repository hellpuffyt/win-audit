#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
    Collectors are intentionally thin. Each one talks to the live system
    (CIM, the registry, local security APIs) and returns plain
    [pscustomobject] records in a stable shape. They contain no
    decision-making logic - that all lives in Private/Analyzers.ps1 so it
    can be unit tested with synthetic data instead of a real machine.
#>

function Get-WinAuditServiceData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

    foreach ($svc in $services) {
        $binaryPath = Get-WinAuditBinaryPathFromServicePath -PathName $svc.PathName
        $accessRules = @()
        $isMicrosoftSigned = $null

        if ($binaryPath -and (Test-Path -LiteralPath $binaryPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            try {
                $acl = Get-Acl -LiteralPath $binaryPath -ErrorAction Stop
                $accessRules = @($acl.Access | ForEach-Object {
                        [pscustomobject]@{
                            IdentityReference = $_.IdentityReference.ToString()
                            FileSystemRights  = $_.FileSystemRights.ToString()
                            AccessControlType = $_.AccessControlType.ToString()
                        }
                    })
            }
            catch {
                $accessRules = @()
            }

            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $binaryPath -ErrorAction Stop
                $isMicrosoftSigned = ($sig.Status -eq 'Valid') -and
                    ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
            }
            catch {
                $isMicrosoftSigned = $null
            }
        }

        [pscustomobject]@{
            Name              = $svc.Name
            DisplayName       = $svc.DisplayName
            StartName         = $svc.StartName
            PathName          = $svc.PathName
            StartMode         = $svc.StartMode
            State             = $svc.State
            BinaryPath        = $binaryPath
            IsMicrosoftSigned = $isMicrosoftSigned
            AccessRules       = $accessRules
        }
    }
}

function Get-WinAuditScheduledTaskData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $tasks = Get-ScheduledTask -ErrorAction Stop

    foreach ($task in $tasks) {
        $actionPaths = @($task.Actions | ForEach-Object {
                try { $_.Execute } catch { $null }
            } | Where-Object { $_ })
        $triggerTypes = @($task.Triggers | ForEach-Object {
                try { ($_.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', '' }
                catch { $null }
            } | Where-Object { $_ })

        [pscustomobject]@{
            TaskName  = $task.TaskName
            TaskPath  = $task.TaskPath
            RunAsUser = $task.Principal.UserId
            LogonType = $task.Principal.LogonType.ToString()
            Actions   = $actionPaths
            Triggers  = $triggerTypes
        }
    }
}

function Get-WinAuditShareData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $shares = Get-SmbShare -ErrorAction Stop

    foreach ($share in $shares) {
        $accessRules = @()
        try {
            $accessRules = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        AccountName       = $_.AccountName
                        AccessRight       = $_.AccessRight.ToString()
                        AccessControlType = $_.AccessControlType.ToString()
                    }
                })
        }
        catch {
            $accessRules = @()
        }

        [pscustomobject]@{
            Name        = $share.Name
            Path        = $share.Path
            AccessRules = $accessRules
        }
    }
}

function Get-WinAuditAccountData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $accounts = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop

    foreach ($account in $accounts) {
        [pscustomobject]@{
            Name             = $account.Name
            Disabled         = [bool]$account.Disabled
            PasswordExpires  = [bool]$account.PasswordExpires
            PasswordRequired = [bool]$account.PasswordRequired
            SID              = $account.SID
        }
    }
}

function Get-WinAuditAdministratorsGroupData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    try {
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                ObjectClass = $_.ObjectClass
            }
        }
    }
    catch {
        @()
    }
}

function Get-WinAuditPolicyData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    function Get-RegValue {
        param($Path, $Name, $Default)
        try {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
        catch {
            return $Default
        }
    }

    $lmLevel = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Default $null
    $smb1 = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Default $null
    $uacEnabled = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Default 1
    $uacConsent = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Default 5
    $sbLogging = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Default 0
    $defenderRtDisabled = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Default 0
    $rdpDeny = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1
    $rdpNla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Default 1
    $winrmUnencrypted = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Default 0
    $autoShareServer = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Default 1
    $autoShareWks = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Default 1

    [pscustomobject]@{
        LmCompatibilityLevel  = $lmLevel
        Smb1Enabled           = if ($null -ne $smb1) { [bool]$smb1 } else { $null }
        UacEnabled            = [bool]$uacEnabled
        UacNeverNotify        = ([int]$uacConsent -eq 0)
        ScriptBlockLogging    = [bool]$sbLogging
        DefenderRealTimeOff   = [bool]$defenderRtDisabled
        RdpEnabled            = ([int]$rdpDeny -eq 0)
        RdpNlaEnabled         = [bool]$rdpNla
        WinRmAllowUnencrypted = [bool]$winrmUnencrypted
        AutoShareEnabled      = ([bool]$autoShareServer -or [bool]$autoShareWks)
    }
}

function Get-WinAuditFirewallProfileData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name    = $_.Name
            Enabled = [bool]$_.Enabled
        }
    }
}

function Get-WinAuditFirewallRuleData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop

    foreach ($rule in $rules) {
        $addressAny = $true
        $portAny = $true

        try {
            $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            $addressAny = @($addrFilter.RemoteAddress) -contains 'Any'
        }
        catch {
            # Filter lookup can fail for rules tied to a removed/renamed interface.
            # Fail safe and keep treating the rule as open (AddressAny stays $true).
            Write-Verbose "Could not read address filter for firewall rule '$($rule.Name)': $_"
        }

        try {
            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
            $portAny = (@($portFilter.LocalPort) -contains 'Any') -or (-not $portFilter.LocalPort)
        }
        catch {
            # Same reasoning as above - fail safe and keep PortAny at $true.
            Write-Verbose "Could not read port filter for firewall rule '$($rule.Name)': $_"
        }

        [pscustomobject]@{
            Name        = $rule.Name
            DisplayName = $rule.DisplayName
            Direction   = $rule.Direction.ToString()
            Action      = $rule.Action.ToString()
            Enabled     = ($rule.Enabled.ToString() -eq 'True')
            AddressAny  = $addressAny
            PortAny     = $portAny
        }
    }
}
