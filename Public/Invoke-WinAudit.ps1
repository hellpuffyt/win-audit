#Requires -Version 5.1
Set-StrictMode -Version Latest

function Invoke-WinAudit {
    <#
        .SYNOPSIS
            Audits this machine's Windows security posture and reports
            findings with severity, risk explanation, and a remediation
            command for each one.

        .DESCRIPTION
            Invoke-WinAudit is READ-ONLY. It collects service, scheduled
            task, share, local account/policy, and firewall configuration
            from the local machine, runs each finding through a pure
            analyser, and returns/prints the results. It never modifies
            system state, including when -Remediate is supplied.

        .PARAMETER Severity
            Only include findings at or above one of these severities.
            Accepts one or more of Info, Low, Medium, High, Critical.

        .PARAMETER Only
            Only include findings whose Id or Category matches one of
            these values (e.g. 'WA-SVC-002' or 'Services').

        .PARAMETER Exclude
            Exclude findings whose Id or Category matches one of these
            values. Applied after -Only.

        .PARAMETER OutputFormat
            Console (default), Json, or Csv.

        .PARAMETER OutputPath
            File path to write Json/Csv output to. If omitted with
            -OutputFormat Json or Csv, output is written to the pipeline
            instead of a file.

        .PARAMETER FailSeverityThreshold
            If any finding is at or above this severity, Invoke-WinAudit
            sets $LASTEXITCODE to 1 so it can drive a scheduled compliance
            check. Default: High. Set to 'None' to always exit 0.

        .PARAMETER Remediate
            Prints the remediation command for every reported finding to
            the console as reference text. It NEVER executes anything -
            this switch only controls whether remediation text is shown;
            use it to generate a script to review and run yourself.

        .PARAMETER PassThru
            Also return the finding objects on the pipeline in addition
            to any console/file output.

        .EXAMPLE
            Invoke-WinAudit

        .EXAMPLE
            Invoke-WinAudit -Severity High,Critical -OutputFormat Json -OutputPath C:\reports\audit.json

        .EXAMPLE
            Invoke-WinAudit -Only Services -Remediate
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'This is an interactive console report (severity-coloured table header and remediation banner). Write-Output would mix formatted UI text into the pipeline the -PassThru findings travel on.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string[]]$Severity,

        [string[]]$Only,

        [string[]]$Exclude,

        [ValidateSet('Console', 'Json', 'Csv')]
        [string]$OutputFormat = 'Console',

        [string]$OutputPath,

        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical', 'None')]
        [string]$FailSeverityThreshold = 'High',

        [switch]$Remediate,

        [switch]$PassThru
    )

    Write-Verbose 'Collecting service inventory...'
    $serviceData = Get-WinAuditServiceData

    Write-Verbose 'Collecting scheduled task inventory...'
    $taskData = Get-WinAuditScheduledTaskData

    Write-Verbose 'Collecting share inventory...'
    $shareData = Get-WinAuditShareData

    Write-Verbose 'Collecting local account inventory...'
    $accountData = Get-WinAuditAccountData
    $adminMembers = Get-WinAuditAdministratorsGroupData

    Write-Verbose 'Collecting policy/registry state...'
    $policyData = Get-WinAuditPolicyData

    Write-Verbose 'Collecting firewall configuration...'
    $fwProfiles = Get-WinAuditFirewallProfileData
    $fwRules = Get-WinAuditFirewallRuleData

    $findings = @()
    $findings += Get-WinAuditServiceFindings -Services $serviceData
    $findings += Get-WinAuditScheduledTaskFindings -Tasks $taskData
    $findings += Get-WinAuditShareFindings -Shares $shareData -AutoShareEnabled $policyData.AutoShareEnabled
    $findings += Get-WinAuditAccountFindings -Accounts $accountData -AdministratorsGroupMembers $adminMembers
    $findings += Get-WinAuditPolicyFindings -Policy $policyData
    $findings += Get-WinAuditFirewallFindings -Profiles $fwProfiles -Rules $fwRules

    if ($Severity) {
        $findings = @($findings | Where-Object { $_.Severity -in $Severity })
    }

    if ($Only) {
        $findings = @($findings | Where-Object { $_.Id -in $Only -or $_.Category -in $Only })
    }

    if ($Exclude) {
        $findings = @($findings | Where-Object { $_.Id -notin $Exclude -and $_.Category -notin $Exclude })
    }

    switch ($OutputFormat) {
        'Json' {
            $json = $findings | ConvertTo-Json -Depth 5
            if ($OutputPath) { $json | Out-File -FilePath $OutputPath -Encoding utf8 }
            else { Write-Output $json }
        }
        'Csv' {
            if ($OutputPath) {
                $findings | Export-Csv -Path $OutputPath -NoTypeInformation
            }
            else {
                $findings | ConvertTo-Csv -NoTypeInformation | Write-Output
            }
        }
        default {
            if ($findings.Count -eq 0) {
                Write-Host 'No findings.' -ForegroundColor Green
            }
            else {
                $findings |
                    Sort-Object @{Expression = { $script:WinAuditSeverityRank[$_.Severity] }; Descending = $true }, Category |
                    Format-Table -AutoSize -Wrap Id, Severity, Category, Object, Risk |
                    Out-Host
            }
        }
    }

    if ($Remediate) {
        Write-Host "`n=== Remediation reference (NOT executed - review before running) ===" -ForegroundColor Yellow
        foreach ($finding in $findings) {
            Write-Host "`n# $($finding.Id) [$($finding.Severity)] $($finding.Object)" -ForegroundColor Cyan
            Write-Host $finding.Remediation
        }
    }

    if ($FailSeverityThreshold -ne 'None') {
        $breach = $findings | Where-Object { Test-WinAuditSeverityAtLeast -Severity $_.Severity -Threshold $FailSeverityThreshold }
        $Global:LASTEXITCODE = if ($breach) { 1 } else { 0 }
    }
    else {
        $Global:LASTEXITCODE = 0
    }

    if ($PassThru) {
        return $findings
    }
}
