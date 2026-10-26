#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Import-Module (Join-Path $PSScriptRoot '..\WinAudit.psd1') -Force

# Invoke-WinAudit end to end with every collector mocked, so it runs on any OS.
# The service analyser returns one synthetic finding per severity.
Describe 'Invoke-WinAudit filtering and exit code' {
    BeforeAll {
        foreach ($name in 'Get-WinAuditServiceData', 'Get-WinAuditScheduledTaskData', 'Get-WinAuditShareData',
            'Get-WinAuditAccountData', 'Get-WinAuditAdministratorsGroupData', 'Get-WinAuditFirewallProfileData',
            'Get-WinAuditFirewallRuleData') {
            # The leading comma keeps an empty array; a bare @() unrolls to $null, which the analysers reject.
            Mock -ModuleName WinAudit -CommandName $name -MockWith { , @() }
        }
        foreach ($name in 'Get-WinAuditScheduledTaskFindings', 'Get-WinAuditShareFindings',
            'Get-WinAuditAccountFindings', 'Get-WinAuditPolicyFindings', 'Get-WinAuditFirewallFindings') {
            Mock -ModuleName WinAudit -CommandName $name -MockWith { @() }
        }
        Mock -ModuleName WinAudit -CommandName Get-WinAuditPolicyData -MockWith { [pscustomobject]@{ AutoShareEnabled = $false } }
        Mock -ModuleName WinAudit -CommandName Get-WinAuditServiceFindings -MockWith {
            foreach ($s in 'Info', 'Low', 'Medium', 'High', 'Critical') {
                # Same shape as New-WinAuditFinding, which is private to the module and not visible here.
                [pscustomobject]@{
                    PSTypeName = 'WinAudit.Finding'; Id = "WA-TEST-$s"; Severity = $s; Category = 'Test'
                    Object = 'synthetic'; Risk = 'r'; Remediation = 'none'; Details = ''
                }
            }
        }
        $script:out = Join-Path $TestDrive 'findings.csv'
    }

    It 'returns every finding when -Severity is not given' {
        $r = Invoke-WinAudit -OutputFormat Csv -OutputPath $script:out -FailSeverityThreshold None -PassThru
        @($r).Count | Should -Be 5
    }

    It '-Severity keeps exactly the listed severities' {
        $r = Invoke-WinAudit -Severity Low, Critical -OutputFormat Csv -OutputPath $script:out -FailSeverityThreshold None -PassThru
        @($r.Severity | Sort-Object) | Should -Be @('Critical', 'Low')
    }

    It '-Severity is not a minimum: High does not include Critical' {
        $r = Invoke-WinAudit -Severity High -OutputFormat Csv -OutputPath $script:out -FailSeverityThreshold None -PassThru
        @($r.Severity) | Should -Be @('High')
    }

    It '-FailSeverityThreshold is a minimum: Critical breaches High' {
        $null = Invoke-WinAudit -Severity Critical -OutputFormat Csv -OutputPath $script:out -FailSeverityThreshold High
        $LASTEXITCODE | Should -Be 1
    }

    It '-FailSeverityThreshold is not breached by findings below it' {
        $null = Invoke-WinAudit -Severity Info, Low, Medium -OutputFormat Csv -OutputPath $script:out -FailSeverityThreshold High
        $LASTEXITCODE | Should -Be 0
    }
}
