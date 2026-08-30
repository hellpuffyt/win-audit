@{
    RootModule        = 'WinAudit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b3f1c6a2-7e2d-4a1a-9c3e-6f2a1d9b4e77'
    Author            = 'Prabesh Sharma'
    CompanyName       = 'Prabesh Sharma'
    Copyright         = '(c) 2026 Prabesh Sharma. MIT License.'
    Description       = 'Read-only Windows security posture auditor: services, scheduled tasks, shares, accounts, policy, and firewall, with severity-scored findings and remediation guidance.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-WinAudit')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('security', 'audit', 'windows', 'hardening', 'compliance')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/hellpuffyt/win-audit'
        }
    }
}
