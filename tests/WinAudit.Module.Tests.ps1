#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Import-Module (Join-Path $PSScriptRoot '..\WinAudit.psd1') -Force

Describe 'WinAudit module' {
    It 'imports cleanly and exports only Invoke-WinAudit' {
        $exported = (Get-Module WinAudit).ExportedFunctions.Keys
        $exported | Should -Be @('Invoke-WinAudit')
    }

    It 'exposes Invoke-WinAudit with the documented filtering parameters' {
        $cmd = Get-Command Invoke-WinAudit
        $cmd.Parameters.Keys | Should -Contain 'Severity'
        $cmd.Parameters.Keys | Should -Contain 'Only'
        $cmd.Parameters.Keys | Should -Contain 'Exclude'
        $cmd.Parameters.Keys | Should -Contain 'Remediate'
        $cmd.Parameters.Keys | Should -Contain 'FailSeverityThreshold'
    }
}
