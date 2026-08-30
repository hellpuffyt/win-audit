#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Import-Module (Join-Path $PSScriptRoot '..\WinAudit.psd1') -Force

Describe 'Test-WinAuditUnquotedServicePath' {
    InModuleScope WinAudit {
        It 'flags an unquoted path with a space in the executable portion' {
            Test-WinAuditUnquotedServicePath -PathName 'C:\Program Files\App\svc.exe -k netsvcs' | Should -BeTrue
        }

        It 'does not flag a quoted path with spaces' {
            Test-WinAuditUnquotedServicePath -PathName '"C:\Program Files\App\svc.exe" -k netsvcs' | Should -BeFalse
        }

        It 'does not flag an unquoted path with no spaces' {
            Test-WinAuditUnquotedServicePath -PathName 'C:\Windows\System32\svc.exe -k netsvcs' | Should -BeFalse
        }

        It 'does not flag a quoted path with no spaces' {
            Test-WinAuditUnquotedServicePath -PathName '"C:\Windows\System32\svc.exe"' | Should -BeFalse
        }

        It 'does not flag an empty path' {
            Test-WinAuditUnquotedServicePath -PathName '' | Should -BeFalse
        }

        It 'does not flag a bare unquoted path with no arguments and no spaces' {
            Test-WinAuditUnquotedServicePath -PathName 'C:\Windows\System32\svchost.exe' | Should -BeFalse
        }
    }
}

Describe 'Get-WinAuditBinaryPathFromServicePath' {
    InModuleScope WinAudit {
        It 'extracts the path from a quoted PathName' {
            Get-WinAuditBinaryPathFromServicePath -PathName '"C:\Program Files\App\svc.exe" -k netsvcs' |
                Should -Be 'C:\Program Files\App\svc.exe'
        }

        It 'extracts the path from an unquoted PathName with arguments' {
            Get-WinAuditBinaryPathFromServicePath -PathName 'C:\Windows\System32\svc.exe -k netsvcs' |
                Should -Be 'C:\Windows\System32\svc.exe'
        }

        It 'extracts the path from an unquoted PathName with no arguments' {
            Get-WinAuditBinaryPathFromServicePath -PathName 'C:\Windows\System32\svchost.exe' |
                Should -Be 'C:\Windows\System32\svchost.exe'
        }

        It 'returns an empty string for an empty PathName' {
            Get-WinAuditBinaryPathFromServicePath -PathName '' | Should -Be ''
        }
    }
}

Describe 'Test-WinAuditUserWritablePath' {
    InModuleScope WinAudit {
        It 'flags a path under a user profile directory' {
            Test-WinAuditUserWritablePath -Path 'C:\Users\bob\AppData\Local\app.exe' | Should -BeTrue
        }

        It 'flags a path directly under the Windows Temp directory' {
            Test-WinAuditUserWritablePath -Path 'C:\Windows\Temp\stager.exe' | Should -BeTrue
        }

        It 'flags a path at the root of a drive' {
            Test-WinAuditUserWritablePath -Path 'C:\tool.exe' | Should -BeTrue
        }

        It 'does not flag a path under Program Files' {
            Test-WinAuditUserWritablePath -Path 'C:\Program Files\Vendor\app.exe' | Should -BeFalse
        }

        It 'does not flag a path under System32' {
            Test-WinAuditUserWritablePath -Path 'C:\Windows\System32\svchost.exe' | Should -BeFalse
        }

        It 'does not flag a path under ProgramData (default ACL is read-only for standard users)' {
            Test-WinAuditUserWritablePath -Path 'C:\ProgramData\Vendor\app.exe' | Should -BeFalse
        }

        It 'does not flag an empty path' {
            Test-WinAuditUserWritablePath -Path '' | Should -BeFalse
        }
    }
}

Describe 'Test-WinAuditSeverityAtLeast' {
    InModuleScope WinAudit {
        It 'returns true when severity equals the threshold' {
            Test-WinAuditSeverityAtLeast -Severity 'High' -Threshold 'High' | Should -BeTrue
        }

        It 'returns true when severity exceeds the threshold' {
            Test-WinAuditSeverityAtLeast -Severity 'Critical' -Threshold 'Medium' | Should -BeTrue
        }

        It 'returns false when severity is below the threshold' {
            Test-WinAuditSeverityAtLeast -Severity 'Low' -Threshold 'High' | Should -BeFalse
        }

        It 'ranks Info as the lowest severity' {
            Test-WinAuditSeverityAtLeast -Severity 'Info' -Threshold 'Low' | Should -BeFalse
        }
    }
}

Describe 'New-WinAuditFinding' {
    InModuleScope WinAudit {
        It 'builds a finding object with all fields populated' {
            $finding = New-WinAuditFinding -Id 'WA-TEST-001' -Severity 'Medium' -Category 'Test' `
                -Object 'thing' -Risk 'risk text' -Remediation 'fix-it' -Details 'extra'

            $finding.Id | Should -Be 'WA-TEST-001'
            $finding.Severity | Should -Be 'Medium'
            $finding.Category | Should -Be 'Test'
            $finding.Object | Should -Be 'thing'
            $finding.Risk | Should -Be 'risk text'
            $finding.Remediation | Should -Be 'fix-it'
            $finding.Details | Should -Be 'extra'
        }

        It 'defaults Details to an empty string when not supplied' {
            $finding = New-WinAuditFinding -Id 'WA-TEST-002' -Severity 'Low' -Category 'Test' `
                -Object 'thing' -Risk 'risk' -Remediation 'fix'

            $finding.Details | Should -Be ''
        }
    }
}
