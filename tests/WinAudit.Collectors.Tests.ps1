#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

Import-Module (Join-Path $PSScriptRoot '..\WinAudit.psd1') -Force

Describe 'Get-WinAuditServiceData' {
    InModuleScope WinAudit {
        It 'maps Win32_Service CIM records into the expected shape' {
            Mock Get-CimInstance {
                [pscustomobject]@{
                    Name        = 'FakeSvc'
                    DisplayName = 'Fake Service'
                    StartName   = 'LocalSystem'
                    PathName    = '"C:\Program Files\Vendor\svc.exe"'
                    StartMode   = 'Auto'
                    State       = 'Running'
                }
            } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            Mock Test-Path { $false }

            $result = @(Get-WinAuditServiceData)

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'FakeSvc'
            $result[0].BinaryPath | Should -Be 'C:\Program Files\Vendor\svc.exe'
            $result[0].AccessRules | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WinAuditAccountData' {
    InModuleScope WinAudit {
        It 'maps Win32_UserAccount CIM records into the expected shape' {
            Mock Get-CimInstance {
                [pscustomobject]@{
                    Name             = 'bob'
                    Disabled         = $false
                    PasswordExpires  = $true
                    PasswordRequired = $true
                    SID              = 'S-1-5-21-0-0-0-1001'
                }
            } -ParameterFilter { $ClassName -eq 'Win32_UserAccount' }

            $result = @(Get-WinAuditAccountData)

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'bob'
            $result[0].PasswordExpires | Should -BeTrue
        }
    }
}

Describe 'Get-WinAuditPolicyData' {
    InModuleScope WinAudit {
        It 'reads UAC state from the registry and reflects it in the result' {
            Mock Get-ItemProperty {
                [pscustomobject]@{ EnableLUA = 0 }
            } -ParameterFilter { $Path -like '*Policies\System' -and $Name -eq 'EnableLUA' }
            Mock Get-ItemProperty { throw 'not found' }

            $policy = Get-WinAuditPolicyData

            $policy.UacEnabled | Should -BeFalse
        }

        It 'falls back to safe defaults when a registry value is absent' {
            Mock Get-ItemProperty { throw [System.Management.Automation.ItemNotFoundException]::new('missing') }

            $policy = Get-WinAuditPolicyData

            $policy.LmCompatibilityLevel | Should -BeNullOrEmpty
            $policy.UacEnabled | Should -BeTrue
        }
    }
}

Describe 'Get-WinAuditAdministratorsGroupData' {
    InModuleScope WinAudit {
        It 'returns an empty collection instead of throwing when the group lookup fails' {
            Mock Get-LocalGroupMember { throw 'access denied' }

            $result = @(Get-WinAuditAdministratorsGroupData)

            $result.Count | Should -Be 0
        }

        It 'maps local group members into the expected shape' {
            Mock Get-LocalGroupMember {
                [pscustomobject]@{ Name = 'CONTOSO\alice'; ObjectClass = 'User' }
            }

            $result = @(Get-WinAuditAdministratorsGroupData)

            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'CONTOSO\alice'
        }
    }
}
