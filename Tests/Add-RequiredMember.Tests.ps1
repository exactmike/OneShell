$CommandName = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
. Join-Path (Join-Path $PSScriptRoot 'Functions') $($CommandName + '.ps1')


InModuleScope OneShell {
    Describe "$CommandName Unit Tests" -Tag 'UnitTests' {
        Context "Validate parameters" {
            $paramCount = 2
            $defaultParamCount = 11
            [object[]]$params = (Get-ChildItem Function:\Add-RequiredMember).Parameters.Keys
            $knownParameters = @('RequiredMember','InputObject')
            It "Should contain our specific parameters" {
                ( @(Compare-Object -ReferenceObject $knownParameters -DifferenceObject $params -IncludeEqual | Where-Object SideIndicator -eq "==").Count ) | Should Be $paramCount
            }
            It "Should only contain $paramCount parameters" {
                $params.Count - $defaultParamCount | Should Be $paramCount
            }
        }
    }
    Describe "$CommandName Integration Tests" -Tags "IntegrationTests" {
        Context "Adds a single member to a single object submitted via parameter" {
            $AnObject = $([pscustomobject]@{})
            Add-RequiredMember -InputObject $AnObject -RequiredMember 'TestMember1'
            $Results = $AnObject | Get-Member
            It "Should have the right attribute" {
                $Results.Name | Should Contain 'TestMember1'
            }
        }
        Context "Adds a multiple members to a single object submitted via parameter" {
            $AnObject = $([pscustomobject]@{})
            Add-RequiredMember -InputObject $AnObject -RequiredMember 'TestMember1','TestMember2'
            $Results = $AnObject | Get-Member
            It "Should have the right attributes" {
                $Results.Name | Should Contain 'TestMember1'
                $Results.Name | Should Contain 'TestMember2'
            }
        }
        Context "Adds a single members to a single object submitted via pipeline" {
            $AnObject = $([pscustomobject]@{})
            $AnObject | Add-RequiredMember -RequiredMember 'TestMember1'
            $Results = $AnObject | Get-Member
            It "Should have the right attribute" {
                $Results.Name | Should Contain 'TestMember1'
            }
        }
        Context "Adds a multiple members to a single object submitted via pipeline" {
            $AnObject = $([pscustomobject]@{})
            $AnObject | Add-RequiredMember -RequiredMember 'TestMember1','TestMember2'
            $Results = $AnObject | Get-Member
            It "Should have the right attributes" {
                $Results.Name | Should Contain 'TestMember1'
                $Results.Name | Should Contain 'TestMember2'
            }
        }
        Context "Adds a multiple members to each of multiple objects submitted via pipeline" {
            $AnObject = $([pscustomobject]@{})
            $AnotherObject = $([pscustomobject]@{})
            $AnObject,$AnotherObject | Add-RequiredMember -RequiredMember 'TestMember1','TestMember2'
            $Results = @($($AnObject | Get-Member),$($AnotherObject | Get-Member))
            It "Should have the right attributes" {
                $Results[0].Name | Should Contain 'TestMember1'
                $Results[0].Name | Should Contain 'TestMember2'
                $Results[1].Name | Should Contain 'TestMember1'
                $Results[1].Name | Should Contain 'TestMember2'
            }
        }
        Context "Specifying an existing member does not throw an error and non-existing members are added" {
            $AnObject = $([pscustomobject]@{'TestMember1' = 1})
            $AnotherObject = $([pscustomobject]@{'TestMember2' = 2})
            $AnObject,$AnotherObject | Add-RequiredMember -RequiredMember 'TestMember1','TestMember2'
            $Results = @($($AnObject | Get-Member),$($AnotherObject | Get-Member))
            It "Should have the right attributes" {
                $Results[0].Name | Should Contain 'TestMember1'
                $Results[0].Name | Should Contain 'TestMember2'
                $Results[1].Name | Should Contain 'TestMember1'
                $Results[1].Name | Should Contain 'TestMember2'
            }
        }
    }
}
