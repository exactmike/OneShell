function Get-DistributionGroupMemberExpanded
{
    [CmdletBinding()]
    param
    (
        $Identity
    )
    $BaseGroupMembership = @(Get-DistributionGroupMember -Identity $Identity -ResultSize Unlimited)
    $AllResolvedMembers = @(
        do 
        {
            $BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -notlike '*group*'}
            $RemainingGroupMembers =  @($BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -like '*group*'})
            $BaseGroupMembership = @($RemainingGroupMembers | ForEach-Object {Get-DistributionGroupMember -Identity $_.guid.guid})

        }
        until ($BaseGroupMembership.count -eq 0)
    )
    Write-Output -InputObject $AllResolvedMembers
}
 
function Get-ADObjectExpandedMembership
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]
        $Identity
    )
 
    process
    {
        $ADObject = Get-ADObject -Identity $Identity
        $DN = $ADObject.DistinguishedName
        $strFilter = "(member:1.2.840.113556.1.4.1941:=$DN)"
        Get-ADGroup -LDAPFilter $strFilter -ResultSetSize Unlimited
    }
}