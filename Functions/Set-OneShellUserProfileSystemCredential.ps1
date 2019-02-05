    Function Set-OneShellUserProfileSystemCredential
    {

    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 2)]
        [string[]]$SystemIdentity
        ,
        [parameter(Position = 3)]
        [string]$Identity
        ,
        [parameter()]
        [ValidateSet('All', 'PSSession', 'Service')]
        $Purpose = 'All'
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )#end param
    Begin
    {
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path;
        #Get/Select the Profile
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        #Get/Select the System
        $Systems = Get-OneShellUserProfileSystem -ProfileIdentity $UserProfile.Identity -Path $Path -ErrorAction 'Stop'
    }
    Process
    {
        if ($SystemIdentity.count -eq 0)
        {
            $SystemIdentity = @(
                $(GetSelectProfileSystem -PotentialSystems $Systems -Operation Edit).Identity
            )
        }
        foreach ($i in $SystemIdentity)
        {
            $System = GetSelectProfileSystem -PotentialSystems $Systems -Identity $i -Operation Edit
            #Get/Select the Credential
            $Credentials = @(Get-OneShellUserProfileCredential -ProfileIdentity $UserProfile.Identity -ErrorAction 'Stop' -Path $path)
            $SelectedCredential = @(
                $Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                $Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
            )
            switch ($SelectedCredential.Count)
            {
                0 {throw("Matching credential for value $($Identity;$UserName) not found")}
                1 {}
                default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
            }
            #If this is the first time a credential has been added we may need to add Properties/Attributes
            if ($null -eq $system.Credentials)
            {
                $system.Credentials = [PSCustomObject]@{PSSession = $null; Service = $null}
            }
            #Remove any existing credential with the same purpose (only one of each purpose is allowed at one time)
            if ($Purpose -eq 'All')
            {
                $system.Credentials.PSSession = $SelectedCredential.Identity
                $system.Credentials.Service = $SelectedCredential.Identity
            }
            else
            {
                $system.Credentials.$purpose = $SelectedCredential.Identity
            }
            $system = $system | Select-Object -Property $(GetUserProfileSystemPropertySet)
            #Save the system changes to the User Profile
            $UserProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $UserProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-OneShellUserProfile -profile $UserProfile -path $path -ErrorAction 'Stop'
        }
    }#end End

    }
