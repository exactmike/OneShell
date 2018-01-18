function Test-Member
    { 
        <# 
            .ForwardHelpTargetName Get-Member 
            .ForwardHelpCategory Cmdlet 
        #> 
        [CmdletBinding()] 
        param( 
            [Parameter(ValueFromPipeline)] 
            [psobject] 
            $InputObject, 

            [Parameter(Position=0)] 
            [ValidateNotNullOrEmpty()] 
            [String[]] 
            $Name, 

            [Alias('Type')] 
            [Management.Automation.PSMemberTypes] 
            $MemberType, 

            [Management.Automation.PSMemberViewTypes] 
            $View, 

            [Switch] 
            $Static, 

            [Switch] 
            $Force 
        )#end param
        begin { 
            try { 
                $outBuffer = $null 
                if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) 
                { 
                    $PSBoundParameters['OutBuffer'] = 1 
                } 
                $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-Member', [Management.Automation.CommandTypes]::Cmdlet) 
                $scriptCmd = {& $wrappedCmd @PSBoundParameters | ForEach-Object -Begin {$members = @()} -Process {$members += $_} -End {$members.Count -ne 0}} 
                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin) 
                $steppablePipeline.Begin($PSCmdlet) 
            } 
            catch { 
                throw 
            } 
        }#end begin
        process { 
            try { 
                $steppablePipeline.Process($_) 
            } 
            catch { 
                throw 
            } 
        }#end process
        end { 
            try { 
                $steppablePipeline.End() 
            } 
            catch { 
                throw 
            } 
        }#end end
    }
#end function Test-Member
function Test-IsNullOrWhiteSpace
    {
        [cmdletbinding()]
        Param
        (
            $String
        )
        [string]::IsNullOrWhiteSpace($String)
    }
#end function Test-IsNullorWhiteSpace
function Test-IsNotNullOrWhiteSpace
    {
        [cmdletbinding()]
        Param(
        $String
        )
        [string]::IsNullOrWhiteSpace($String) -eq $false
    }
#end function Test-IsNotNullOrWhiteSpace
function Test-IP
    {
        #https://gallery.technet.microsoft.com/scriptcenter/A-short-tip-to-validate-IP-4f039260
        param
        (
            [Parameter(Mandatory)]
            [ValidateScript({$_ -match [IPAddress]$_ })]
            [String]$ip    
        )
        $ip
    }
#end function Test-IP
Function Test-FilePath
    {
        [cmdletbinding()]
        param(
            [parameter(Mandatory = $true)]
            [string]$path
        )
        if (Test-Path -Path $path)
        {
            $item = Get-Item -Path $path
            if ($item.GetType().fullname -eq 'System.IO.FileInfo')
            {Write-Output -InputObject $true}
            else
            {Write-Output -InputObject $false}
        }
        else
        {Write-Output -InputObject $false}
    }
#end function Test-FilePath
Function Test-DirectoryPath
    {
        [cmdletbinding()]
        param(
            [parameter(Mandatory = $true)]
            [string]$path
        )
        if (Test-Path -Path $path)
        {
            $item = Get-Item -Path $path
            if ($item.GetType().fullname -eq 'System.IO.DirectoryInfo')
            {Write-Output -InputObject $true}
            else
            {Write-Output -InputObject $false}
        }
        else
        {Write-Output -InputObject $false}
    }
#end function
function Test-IsWriteableDirectory
    {
        #Credits to the following:
        #http://poshcode.org/2236
        #http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
        [CmdletBinding()]
        param
        (
            [parameter()]
            [ValidateScript(
                {
                    $IsContainer = Test-Path -Path ($_) -PathType Container
                    if ($IsContainer)
                    {
                        $Item = Get-Item -Path $_
                        if ($item.PsProvider.Name -eq 'FileSystem') {$true}
                        else {$false}
                    }
                    else {$false}
                }
            )]
            [string]$Path
        )
        try
        {
            $testPath = Join-Path -Path $Path -ChildPath ([IO.Path]::GetRandomFileName())
                New-Item -Path $testPath -ItemType File -ErrorAction Stop > $null
            $true
        }
        catch
        {
            $false
        }
        finally
        {
            Remove-Item -Path $testPath -ErrorAction SilentlyContinue
        }
    }
#end function Test-IsWriteableDirectory
function Test-CurrentPrincipalIsAdmin
    {
        $currentPrincipal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
        $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator') 
    }
#end function Test-CurrentPrincipalIsAdmin
Function Test-ForInstalledModule
    {
        Param
        (
            [parameter(Mandatory=$True)]
            [string]$Name
        )
        If
        (
            (Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)
        )
        {$True}
        Else
        {$False}
    }
#end function Test-ForInstalledModule
Function Test-ForImportedModule
    {
        Param(
        [parameter(Mandatory=$True)]
        [string]$Name
        )
        If
        (
        (Get-Module -Name $Name -ErrorAction SilentlyContinue) `
        -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)
        )
        {$True}
        Else
        {$False}
    }
#end function Test-ForImportedModule
Function Test-CommandExists
    {
        Param ([string]$command)
        Try {if(Get-Command -Name $command -ErrorAction Stop){$true}}
        Catch {$false}
    }
#end function Test-CommandExists
Function Test-EmailAddress
    {
        [cmdletbinding()]
        param
        (
            [string]$EmailAddress
        )
        #Regex borrowed from: http://www.regular-expressions.info/email.html
        $EmailAddress -imatch '^(?=[A-Z0-9][A-Z0-9@._%+-]{5,253}$)[A-Z0-9._%+-]{1,64}@(?:(?=[A-Z0-9-]{1,63}\.)[A-Z0-9]+(?:-[A-Z0-9]+)*\.){1,8}[A-Z]{2,63}$'
    }
#end function Test-EmailAddress
function Test-StringIsConvertibleToGUID
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory,ValueFromPipeline)]
            [String]$string
        )
        try {([guid]$string -is [guid])} catch {$false}
    }
#end function TestStringIsConvertibleToGUID