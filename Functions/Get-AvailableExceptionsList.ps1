    Function Get-AvailableExceptionsList
    {

    <#
            .Synopsis      Retrieves all available Exceptions to construct ErrorRecord objects.
            .Description      Retrieves all available Exceptions in the current session to construct ErrorRecord objects.
            .Example      $availableExceptions = Get-AvailableExceptionsList      Description      ===========      Stores all available Exception objects in the variable 'availableExceptions'.
            .Example      Get-AvailableExceptionsList | Set-Content [IO.Path]::GetTempDirectory()\AvailableExceptionsList.txt      Description      ===========      Writes all available Exception objects to the 'AvailableExceptionsList.txt' file in the user's Temp directory.
            .Inputs     None
            .Outputs     System.String
            .Link      New-ErrorRecord
            .Notes Name:  Get-AvailableExceptionsList  Original Author: Robert Robelo  ModifiedBy: Mike Campbell
        #>
    [CmdletBinding()]
    param()
    $irregulars = 'Dispose|OperationAborted|Unhandled|ThreadAbort|ThreadStart|TypeInitialization'
    $appDomains = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {-not $_.IsDynamic}
    $ExportedTypes = $appDomains | ForEach-Object {$_.GetExportedTypes()}
    $Exceptions = $ExportedTypes | Where-Object {$_.name -like '*exception*' -and $_.name -notmatch $irregulars}
    $exceptionsWithGetConstructorsMethod = $Exceptions | Where-Object -FilterScript {'GetConstructors' -in @($_ | Get-Member -MemberType Methods | Select-Object -ExpandProperty Name)}
    $exceptionsWithGetConstructorsMethod | Select-Object -ExpandProperty FullName

    }
