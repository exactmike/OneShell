Function Connect-LotusNotesDatabase {
    [cmdletbinding(DefaultParameterSetName = 'LotusNotesDatabase')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'LotusNotesDatabase'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'LotusNotesDatabase'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('Org','ExchangeOrg')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    begin{
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'LotusNotesDatabase' {
                $Identity = $PSBoundParameters[$ParameterName]
                $LotusNotesDatabaseObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Where-Object {$_.name -eq $Identity}
                $name = $LotusNotesDatabaseObj.Name
                $NotesServer = $LotusNotesDatabaseObj.Server
                $Database = $LotusNotesDatabaseObj.Database
                $Credential = $LotusNotesDatabaseObj.credential
                $Description = $LotusNotesDatabaseObj.description
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $message = "Verify Lotus Note Client Present"
            Write-Log -Message $message -EntryType Attempting
            $LotusNotesDatabaseConnection = New-Object -ComObject Lotus.NotesSession
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        try
        {
            $message = "Connect to $Description on $SQLServer as User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting
            Write-Warning -Message "Connect-SQLDatabase currently uses Windows Integrated Authentication to connect to SQL Servers and ignores supplied credentials"
            $SQLConnection = New-SQLServerConnection -server $SQLServer -database $Database -ErrorAction Stop #-user $credential.username -password $($Credential.password | Convert-SecureStringToString)
            $SQLConnectionString = New-SQLServerConnectionString -server $SQLServer -database $Database -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
            $SQLConnection | Add-Member -Name 'Name' -Value $name -MemberType NoteProperty
            Update-SQLConnections -ConnectionName $Name -SQLConnection $SQLConnection
            Update-SQLConnectionStrings -ConnectionName $name -SQLConnectionString $SQLConnectionString
            Write-Output $true
        }
        catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror) 
        }
    }#process
}#function Connect-SQLDatabase 